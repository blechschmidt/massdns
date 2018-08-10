#define _GNU_SOURCE

#ifdef DEBUG
#include <sys/resource.h>
#endif

#include "massdns.h"
#include "string.h"
#include "random.h"
#include "net.h"
#include "cmd.h"
#include "dns.h"
#include "list.h"
#include "flow.h"
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/ioctl.h>
#include <stddef.h>
#ifdef HAVE_SYSINFO
    #include <sys/sysinfo.h>
#endif
#include <limits.h>
#include <stdarg.h>

#ifdef PCAP_SUPPORT
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <net/if.h>
#endif

void print_help()
{
    fprintf(stderr, ""
                    "Usage: %s [options] [domainlist]\n"
                    "  -b  --bindto           Bind to IP address and port. (Default: 0.0.0.0:0)\n"
#ifdef HAVE_EPOLL
                    "      --busy-poll        Use busy-wait polling instead of epoll.\n"
#endif
                    "  -c  --resolve-count    Number of resolves for a name before giving up. (Default: 50)\n"
                    "      --drop-group       Group to drop privileges to when running as root. (Default: nogroup)\n"
                    "      --drop-user        User to drop privileges to when running as root. (Default: nobody)\n"
                    "      --flush            Flush the output file whenever a response was received.\n"
                    "  -h  --help             Show this help.\n"
                    "  -i  --interval         Interval in milliseconds to wait between multiple resolves of the same\n"
                    "                         domain. (Default: 500)\n"
                    "  -l  --error-log        Error log file path. (Default: /dev/stderr)\n"
                    "      --norecurse        Use non-recursive queries. Useful for DNS cache snooping.\n"
                    "  -o  --output           Flags for output formatting.\n"
                    "      --predictable      Use resolvers incrementally. Useful for resolver tests.\n"
                    "      --processes        Number of processes to be used for resolving. (Default: 1)\n"
                    "  -q  --quiet            Quiet mode.\n"
                    "      --rcvbuf           Size of the receive buffer in bytes.\n"
                    "      --retry            Unacceptable DNS response codes. (Default: REFUSED)\n"
                    "  -r  --resolvers        Text file containing DNS resolvers.\n"
                    "      --root             Do not drop privileges when running as root. Not recommended.\n"
                    "  -s  --hashmap-size     Number of concurrent lookups. (Default: 10000)\n"
                    "      --sndbuf           Size of the send buffer in bytes.\n"
                    "      --sticky           Do not switch the resolver when retrying.\n"
                    "      --socket-count     Socket count per process. (Default: 1)\n"
                    "  -t  --type             Record type to be resolved. (Default: A)\n"
#ifdef PCAP_SUPPORT
                    "      --use-pcap         Enable pcap usage.\n"
#endif
                    "      --verify-ip        Verify IP addresses of incoming replies.\n"
                    "  -w  --outfile          Write to the specified output file instead of standard output.\n"
                    "\n"
                    "Output flags:\n"
                    "  S - simple text output\n"
                    "  F - full text output\n"
                    "  B - binary output\n"
                    "  J - ndjson output\n"
                    "\n"
                    "Advanced flags for the simple output mode:\n"
                    "  d - Include records from the additional section.\n"
                    "  i - Indent any reply record.\n"
                    "  l - Separate replies using a line feed.\n"
                    "  m - Only output reply records that match the question name.\n"
                    "  n - Include records from the answer section.\n"
                    "  q - Print the question.\n"
                    "  r - Prepend resolver IP address, Unix timestamp and return code to the question line.\n"
                    "  s - Separate packet sections using a line feed.\n"
                    "  t - Include TTL and record class within the output.\n"
                    "  u - Include records from the authority section.\n",
                    context.cmd_args.argv[0] ? context.cmd_args.argv[0] : "massdns"
    );
}

void cleanup()
{
#ifdef PCAP_SUPPORT
    if(context.pcap != NULL)
    {
        pcap_close(context.pcap);
    }
#endif
    if(context.map)
    {
        hashmapFree(context.map);
    }

    if(context.resolver_map)
    {
        hashmapFree(context.resolver_map);
    }

    timed_ring_destroy(&context.ring);

    free(context.resolvers.data);

    free(context.sockets.interfaces4.data);
    free(context.sockets.interfaces6.data);

    urandom_close();

    if(context.domainfile)
    {
        fclose(context.domainfile);
    }
    if(context.outfile)
    {
        fclose(context.outfile);
    }
    if(context.logfile)
    {
        fclose(context.logfile);
    }

    free(context.stat_messages);


    free(context.lookup_pool.data);
    free(context.lookup_space);
    
    for (size_t i = 0; i < context.cmd_args.num_processes * 2; i++)
    {
        if(context.sockets.pipes && context.sockets.pipes[i] >= 0)
        {
            close(context.sockets.pipes[i]);
        }
    }
    free(context.sockets.pipes);
    free(context.sockets.master_pipes_read);
    free(context.pids);
    free(context.done);
}

void log_msg(const char* format, ...)
{
    if(context.logfile != stderr)
    {
        va_list args;
        va_start(args, format);
        vfprintf(stderr, format, args);
        va_end(args);
    }
    if(context.logfile)
    {
        va_list args;
        va_start(args, format);
        vfprintf(context.logfile, format, args);
        va_end(args);
    }
}

void clean_exit(int status)
{
    cleanup();
    exit(status);
}

// Adaption of djb2 for sockaddr_storage
int hash_address(void *param)
{
    struct sockaddr_storage *address = param;

    unsigned long hash = 5381;
    uint8_t *addr_ptr;
    uint8_t *addr_end;

    if(address->ss_family == AF_INET)
    {
        struct sockaddr_in *addr4 = param;
        addr_ptr = (uint8_t*)&addr4->sin_addr;
        addr_end = addr_ptr + sizeof(addr4->sin_addr);
        hash = ((hash << 5) + hash) + ((addr4->sin_port & 0xFF00) >> 8);
        hash = ((hash << 5) + hash) + (addr4->sin_port & 0x00FF);
    }
    else if(address->ss_family == AF_INET6)
    {
        struct sockaddr_in6 *addr6 = param;
        addr_ptr = (uint8_t*)&addr6->sin6_addr;
        addr_end = addr_ptr + sizeof(addr6->sin6_addr);
        hash = ((hash << 5) + hash) + ((addr6->sin6_port & 0xFF00) >> 8);
        hash = ((hash << 5) + hash) + (addr6->sin6_port & 0x00FF);
    }
    else
    {
        log_msg("Unsupported address for hashing.\n");
        abort();
    }

    while (addr_ptr < addr_end)
    {
        hash = ((hash << 5) + hash) + *addr_ptr; /* hash * 33 + c */
        addr_ptr++;
    }
    return (int)hash;
}

// Expects valid (non-NULL) pointers to sockaddr storages of family AF_INET / AF_INET6
bool addresses_equal(void *param1, void *param2)
{
    struct sockaddr_storage *addr1 = param1;
    struct sockaddr_storage *addr2 = param2;

    if(addr1->ss_family != addr2->ss_family)
    {
        return false;
    }

    if(addr1->ss_family == AF_INET)
    {
        return memcmp(&((struct sockaddr_in*)addr1)->sin_addr,
                &((struct sockaddr_in*)addr2)->sin_addr, sizeof(((struct sockaddr_in*)addr1)->sin_addr)) == 0
                && ((struct sockaddr_in*)addr1)->sin_port == ((struct sockaddr_in*)addr2)->sin_port;
    }
    else // Must be AF_INET6
    {
        return memcmp(&((struct sockaddr_in6*)addr1)->sin6_addr,
                      &((struct sockaddr_in6*)addr2)->sin6_addr, sizeof(((struct sockaddr_in6*)addr1)->sin6_addr)) == 0
               && ((struct sockaddr_in6*)addr1)->sin6_port == ((struct sockaddr_in6*)addr2)->sin6_port;
    }
    return false;
}

buffer_t massdns_resolvers_from_file(char *filename)
{
    char line[4096];
    FILE *f = fopen(filename, "r");
    if (f == NULL)
    {
        log_msg("Failed to open resolver file: %s\n", strerror(errno));
        clean_exit(EXIT_FAILURE);
    }
    single_list_t *list = single_list_new();
    while (!feof(f))
    {
        if (fgets(line, sizeof(line), f))
        {
            trim_end(line);
            resolver_t *resolver = safe_calloc(sizeof(*resolver));
            struct sockaddr_storage *addr = &resolver->address;
            if (str_to_addr(line, 53, addr))
            {
                if((addr->ss_family == AF_INET && context.sockets.interfaces4.len > 0)
                    || (addr->ss_family == AF_INET6 && context.sockets.interfaces6.len > 0))
                {
                    single_list_push_back(list, resolver);
                }
                else
                {
                    log_msg("No query socket for resolver \"%s\" found.\n", line);
                }
            }
            else
            {
                log_msg("\"%s\" is not a valid resolver. Skipped.\n", line);
            }
        }
    }
    fclose(f);
    buffer_t resolvers = single_list_to_array_copy(list, sizeof(resolver_t));
    if(single_list_count(list) == 0)
    {
        log_msg("No usable resolvers were found. Terminating.\n");
        clean_exit(EXIT_FAILURE);
    }

    if(context.cmd_args.verify_ip)
    {
        context.resolver_map = hashmapCreate(resolvers.len, hash_address, addresses_equal);
        if(!context.resolver_map)
        {
            log_msg("Failed to create resolver lookup map: %s\n", strerror(errno));
            abort();
        }

        for (size_t i = 0; i < resolvers.len; i++)
        {
            resolver_t *resolver = ((resolver_t*)resolvers.data) + i;

            errno = 0;
            hashmapPut(context.resolver_map, &resolver->address, resolver);
            if (errno != 0)
            {
                log_msg("Error putting resolver into hashmap: %s\n", strerror(errno));
                abort();
            }
        }
    }

    single_list_free_with_elements(list);
    return resolvers;
}

void set_sndbuf(int fd)
{
    if(context.cmd_args.sndbuf
        && setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &context.cmd_args.sndbuf, sizeof(context.cmd_args.sndbuf)) != 0)
    {
        log_msg("Failed to adjust send buffer size: %s\n", strerror(errno));
    }
}

void set_rcvbuf(int fd)
{
    if(context.cmd_args.rcvbuf
        && setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &context.cmd_args.rcvbuf, sizeof(context.cmd_args.rcvbuf)) != 0)
    {
        log_msg("Failed to adjust receive buffer size: %s\n", strerror(errno));
    }
}

void add_default_socket(int version)
{
    socket_info_t info;

    info.descriptor = socket(version == 4 ? PF_INET : PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    info.protocol = version == 4 ? PROTO_IPV4 : PROTO_IPV6;
    info.type = SOCKET_TYPE_QUERY;
    if(info.descriptor >= 0)
    {
        buffer_t *buffer = version == 4 ? &context.sockets.interfaces4 : &context.sockets.interfaces6;
        buffer->data = safe_realloc(buffer->data, (buffer->len + 1) * sizeof(info));
        ((socket_info_t*)buffer->data)[buffer->len++] = info;
        set_rcvbuf(info.descriptor);
        set_sndbuf(info.descriptor);
    }
    else
    {
        log_msg("Failed to create IPv%d socket: %s\n", version, strerror(errno));
    }
}

void set_user_sockets(single_list_t *bind_addrs, buffer_t *buffer)
{
    single_list_t sockets;
    single_list_init(&sockets);
    single_list_ref_foreach_free(bind_addrs, element)
    {
        struct sockaddr_storage* addr = element->data;
        socket_info_t info;
        info.descriptor = socket(addr->ss_family, SOCK_DGRAM, IPPROTO_UDP);
        info.protocol = addr->ss_family == AF_INET ? PROTO_IPV4 : PROTO_IPV6;
        info.type = SOCKET_TYPE_QUERY;
        if(info.descriptor >= 0)
        {
            if(bind(info.descriptor, (struct sockaddr*)addr, sizeof(*addr)) != 0)
            {
                log_msg("Not adding socket %s due to bind failure: %s\n", sockaddr2str(addr), strerror(errno));
            }
            else
            {
                set_rcvbuf(info.descriptor);
                set_sndbuf(info.descriptor);
                single_list_push_back(&sockets, flatcopy(&info, sizeof(info)));
            }
        }
        else
        {
            log_msg("Failed to create IPv%d socket: %s\n", info.protocol, strerror(errno));
        }
        free(element->data);
    }
    single_list_init(bind_addrs);
    *buffer = single_list_to_array_copy(&sockets, sizeof(socket_info_t));
    single_list_clear(&sockets);
}

void query_sockets_setup()
{
    if(single_list_count(&context.cmd_args.bind_addrs4) == 0 && single_list_count(&context.cmd_args.bind_addrs6) == 0)
    {
        for(size_t i = 0; i < context.cmd_args.socket_count; i++)
        {
            add_default_socket(4);
            add_default_socket(6);
        }
    }
    else
    {
        set_user_sockets(&context.cmd_args.bind_addrs4, &context.sockets.interfaces4);
        set_user_sockets(&context.cmd_args.bind_addrs6, &context.sockets.interfaces6);
    }
}

bool next_query(char **qname)
{
    static char line[512];
    static size_t line_index = 0;

    while (fgets(line, sizeof(line), context.domainfile))
    {
        if(line_index >= context.cmd_args.num_processes)
        {
            line_index = 0;
        }
        if (context.fork_index != line_index++)
        {
            continue;
        }
        trim_end(line);
        if (*line == 0)
        {
            continue;
        }
        *qname = line;

        return true;
    }
    return false;
}


// This is the djb2 hashing method treating the DNS type as two extra characters
int hash_lookup_key(void *key)
{
    unsigned long hash = 5381;
    uint8_t *entry = ((lookup_key_t *)key)->name.name;
    int c;
    while ((c = *entry++) != 0)
    {
        hash = ((hash << 5) + hash) + tolower(c); /* hash * 33 + c */
    }
    hash = ((hash << 5) + hash) + ((((lookup_key_t *)key)->type & 0xFF00) >> 8);
    hash = ((hash << 5) + hash) + (((lookup_key_t *)key)->type & 0x00FF);
    hash = ((hash << 5) + hash) + ((lookup_key_t *)key)->name.length;
    return (int)hash;
}

void end_warmup()
{
    context.state = STATE_QUERYING;
    if(context.cmd_args.extreme <= 1 && !context.cmd_args.busypoll)
    {
        // Reduce our CPU load from epoll interrupts by removing the EPOLLOUT event
#ifdef PCAP_SUPPORT
        if(!context.pcap)
#endif
#ifdef HAVE_EPOLL
        {
            add_sockets(context.epollfd, EPOLLIN, EPOLL_CTL_MOD, &context.sockets.interfaces4);
            add_sockets(context.epollfd, EPOLLIN, EPOLL_CTL_MOD, &context.sockets.interfaces6);
        }
#endif
    }
}

lookup_t *new_lookup(const char *qname, dns_record_type type, bool *new)
{
    if(context.lookup_pool.len == 0)
    {
        log_msg("Empty lookup pool.\n");
        clean_exit(EXIT_FAILURE);
    }
    lookup_entry_t *entry = ((lookup_entry_t**)context.lookup_pool.data)[--context.lookup_pool.len];
    lookup_key_t *key = &entry->key;

    key->name.length = (uint8_t)string_copy((char*)key->name.name, qname, sizeof(key->name.name));
    if(key->name.name[key->name.length - 1] != '.')
    {
        key->name.name[key->name.length] = '.';
        key->name.name[++key->name.length] = 0;
    }

    key->type = type;
    if(hashmapGet(context.map, key) != NULL)
    {
        context.lookup_pool.len++;
        *new = false;
        return NULL;
    }
    *new = true;
    lookup_t *value = &entry->value;
    bzero(value, sizeof(*value));

    value->ring_entry = timed_ring_add(&context.ring, context.cmd_args.interval_ms * TIMED_RING_MS, value);
    urandom_get(&value->transaction, sizeof(value->transaction));
    value->key = key;

    errno = 0;
    hashmapPut(context.map, key, value);
    if(errno != 0)
    {
        log_msg("Error putting lookup into hashmap: %s\n", strerror(errno));
        abort();
    }

    context.lookup_index++;
    context.stats.timeouts[0]++;
    if(context.lookup_index >= context.cmd_args.hashmap_size)
    {
        end_warmup();
    }

    return value;
}

void send_query(lookup_t *lookup)
{
    static uint8_t query_buffer[0x200];

    // Choose random resolver
    // Pool of resolvers cannot be empty due to check after parsing resolvers.
    if(!context.cmd_args.sticky || lookup->resolver == NULL)
    {
        if(context.cmd_args.predictable_resolver)
        {
            lookup->resolver = ((resolver_t *) context.resolvers.data) + context.lookup_index % context.resolvers.len;
        }
        else
        {
            lookup->resolver = ((resolver_t *) context.resolvers.data) + urandom_size_t() % context.resolvers.len;
        }
    }

    // We need to select the correct socket pool: IPv4 socket pool for IPv4 resolver/IPv6 socket pool for IPv6 resolver
    buffer_t *interfaces;
    if(lookup->resolver->address.ss_family == AF_INET)
    {
        interfaces = &context.sockets.interfaces4;
    }
    else
    {
        interfaces = &context.sockets.interfaces6;
    }

    if(lookup->socket == NULL)
    {
        // Pick a random socket from that pool
        // Pool of sockets cannot be empty due to check when parsing resolvers. Socket creation must have succeeded.
        size_t socket_index = urandom_size_t() % interfaces->len;
        lookup->socket = (socket_info_t *) interfaces->data + socket_index;
    }

    ssize_t result = dns_question_create(query_buffer, (char*)lookup->key->name.name, lookup->key->type,
                                                   lookup->transaction);
    if (result < DNS_PACKET_MINIMUM_SIZE)
    {
        log_msg("Failed to create DNS question for query \"%s\".", lookup->key->name.name);
        return;
    }

    // Set or unset the QD bit based on user preference
    dns_buf_set_rd(query_buffer, !context.cmd_args.norecurse);
    
    errno = 0;
    ssize_t sent = sendto(lookup->socket->descriptor, query_buffer, (size_t) result, 0,
                          (struct sockaddr *) &lookup->resolver->address,
                          sockaddr_storage_size(&lookup->resolver->address));
    if(sent != result)
    {
        if(errno != EAGAIN && errno != EWOULDBLOCK)
        {
            log_msg("Error sending: %s\n", strerror(errno));
        }
    }
}

#define STAT_IDX_OK 0
#define STAT_IDX_NXDOMAIN 1
#define STAT_IDX_SERVFAIL 2
#define STAT_IDX_REFUSED 3
#define STAT_IDX_FORMERR 4

void my_stats_to_msg(stats_exchange_t *stats_msg)
{
    stats_msg->finished = context.stats.finished;
    stats_msg->finished_success = context.stats.finished_success;
    stats_msg->fork_index = context.fork_index;
    stats_msg->mismatch_domain = context.stats.mismatch_domain;
    stats_msg->mismatch_id = context.stats.mismatch_id;
    stats_msg->numdomains = context.stats.numdomains;
    stats_msg->numreplies = context.stats.numreplies;
    stats_msg->all_rcodes[STAT_IDX_OK] = context.stats.all_rcodes[DNS_RCODE_OK];
    stats_msg->all_rcodes[STAT_IDX_NXDOMAIN] = context.stats.all_rcodes[DNS_RCODE_NXDOMAIN];
    stats_msg->all_rcodes[STAT_IDX_SERVFAIL] = context.stats.all_rcodes[DNS_RCODE_SERVFAIL];
    stats_msg->all_rcodes[STAT_IDX_REFUSED] = context.stats.all_rcodes[DNS_RCODE_REFUSED];
    stats_msg->all_rcodes[STAT_IDX_FORMERR] = context.stats.all_rcodes[DNS_RCODE_FORMERR];
    stats_msg->final_rcodes[STAT_IDX_OK] = context.stats.final_rcodes[DNS_RCODE_OK];
    stats_msg->final_rcodes[STAT_IDX_NXDOMAIN] = context.stats.final_rcodes[DNS_RCODE_NXDOMAIN];
    stats_msg->final_rcodes[STAT_IDX_SERVFAIL] = context.stats.final_rcodes[DNS_RCODE_SERVFAIL];
    stats_msg->final_rcodes[STAT_IDX_REFUSED] = context.stats.final_rcodes[DNS_RCODE_REFUSED];
    stats_msg->final_rcodes[STAT_IDX_FORMERR] = context.stats.final_rcodes[DNS_RCODE_FORMERR];
    stats_msg->current_rate = context.stats.current_rate;
    stats_msg->success_rate = context.stats.success_rate;
    stats_msg->numparsed = context.stats.numparsed;
    stats_msg->done = (context.state >= STATE_DONE);
    for(size_t i = 0; i <= context.cmd_args.resolve_count; i++)
    {
        stats_msg->timeouts[i] = context.stats.timeouts[i];
    }
}

void send_stats()
{
    static stats_exchange_t stats_msg;
    
    my_stats_to_msg(&stats_msg);

    if(write(context.sockets.write_pipe.descriptor, &stats_msg, sizeof(stats_msg)) != sizeof(stats_msg))
    {
        log_msg("Could not send stats atomically.\n");
    }
}

void check_progress()
{
    static struct timespec last_time;
    static char timeouts[4096];
    static struct timespec now;
    static const char* stats_format = "\033[H\033[2J" // Clear screen (probably simplest and most portable solution)
            "Processed queries: %zu\n"
            "Received packets: %zu\n"
            "Progress: %.2f%% (%02lld h %02lld min %02lld sec / %02lld h %02lld min %02lld sec)\n"
            "Current incoming rate: %zu pps, average: %zu pps\n"
            "Current success rate: %zu pps, average: %zu pps\n"
            "Finished total: %zu, success: %zu (%.2f%%)\n"
            "Mismatched domains: %zu (%.2f%%), IDs: %zu (%.2f%%)\n"
            "Failures: %s\n"
            "Response: | Success:               | Total:\n"
            "OK:       | %12zu (%6.2f%%) | %12zu (%6.2f%%)\n"
            "NXDOMAIN: | %12zu (%6.2f%%) | %12zu (%6.2f%%)\n"
            "SERVFAIL: | %12zu (%6.2f%%) | %12zu (%6.2f%%)\n"
            "REFUSED:  | %12zu (%6.2f%%) | %12zu (%6.2f%%)\n"
            "FORMERR:  | %12zu (%6.2f%%) | %12zu (%6.2f%%)\n";

    clock_gettime(CLOCK_MONOTONIC, &now);

    time_t elapsed_ns = (now.tv_sec - last_time.tv_sec) * 1000000000 + (now.tv_nsec - last_time.tv_nsec);
    size_t rate_pps = elapsed_ns == 0 ? 0 : context.stats.current_rate * TIMED_RING_S / elapsed_ns;
    size_t rate_success = elapsed_ns == 0 ? 0 : context.stats.success_rate * TIMED_RING_S / elapsed_ns;
    last_time = now;

    // Send the stats of the child to the parent process
    if(context.cmd_args.num_processes > 1 && context.fork_index != 0)
    {
        send_stats();
        goto end_stats;
    }

    if(context.cmd_args.quiet)
    {
        return;
    }

    // Go on with printing stats.

    float progress = context.state == STATE_DONE ? 1 : 0;
    if(context.domainfile_size > 0) // If the domain file is not a real file, the progress cannot be estimated.
    {
        // Get a rough estimate of the progress, only roughly proportional to the number of domains.
        // Will be very inaccurate if the domain file is sorted per domain name length.
        long int domain_file_position = ftell(context.domainfile);
        if (domain_file_position >= 0)
        {
            progress = domain_file_position / (float)context.domainfile_size;
        }
    }

    time_t total_elapsed_ns = (now.tv_sec - context.stats.start_time.tv_sec) * 1000000000
        + (now.tv_nsec - context.stats.start_time.tv_nsec); // since last output
    long long elapsed = now.tv_sec - context.stats.start_time.tv_sec; // resolution of one second should be okay
    long long sec = elapsed % 60;
    long long min = (elapsed / 60) % 60;
    long long h = elapsed / 3600;

    long long estimated_time = progress == 0 ? 0 : (long long)(elapsed / progress);
    if(estimated_time < elapsed)
    {
        estimated_time = elapsed;
    }
    long long prog_sec = estimated_time % 60;
    long long prog_min = (estimated_time / 60) % 60;
    long long prog_h = (estimated_time / 3600);

#define stats_percent(a, b) ((b) == 0 ? 0 : (a) / (float) (b) * 100)
#define stat_abs_share(a, b) a, stats_percent(a, b)
#define rcode_stat(code) stat_abs_share(context.stats.final_rcodes[(code)], context.stats.finished_success),\
        stat_abs_share(context.stats.all_rcodes[(code)], context.stats.numparsed)
#define rcode_stat_multi(code) stat_abs_share(context.stat_messages[0].final_rcodes[(code)], \
    context.stat_messages[0].finished_success),\
        stat_abs_share(context.stat_messages[0].all_rcodes[(code)], context.stat_messages[0].numparsed)
    
    if(context.cmd_args.num_processes == 1)
    {
        size_t average_pps = elapsed == 0 ? rate_pps : context.stats.numreplies * TIMED_RING_S / total_elapsed_ns;
        size_t average_success = elapsed == 0 ? rate_success : context.stats.finished_success * TIMED_RING_S / total_elapsed_ns;

        // Print the detailed timeout stats (number of tries before timeout) to the timeouts buffer.
        int offset = 0;
        for (size_t i = 0; i <= context.cmd_args.resolve_count; i++)
        {
            float share = stats_percent(context.stats.timeouts[i], context.stats.finished);
            int result = snprintf(timeouts + offset, sizeof(timeouts) - offset, "%zu: %.2f%%, ", i, share);
            if (result <= 0 || result >= sizeof(timeouts) - offset)
            {
                break;
            }
            offset += result;
        }

        fprintf(stderr,
                stats_format,
                context.stats.numdomains,
                context.stats.numreplies,
                progress * 100, h, min, sec, prog_h, prog_min, prog_sec, rate_pps, average_pps,
                rate_success, average_success,
                context.stats.finished,
                stat_abs_share(context.stats.finished_success, context.stats.finished),
                stat_abs_share(context.stats.mismatch_domain, context.stats.numparsed),
                stat_abs_share(context.stats.mismatch_id, context.stats.numparsed),
                timeouts,

                rcode_stat(DNS_RCODE_OK),
                rcode_stat(DNS_RCODE_NXDOMAIN),
                rcode_stat(DNS_RCODE_SERVFAIL),
                rcode_stat(DNS_RCODE_REFUSED),
                rcode_stat(DNS_RCODE_FORMERR)
        );
    }
    else
    {
        my_stats_to_msg(&context.stat_messages[0]);

        for(size_t j = 1; j < context.cmd_args.num_processes; j++)
        {
            for (size_t i = 0; i <= context.cmd_args.resolve_count; i++)
            {
                context.stat_messages[0].timeouts[i] += context.stat_messages[j].timeouts[i];
            }
            context.stat_messages[0].numreplies += context.stat_messages[j].numreplies;
            context.stat_messages[0].numparsed += context.stat_messages[j].numparsed;
            context.stat_messages[0].numdomains += context.stat_messages[j].numdomains;
            context.stat_messages[0].mismatch_id += context.stat_messages[j].mismatch_id;
            context.stat_messages[0].mismatch_domain += context.stat_messages[j].mismatch_domain;
            context.stat_messages[0].finished_success += context.stat_messages[j].finished_success;
            context.stat_messages[0].finished += context.stat_messages[j].finished;
            for(size_t i = 0; i < 5; i++)
            {
                context.stat_messages[0].all_rcodes[i] += context.stat_messages[j].all_rcodes[i];
            }
            for(size_t i = 0; i < 5; i++)
            {
                context.stat_messages[0].final_rcodes[i] += context.stat_messages[j].final_rcodes[i];
            }
            rate_pps += context.stat_messages[j].current_rate;
            rate_success += context.stat_messages[j].success_rate;
        }

        size_t average_pps = elapsed == 0 ? rate_pps :
                             context.stat_messages[0].numreplies * TIMED_RING_S / total_elapsed_ns;
        size_t average_success = elapsed == 0 ? rate_pps :
                             context.stat_messages[0].finished_success * TIMED_RING_S / total_elapsed_ns;


        // Print the detailed timeout stats (number of tries before timeout) to the timeouts buffer.
        int offset = 0;
        for (size_t i = 0; i <= context.cmd_args.resolve_count; i++)
        {
            float share = stats_percent(context.stat_messages[0].timeouts[i], context.stat_messages[0].finished);
            int result = snprintf(timeouts + offset, sizeof(timeouts) - offset, "%zu: %.2f%%, ", i, share);
            if (result <= 0 || result >= sizeof(timeouts) - offset)
            {
                break;
            }
            offset += result;
        }

        fprintf(stderr,
                stats_format,
                context.stat_messages[0].numdomains,
                context.stat_messages[0].numreplies,
                progress * 100, h, min, sec, prog_h, prog_min, prog_sec, rate_pps, average_pps,
                rate_success, average_success,
                context.stat_messages[0].finished,
                stat_abs_share(context.stat_messages[0].finished_success, context.stat_messages[0].finished),
                stat_abs_share(context.stat_messages[0].mismatch_domain, context.stat_messages[0].numparsed),
                stat_abs_share(context.stat_messages[0].mismatch_id, context.stat_messages[0].numparsed),
                timeouts,

                rcode_stat_multi(STAT_IDX_OK),
                rcode_stat_multi(STAT_IDX_NXDOMAIN),
                rcode_stat_multi(STAT_IDX_SERVFAIL),
                rcode_stat_multi(STAT_IDX_REFUSED),
                rcode_stat_multi(STAT_IDX_FORMERR)
        );
    }

end_stats:
    context.stats.current_rate = 0;
    context.stats.success_rate = 0;
    // Call this function in about one second again
    timed_ring_add(&context.ring, TIMED_RING_S, check_progress);
}

void done()
{
    context.done[context.fork_index] = true;
    if(context.fork_index != 0 || context.cmd_args.num_processes == 1)
    {
        context.state = STATE_DONE;
    }
    else
    {
        context.finished++;
        context.state = (context.finished < context.cmd_args.num_processes ? STATE_WAIT_CHILDREN : STATE_DONE);
    }
    if(context.cmd_args.num_processes > 1 && context.fork_index != 0)
    {
        send_stats();
    }
    check_progress();
}

void can_send()
{
    char *qname;
    bool new;

    while (hashmapSize(context.map) < context.cmd_args.hashmap_size && context.state <= STATE_QUERYING)
    {
        if(!next_query(&qname))
        {
            context.state = STATE_COOLDOWN; // We will not create any new queries
            break;
        }
        context.stats.numdomains++;
        lookup_t *lookup = new_lookup(qname, context.cmd_args.record_type, &new);
        if(!new)
        {
            continue;
        }
        send_query(lookup);
    }
}

bool is_unacceptable(dns_pkt_t *packet)
{
    return context.cmd_args.retry_codes[packet->head.header.rcode];
}

void lookup_done(lookup_t *lookup)
{
    context.stats.finished++;

    hashmapRemove(context.map, lookup->key);

    // Return lookup to pool.
    // According to ISO/IEC 9899:TC2 §6.7.2.1 (13), structs are not padded at the beginning
    ((lookup_key_t**)context.lookup_pool.data)[context.lookup_pool.len++] = lookup->key;


    // When transmission is not aggressive, we only start a new lookup after another one has finished.
    // When our transmission is very aggressive, we also start a new lookup, although we listen for EPOLLOUT
    // events as well.
    if(context.cmd_args.extreme == 0 || context.cmd_args.extreme == 2)
    {
        can_send();
    }

    if(context.state == STATE_COOLDOWN && hashmapSize(context.map) <= 0)
    {
        done();
    }
}

bool retry(lookup_t *lookup)
{
    context.stats.timeouts[lookup->tries]--;
    context.stats.timeouts[++lookup->tries]++;
    if(lookup->tries < context.cmd_args.resolve_count)
    {
        lookup->ring_entry = timed_ring_add(&context.ring, context.cmd_args.interval_ms * TIMED_RING_MS, lookup);
        send_query(lookup);
        return true;
    }
    return false;
}

void ring_timeout(void *param)
{
    if(param == check_progress)
    {
        check_progress();
        return;
    }

    lookup_t *lookup = param;
    if(!retry(lookup))
    {
        lookup_done(lookup);
    }
}

void do_read(uint8_t *offset, size_t len, struct sockaddr_storage *recvaddr)
{
    static dns_pkt_t packet;
    static uint8_t *parse_offset;
    static lookup_t *lookup;
    static resolver_t* resolver;
    static char json_buffer[0xFFFF];

    context.stats.current_rate++;
    context.stats.numreplies++;

    if(context.cmd_args.verify_ip)
    {
        resolver = hashmapGet(context.resolver_map, recvaddr);
        if(resolver == NULL)
        {
            //log_msg("Fake/NAT reply from %s\n", sockaddr2str(recvaddr));
            return;
        }
    }

    if(!dns_parse_question(offset, len, &packet.head, &parse_offset))
    {
        return;
    }

    context.stats.numparsed++;
    context.stats.all_rcodes[packet.head.header.rcode]++;

    // TODO: Remove unnecessary copy.
    //search_key.domain = (char*)packet.head.question.name.name;
    lookup = hashmapGet(context.map, &packet.head.question);
    if(!lookup) // Most likely reason: delayed response after duplicate query
    {
        context.stats.mismatch_domain++;
        return;
    }

    if(lookup->transaction != packet.head.header.id)
    {
        context.stats.mismatch_id++;
        return;
    }

    timed_ring_remove(&context.ring, lookup->ring_entry); // Clear timeout trigger

    // Check whether we want to retry resending the packet
    if(is_unacceptable(&packet))
    {
        // We may have tried to many times already.
        if(!retry(lookup))
        {
            // If this is the case, we will not try again.
            lookup_done(lookup);
        }
    }
    else
    {
        // We are done with the lookup because we received an acceptable reply.
        context.stats.finished_success++;
        context.stats.final_rcodes[packet.head.header.rcode]++;
        context.stats.success_rate++;

        // Print packet
        time_t now = time(NULL);
        uint16_t short_len = (uint16_t) len;
        uint8_t *next = parse_offset;
        dns_record_t rec;
        size_t non_add_count = packet.head.header.ans_count + packet.head.header.auth_count;
        dns_section_t section = DNS_SECTION_ANSWER;

        switch(context.cmd_args.output)
        {
            case OUTPUT_BINARY:
                // The output file is platform dependent for performance reasons.
                fwrite(&now, sizeof(now), 1, context.outfile);
                fwrite(recvaddr, sizeof(*recvaddr), 1, context.outfile);
                fwrite(&short_len, sizeof(short_len), 1, context.outfile);
                fwrite(offset, short_len, 1, context.outfile);
                break;

            case OUTPUT_TEXT_FULL: // Print packet similar to dig style
                // Resolver and timestamp are not part of the packet, we therefore have to print it manually
                fprintf(context.outfile, ";; Server: %s\n;; Size: %" PRIu16 "\n;; Unix time: %lu\n",
                        sockaddr2str(recvaddr), short_len, now);
                dns_print_packet(context.outfile, &packet, offset, len, next);
                break;

            case OUTPUT_NDJSON: // Only print records from answer section that match the query name (in ndjson)

                for(size_t rec_index = 0; dns_parse_record_raw(offset, next, offset + len, &next, &rec); rec_index++)
                {
                    fprintf(context.outfile,
                            "{\"query_name\":\"%s\",\"query_type\":\"%s\",",
                            dns_name2str(&packet.head.question.name),
                            dns_record_type2str((dns_record_type) packet.head.question.type));

                    json_escape(json_buffer, dns_raw_record_data2str(&rec, offset, offset + short_len), sizeof(json_buffer));

                    fprintf(context.outfile,
                            "\"resp_name\":\"%s\",\"resp_type\":\"%s\",\"data\":\"%s\"}\n",
                            dns_name2str(&rec.name),
                            dns_record_type2str((dns_record_type) rec.type),
                            json_buffer);
                }

                break;

            case OUTPUT_TEXT_SIMPLE: // Only print records from answer section that match the query name
                if(context.format.print_question)
                {
                    if(!context.format.include_meta)
                    {
                        fprintf(context.outfile,
                                "%s %s %s\n",
                                dns_name2str(&packet.head.question.name),
                                context.format.ttl ? dns_class2str((dns_class) packet.head.question.class) : "",
                                dns_record_type2str((dns_record_type) packet.head.question.type));
                    }
                    else
                    {
                        fprintf(context.outfile,
                                "%s %lu %s %s %s %s\n",
                                sockaddr2str(recvaddr),
                                now,
                                dns_rcode2str((dns_rcode)packet.head.header.rcode),
                                dns_name2str(&packet.head.question.name),
                                context.format.ttl ? dns_class2str((dns_class) packet.head.question.class) : "",
                                dns_record_type2str((dns_record_type) packet.head.question.type));
                    }
                }
                for(size_t rec_index = 0; dns_parse_record_raw(offset, next, offset + len, &next, &rec); rec_index++)
                {
                    char *section_separator = "";
                    if(rec_index >= packet.head.header.ans_count)
                    {
                        if(rec_index >= non_add_count)
                        {
                            // We are entering a new section
                            if(context.format.separate_sections && section != DNS_SECTION_ADDITIONAL)
                            {
                                section_separator = "\n";
                            }
                            section = DNS_SECTION_ADDITIONAL;
                        }
                        else
                        {
                            // We are entering a new section
                            if(context.format.separate_sections && section != DNS_SECTION_AUTHORITY)
                            {
                                section_separator = "\n";
                            }
                            section = DNS_SECTION_AUTHORITY;
                        }
                    }

                    if((context.format.match_name && !dns_names_eq(&rec.name, &packet.head.question.name))
                            || !context.format.sections[section])
                    {
                        continue;
                    }
                    if(!context.format.ttl)
                    {
                        fprintf(context.outfile,
                                "%s%s%s %s %s\n",
                                section_separator,
                                context.format.indent_sections ? "\t" : "",
                                dns_name2str(&rec.name),
                                dns_record_type2str((dns_record_type) rec.type),
                                dns_raw_record_data2str(&rec, offset, offset + short_len));
                    }
                    else
                    {
                        fprintf(context.outfile,
                                "%s%s%s %s %" PRIu32 " %s %s\n",
                                section_separator,
                                context.format.indent_sections ? "\t" : "",
                                dns_name2str(&rec.name),
                                dns_class2str((dns_class)rec.class),
                                rec.ttl,
                                dns_record_type2str((dns_record_type) rec.type),
                                dns_raw_record_data2str(&rec, offset, offset + short_len));
                    }
                }
                if(context.format.separate_queries)
                {
                    fprintf(context.outfile, "\n");
                }
                break;
        }

        lookup_done(lookup);
        
        // Sometimes, users may want to obtain results immediately.
        if(context.cmd_args.flush)
        {
            fflush(context.outfile);
        }
    }
}

#ifdef PCAP_SUPPORT
void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *packet)
{
    static struct sockaddr_storage addr;
    static size_t len;
    static const uint8_t *frame;
    static ssize_t remaining;

    // We expect at least an Ethernet header + IPv4/IPv6 header (>= 20) + UDP header
    if(header->len < 42)
    {
        return;
    }
    frame = ((uint8_t*)packet) + 14;
    remaining = header->len - 14;

    if(((struct ether_header*)packet)->ether_type == context.ether_type_ip)
    {
        unsigned int ip_hdr_len = ((struct iphdr *) frame)->ihl * 4;
        remaining -= ip_hdr_len;

        // Check whether the packet is long enough to still contain a UDP frame
        if(((struct iphdr *) frame)->protocol != 17
            || remaining < 0)
        {
            return;
        }
        frame += ip_hdr_len;
        len = (size_t)remaining;
        remaining -= ntohs(((struct udphdr *) frame)->len);
        if(remaining != 0)
        {
            return;
        }
        frame += 8;
        addr.ss_family = AF_INET;
    }
    else
    {
        return;
    }
    do_read((uint8_t*)frame, len, &addr);
}

void pcap_can_read()
{
    pcap_dispatch(context.pcap, 1, pcap_callback, NULL);
}
#endif

void can_read(socket_info_t *info)
{
    static uint8_t readbuf[0xFFFF];
    static struct sockaddr_storage recvaddr;
    static socklen_t fromlen;
    static ssize_t num_received;



    fromlen = sizeof(recvaddr);
    num_received = recvfrom(info->descriptor, readbuf, sizeof(readbuf), 0, (struct sockaddr *) &recvaddr, &fromlen);
    if(num_received <= 0)
    {
        return;
    }

    do_read(readbuf, (size_t)num_received, &recvaddr);
}

bool cmp_lookup(void *lookup1, void *lookup2)
{
    return dns_names_eq(&((lookup_key_t *) lookup1)->name, &((lookup_key_t *) lookup2)->name);
    //return strcasecmp(((lookup_key_t *) lookup1)->domain,((lookup_key_t *) lookup2)->domain) == 0;
}

void binfile_write_head()
{
    // Write file type signature including null character
    char signature[] = "massdns";
    fwrite(signature, sizeof(signature), 1, context.outfile);

    // Write a uint32_t integer in native byte order to allow detection of endianness
    uint32_t endianness = 0x12345678;
    fwrite(&endianness, sizeof(endianness), 1, context.outfile);

    // Write uint32_t file version number
    // Number is to be incremented if file format is changed
    fwrite(&OUTPUT_BINARY_VERSION, sizeof(OUTPUT_BINARY_VERSION), 1, context.outfile);

    // Write byte length of native size_t type
    uint8_t size_t_len = sizeof(size_t);
    fwrite(&size_t_len, sizeof(size_t_len), 1, context.outfile);

    // Write size of time_t
    size_t time_t_len = sizeof(time_t);
    fwrite(&time_t_len, sizeof(time_t_len), 1, context.outfile);

    // Write byte length of sockaddr_storage size
    size_t sockaddr_storage_len = sizeof(struct sockaddr_storage);
    fwrite(&sockaddr_storage_len, sizeof(sockaddr_storage_len), 1, context.outfile);

    // Write offset of ss_family within sockaddr_storage
    size_t ss_family_offset = offsetof(struct sockaddr_storage, ss_family);
    fwrite(&ss_family_offset, sizeof(ss_family_offset), 1, context.outfile);

    // Write size of sa_family_size within sockaddr_storage
    size_t sa_family_size = sizeof(sa_family_t);
    fwrite(&sa_family_size, sizeof(sa_family_size), 1, context.outfile);

    // Write size of in_port_t
    size_t sin_port_len = sizeof(in_port_t);
    fwrite(&sin_port_len, sizeof(sin_port_len), 1, context.outfile);


    // Write IPv4 family constant
    sa_family_t family_inet = AF_INET;
    fwrite(&family_inet, sizeof(family_inet), 1, context.outfile);

    // Write offset of sin_addr within sockaddr_in
    size_t sin_addr_offset = offsetof(struct sockaddr_in, sin_addr);
    fwrite(&sin_addr_offset, sizeof(sin_addr_offset), 1, context.outfile);

    // Write offset of sin_port within sockaddr_in
    size_t sin_port_offset = offsetof(struct sockaddr_in, sin_port);
    fwrite(&sin_port_offset, sizeof(sin_port_offset), 1, context.outfile);


    // Write IPv6 family constant
    sa_family_t family_inet6 = AF_INET6;
    fwrite(&family_inet6, sizeof(family_inet6), 1, context.outfile);

    // Write offset of sin6_addr within sockaddr_in6
    size_t sin6_addr_offset = offsetof(struct sockaddr_in6, sin6_addr);
    fwrite(&sin6_addr_offset, sizeof(sin6_addr_offset), 1, context.outfile);

    // Write offset of sin6_port within sockaddr_in6
    size_t sin6_port_offset = offsetof(struct sockaddr_in6, sin6_port);
    fwrite(&sin6_port_offset, sizeof(sin6_port_offset), 1, context.outfile);
}

void privilege_drop()
{
    if (geteuid() != 0)
    {
        return;
    }
    char *username = context.cmd_args.drop_user ? context.cmd_args.drop_user : COMMON_UNPRIVILEGED_USER;
    char *groupname = context.cmd_args.drop_group ? context.cmd_args.drop_group : COMMON_UNPRIVILEGED_GROUP;
    if(!context.cmd_args.root)
    {
        struct passwd *drop_user = getpwnam(username);
        struct group *drop_group = getgrnam(groupname);
        if (drop_group && drop_user && setgid(drop_group->gr_gid) == 0 && setuid(drop_user->pw_uid) == 0)
        {
            if (!context.cmd_args.quiet)
            {
                log_msg("Privileges have been dropped to \"%s:%s\" for security reasons.\n", username, groupname);
            }
        }
        else
        {
            log_msg("Privileges could not be dropped to \"%s:%s\".\n"
                "For security reasons, this program will only run as root user when supplied with --root, "
                "which is not recommended.\n"
                "It is better practice to run this program as a different user.\n", username, groupname);
            clean_exit(EXIT_FAILURE);
        }
    }
    else
    {
        if (!context.cmd_args.quiet)
        {
            log_msg("[WARNING] Privileges were not dropped. This is not recommended.\n");
        }
    }
}

#ifdef PCAP_SUPPORT
void pcap_setup()
{
    context.pcap_dev = pcap_lookupdev(context.pcap_error);
    if(context.pcap_dev == NULL)
    {
        goto pcap_error;
    }
    log_msg("Default pcap device: %s", context.pcap_dev);


    char mac_filter[sizeof("ether dst ") - 1 + MAC_READABLE_BUFLEN];
    char *mac_readable = mac_filter + sizeof("ether dst ") - 1;
    strcpy(mac_filter, "ether dst ");

    if(get_iface_hw_addr_readable(context.pcap_dev, mac_readable) != 0)
    {
        log_msg("\nFailed to determine the hardware address of the device.\n");
        goto pcap_error_noprint;
    }
    log_msg(", address: %s\n", mac_readable);


    context.pcap = pcap_create(context.pcap_dev, context.pcap_error);
    if(context.pcap == NULL)
    {
        goto pcap_error;
    }

    if(pcap_set_snaplen(context.pcap, 0xFFFF) != 0)
    {
        goto pcap_error;
    }

    if(pcap_setnonblock(context.pcap, 1, context.pcap_error) == -1)
    {
        goto pcap_error;
    }

    if(pcap_set_buffer_size(context.pcap, 1024 * 1024) != 0)
    {
        goto pcap_error;
    }

    int activation_status = pcap_activate(context.pcap);
    if(activation_status != 0)
    {
        log_msg("Error during pcap activation: %s\n", pcap_statustostr(activation_status));
        goto pcap_error_noprint;
    }

    if(pcap_compile(context.pcap, &context.pcap_filter, mac_filter, 0, PCAP_NETMASK_UNKNOWN) != 0)
    {
        log_msg("Error during pcap filter compilation: %s\n", pcap_geterr(context.pcap));
        goto pcap_error_noprint;
    }

    if(pcap_setfilter(context.pcap, &context.pcap_filter) != 0)
    {
        log_msg("Error setting pcap filter: %s\n", pcap_geterr(context.pcap));
        goto pcap_error_noprint;
    }

    context.pcap_info.descriptor = pcap_get_selectable_fd(context.pcap);
    if(context.pcap_info.descriptor < 0)
    {
        goto pcap_error;
    }
#ifdef HAVE_EPOLL
    struct epoll_event ev;
    bzero(&ev, sizeof(ev));
    ev.data.ptr = &context.pcap_info;
    ev.events = EPOLLIN;
    if (epoll_ctl(context.epollfd, EPOLL_CTL_ADD, context.pcap_info.descriptor, &ev) != 0)
    {
        log_msg("Failed to add epoll event: %s\n", strerror(errno));
        clean_exit(EXIT_FAILURE);
    }
#endif
    return;

pcap_error:
    log_msg("Error during pcap setup: %s\n", context.pcap_error);
pcap_error_noprint:
    cleanup();
    clean_exit(EXIT_FAILURE);
}
#endif

void init_pipes()
{
    // We don't need any pipes if the process is not forked
    if(context.cmd_args.num_processes <= 1)
    {
        return;
    }

    // Otherwise create a unidirectional pipe for reading and writing from every fork
    context.sockets.pipes = safe_malloc(sizeof(*context.sockets.pipes) * 2 * context.cmd_args.num_processes);
    for(size_t i = 0; i < context.cmd_args.num_processes; i++)
    {
        if(pipe(context.sockets.pipes + i * 2) != 0)
        {
            log_msg("Pipe failed: %s\n", strerror(errno));
            clean_exit(EXIT_FAILURE);
        }
    }

}

void setup_pipes()
{
    if(context.fork_index == 0) // We are in the main process
    {
        context.sockets.master_pipes_read = safe_calloc(sizeof(socket_info_t) * context.cmd_args.num_processes);

        // Close all pipes that the children use to write
        for (size_t i = 0; i < context.cmd_args.num_processes; i++)
        {
            close(context.sockets.pipes[2 * i + 1]);
            context.sockets.pipes[2 * i + 1] = -1;

            context.sockets.master_pipes_read[i].descriptor = context.sockets.pipes[2 * i];
            context.sockets.master_pipes_read[i].type = SOCKET_TYPE_CONTROL;
            context.sockets.master_pipes_read[i].data = (void*)i;

            if(context.cmd_args.busypoll)
            {
                continue;
            }

#ifdef HAVE_EPOLL
            // Add all pipes the main process can read from to the epoll descriptor
            struct epoll_event ev;
            bzero(&ev, sizeof(ev));
            ev.data.ptr = &context.sockets.master_pipes_read[i];
            ev.events = EPOLLIN;
            if (epoll_ctl(context.epollfd, EPOLL_CTL_ADD, context.sockets.master_pipes_read[i].descriptor, &ev) != 0)
            {
                log_msg("Failed to add epoll event: %s\n", strerror(errno));
                clean_exit(EXIT_FAILURE);
            }
#endif
        }
    }
    else // It's a child process
    {
        // Close all pipes except the two belonging to the current process
        for (size_t i = 0; i < context.cmd_args.num_processes; i++)
        {
            if (i == context.fork_index)
            {
                continue;
            }
            close(context.sockets.pipes[2 * i]);
            close(context.sockets.pipes[2 * i + 1]);
            context.sockets.pipes[2 * i] = -1;
            context.sockets.pipes[2 * i + 1] = -1;
        }
        context.sockets.write_pipe.descriptor = context.sockets.pipes[2 * context.fork_index + 1];
        context.sockets.write_pipe.type = SOCKET_TYPE_CONTROL;
        close(context.sockets.pipes[2 * context.fork_index]);
        context.sockets.pipes[2 * context.fork_index] = -1;
    }
}

void read_control_message(socket_info_t *socket_info)
{
    size_t process = (size_t)socket_info->data;
    ssize_t read_result = read(socket_info->descriptor, context.stat_messages + process, sizeof(stats_exchange_t));
    if(read_result > 0 && read_result < sizeof(stats_exchange_t))
    {
        log_msg("Atomic read failed: Read %ld bytes.\n", read_result);
    }
    if(!context.done[process] && context.stat_messages[process].done)
    {
        context.finished++;
        context.done[process] = true;
    }
}

void make_query_sockets_nonblocking()
{
    for(size_t i = 0; i < context.sockets.interfaces4.len; i++)
    {
        socket_noblock(((socket_info_t*)context.sockets.interfaces4.data) + i);
    }
    for(size_t i = 0; i < context.sockets.interfaces6.len; i++)
    {
        socket_noblock(((socket_info_t*)context.sockets.interfaces6.data) + i);
    }
}

void run()
{
    static char multiproc_outfile_name[8192];

    if(!urandom_init())
    {
        log_msg("Failed to open /dev/urandom: %s\n", strerror(errno));
        clean_exit(EXIT_FAILURE);
    }

    context.map = hashmapCreate(context.cmd_args.hashmap_size, hash_lookup_key, cmp_lookup);
    if(context.map == NULL)
    {
        log_msg("Failed to create hashmap.\n");
        clean_exit(EXIT_FAILURE);
    }

    context.lookup_pool.len = context.cmd_args.hashmap_size;
    context.lookup_pool.data = safe_calloc(context.lookup_pool.len * sizeof(void*));
    context.lookup_space = safe_calloc(context.lookup_pool.len * sizeof(*context.lookup_space));
    for(size_t i = 0; i < context.lookup_pool.len; i++)
    {
        ((lookup_entry_t**)context.lookup_pool.data)[i] = context.lookup_space + i;
    }

    timed_ring_init(&context.ring, max(context.cmd_args.interval_ms, 1000), 2 * TIMED_RING_MS, context.cmd_args.timed_ring_buckets);

#ifdef HAVE_EPOLL
    uint32_t socket_events = EPOLLOUT;

    struct epoll_event pevents[100000];
    bzero(pevents, sizeof(pevents));
#endif

    init_pipes();
    context.pids = safe_calloc(context.cmd_args.num_processes * sizeof(*context.pids));
    context.done = safe_calloc(context.cmd_args.num_processes * sizeof(*context.done));
    context.fork_index = split_process(context.cmd_args.num_processes, context.pids);
#ifdef HAVE_EPOLL
    if(!context.cmd_args.busypoll)
    {
        context.epollfd = epoll_create(1);
    }
#endif
#ifdef PCAP_SUPPORT
    if(context.cmd_args.use_pcap)
    {
        pcap_setup();
    }
    else
#endif
#ifdef HAVE_EPOLL
    {
        socket_events |= EPOLLIN;
    }
#endif
    if(context.cmd_args.num_processes > 1)
    {
        setup_pipes();
        if(context.fork_index == 0)
        {
            context.stat_messages = safe_calloc(context.cmd_args.num_processes * sizeof(stats_exchange_t));
        }
    }

    if(strcmp(context.cmd_args.outfile_name, "-") != 0)
    {
        if(context.cmd_args.num_processes > 1)
        {
            snprintf(multiproc_outfile_name, sizeof(multiproc_outfile_name), "%s%zd", context.cmd_args.outfile_name,
            context.fork_index);
            context.outfile = fopen(multiproc_outfile_name, "w");
        }
        else
        {
            context.outfile = fopen(context.cmd_args.outfile_name, "w");
        }
        if(!context.outfile)
        {
            log_msg("Failed to open output file: %s\n", strerror(errno));
            clean_exit(EXIT_FAILURE);
        }
    }
    else
    {
        if(context.cmd_args.num_processes > 1)
        {
            log_msg("Multiprocessing is currently only supported through the -w parameter.\n");
            clean_exit(EXIT_FAILURE);
        }
    }

    if(context.domainfile != stdin)
    {
        context.domainfile = fopen(context.cmd_args.domains, "r");
        if (context.domainfile == NULL)
        {
            log_msg("Failed to open domain file \"%s\".\n", context.cmd_args.domains);
            clean_exit(EXIT_FAILURE);
        }
    }

    if(context.cmd_args.output == OUTPUT_BINARY)
    {
        binfile_write_head();
    }


    // It is important to call default interface sockets setup before reading the resolver list
    // because that way we can warn if the socket creation for a certain IP protocol failed although a resolver
    // requires the protocol.
    query_sockets_setup();
    context.resolvers = massdns_resolvers_from_file(context.cmd_args.resolvers);

    privilege_drop();

#ifdef HAVE_EPOLL
    if(!context.cmd_args.busypoll)
    {
        add_sockets(context.epollfd, socket_events, EPOLL_CTL_ADD, &context.sockets.interfaces4);
        add_sockets(context.epollfd, socket_events, EPOLL_CTL_ADD, &context.sockets.interfaces6);
    }
#endif
    if(context.cmd_args.busypoll)
    {
        make_query_sockets_nonblocking();
    }


    clock_gettime(CLOCK_MONOTONIC, &context.stats.start_time);
    check_progress();

    if(!context.cmd_args.busypoll)
    {
#ifdef HAVE_EPOLL
        while(context.state < STATE_DONE)
        {

            int ready = epoll_wait(context.epollfd, pevents, sizeof(pevents) / sizeof(pevents[0]), 1);
            if (ready < 0)
            {
                log_msg("Epoll failure: %s\n", strerror(errno));
            }
            else if (ready == 0) // Epoll timeout
            {
                timed_ring_handle(&context.ring, ring_timeout);
            }
            else if (ready > 0)
            {
                for (int i = 0; i < ready; i++)
                {
                    socket_info_t *socket_info = pevents[i].data.ptr;
                    if ((pevents[i].events & EPOLLOUT) && socket_info->type == SOCKET_TYPE_QUERY)
                    {
                        can_send();
                        timed_ring_handle(&context.ring, ring_timeout);
                    }
                    if ((pevents[i].events & EPOLLIN) && socket_info->type == SOCKET_TYPE_QUERY)
                    {
                        can_read(socket_info);
                    }
#ifdef PCAP_SUPPORT
                        else if((pevents[i].events & EPOLLIN) && socket_info == &context.pcap_info)
                        {
                            pcap_can_read();
                        }
#endif
                    else if ((pevents[i].events & EPOLLIN) && socket_info->type == SOCKET_TYPE_CONTROL)
                    {
                        read_control_message(socket_info);
                        if(context.finished >= context.cmd_args.num_processes)
                        {
                            context.state = STATE_DONE;
                            break;
                        }
                    }
                }
                timed_ring_handle(&context.ring, ring_timeout);
            }
        }
#endif
    }
    else
    {
        while(context.state < STATE_DONE)
        {
            can_send();
            for(size_t i = 0; i < context.sockets.interfaces4.len; i++)
            {
                can_read(((socket_info_t*)context.sockets.interfaces4.data) + i);
            }
            for(size_t i = 0; i < context.sockets.interfaces6.len; i++)
            {
                can_read(((socket_info_t*)context.sockets.interfaces6.data) + i);
            }
            timed_ring_handle(&context.ring, ring_timeout);

            if(context.cmd_args.num_processes > 1 && context.fork_index == 0)
            {
                for (size_t i = 1; i < context.cmd_args.num_processes; i++)
                {
                    read_control_message(context.sockets.master_pipes_read + i);
                }
                if(context.finished >= context.cmd_args.num_processes)
                {
                    context.state = STATE_DONE;
                    break;
                }
            }
        }
    }
}

void use_stdin()
{
    if (!context.cmd_args.quiet)
    {
        log_msg("Reading domain list from stdin.\n");
    }
    context.domainfile = stdin;
}

int parse_cmd(int argc, char **argv)
{
    bool domain_param = false;

    context.cmd_args.argc = argc;
    context.cmd_args.argv = argv;
    context.cmd_args.help_function = print_help;

    if (argc <= 1)
    {
        print_help();
        clean_exit(EXIT_FAILURE);
    }

#ifdef PCAP_SUPPORT
    // Precompute values so we do not have to call htons for each incoming packet
    context.ether_type_ip = htons(ETHERTYPE_IP);
    context.ether_type_ip6 = htons(ETHERTYPE_IPV6);
#endif

    context.cmd_args.record_type = DNS_REC_INVALID;
    context.domainfile_size = -1;
    context.state = STATE_WARMUP;
    context.logfile = stderr;
    context.outfile = stdout;
    context.cmd_args.outfile_name = "-";

    context.format.match_name = true;
    context.format.sections[DNS_SECTION_ANSWER] = true;

    context.cmd_args.resolve_count = 50;
    context.cmd_args.hashmap_size = 10000;
    context.cmd_args.interval_ms = 500;
    context.cmd_args.timed_ring_buckets = 10000;
    context.cmd_args.output = OUTPUT_TEXT_FULL;
    context.cmd_args.retry_codes[DNS_RCODE_REFUSED] = true;
    context.cmd_args.num_processes = 1;
    context.cmd_args.socket_count = 1;
#ifndef HAVE_EPOLL
    context.cmd_args.busypoll = true;
#endif

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
        {
            print_help();
            clean_exit(EXIT_SUCCESS);
        }
        else if (strcmp(argv[i], "--busypoll") == 0 || strcmp(argv[i], "--busy-poll") == 0)
        {
            context.cmd_args.busypoll = true;
        }
        else if (strcmp(argv[i], "--resolvers") == 0 || strcmp(argv[i], "-r") == 0)
        {
            if (context.cmd_args.resolvers == NULL)
            {
                expect_arg(i);
                context.cmd_args.resolvers = argv[++i];
            }
            else
            {
                log_msg("Resolvers may only be supplied once.\n");
                clean_exit(EXIT_FAILURE);
            }
        }
        else if(strcmp(argv[i], "--retry") == 0)
        {
            expect_arg(i);
            dns_rcode rcode;
            if(dns_str2rcode(argv[++i], &rcode))
            {
                if(!context.cmd_args.retry_codes_set)
                {
                    context.cmd_args.retry_codes[DNS_RCODE_REFUSED] = false;
                    context.cmd_args.retry_codes_set = true;
                }
                context.cmd_args.retry_codes[rcode] = true;
            }
            else if(strcasecmp(argv[i], "never") == 0)
            {
                context.cmd_args.retry_codes[DNS_RCODE_REFUSED] = false;
                context.cmd_args.retry_codes_set = true;
            }
            else
            {
                log_msg("Invalid retry code: %s.\n", argv[i]);
            }
        }
        else if (strcmp(argv[i], "--bindto") == 0 || strcmp(argv[i], "-b") == 0)
        {
            expect_arg(i);
            struct sockaddr_storage *addr = safe_malloc(sizeof(addr));
            if (!str_to_addr(argv[++i], 0, addr))
            {
                free(addr);
                log_msg("Invalid address for socket binding: %s\n", argv[i]);
                clean_exit(EXIT_FAILURE);

            }
            single_list_push_back(addr->ss_family == AF_INET ? &context.cmd_args.bind_addrs4 :
                                  &context.cmd_args.bind_addrs6, addr);
        }
        else if (strcmp(argv[i], "--outfile") == 0 || strcmp(argv[i], "-w") == 0)
        {
            expect_arg(i);
            context.cmd_args.outfile_name = argv[++i];

        }
        else if (strcmp(argv[i], "--error-log") == 0 || strcmp(argv[i], "-l") == 0)
        {
            expect_arg(i);
            char *filename = argv[++i];
            if(strcmp(filename, "-") != 0)
            {
                context.logfile = fopen(filename, "w");
                if(!context.logfile)
                {
                    log_msg("Failed to open log file: %s\n", strerror(errno));
                    clean_exit(EXIT_FAILURE);
                }
            }
        }
        else if (strcmp(argv[i], "--types") == 0 || strcmp(argv[i], "-t") == 0)
        {
            expect_arg(i);
            if (context.cmd_args.record_type != DNS_REC_INVALID)
            {
                log_msg("Currently, only one record type is supported.\n");
                clean_exit(EXIT_FAILURE);
            }
            dns_record_type rtype = dns_str_to_record_type(argv[++i]);
            if (rtype == DNS_REC_INVALID)
            {
                log_msg("Unsupported record type: %s\n", argv[i]);
                clean_exit(EXIT_FAILURE);
            }
            context.cmd_args.record_type = rtype;
        }
        else if (strcmp(argv[i], "--drop-group") == 0)
        {
            expect_arg(i);
            context.cmd_args.drop_group = argv[++i];
        }
        else if (strcmp(argv[i], "--drop-user") == 0)
        {
            expect_arg(i);
            context.cmd_args.drop_user = argv[++i];
        }
        else if (strcmp(argv[i], "--root") == 0)
        {
            context.cmd_args.root = true;
        }
        else if (strcmp(argv[i], "--norecurse") == 0 || strcmp(argv[i], "-n") == 0)
        {
            context.cmd_args.norecurse = true;
        }
        else if (strcmp(argv[i], "--output") == 0 || strcmp(argv[i], "-o") == 0)
        {
            expect_arg(i++);
            switch(argv[i][0])
            {
                case 'B':
                    context.cmd_args.output = OUTPUT_BINARY;
                    break;

                case 'J':
                    context.cmd_args.output = OUTPUT_NDJSON;
                    break;

                case 'S':
                    context.cmd_args.output = OUTPUT_TEXT_SIMPLE;

                    if(strcmp(argv[i], "S") != 0)
                    {
                        context.format.sections[DNS_SECTION_ANSWER] = false;
                        context.format.match_name = false;
                    }
                    for(char *output_option = argv[i] + 1; *output_option != 0; output_option++)
                    {
                        switch(*output_option)
                        {
                            case 'u':
                                context.format.sections[DNS_SECTION_AUTHORITY] = true;
                                break;
                            case 'd':
                                context.format.sections[DNS_SECTION_ADDITIONAL] = true;
                                break;
                            case 'n':
                                context.format.sections[DNS_SECTION_ANSWER] = true;
                                break;
                            case 'm':
                                context.format.match_name = true;
                                break;
                            case 't':
                                context.format.ttl = true;
                                break;
                            case 'l':
                                context.format.separate_queries = true;
                                break;
                            case 'i':
                                context.format.indent_sections = true;
                                break;
                            case 's':
                                context.format.separate_sections = true;
                                break;
                            case 'q':
                                context.format.print_question = true;
                                break;
                            case 'r':
                                context.format.include_meta = true;
                                break;
                            default:
                                log_msg("Unrecognized output option: %c\n", *output_option);
                                clean_exit(EXIT_FAILURE);
                        }
                    }
                    break;

                case 'F':
                    context.cmd_args.output = OUTPUT_TEXT_FULL;
                    break;

                default:
                    log_msg("Unrecognized output format.\n");
                    clean_exit(EXIT_FAILURE);
            }
        }
#ifdef PCAP_SUPPORT
        else if (strcmp(argv[i], "--use-pcap") == 0)
        {
            context.cmd_args.use_pcap = true;
        }
#endif
        else if (strcmp(argv[i], "--predictable") == 0)
        {
            context.cmd_args.predictable_resolver = true;
        }
        else if (strcmp(argv[i], "--sticky") == 0)
        {
            context.cmd_args.sticky = true;
        }
        else if (strcmp(argv[i], "--quiet") == 0 || strcmp(argv[i], "-q") == 0)
        {
            context.cmd_args.quiet = true;
        }
        else if (strcmp(argv[i], "--extreme") == 0)
        {
            context.cmd_args.extreme = (int) expect_arg_nonneg(i++, 0, 2);
        }
        else if (strcmp(argv[i], "--resolve-count") == 0 || strcmp(argv[i], "-c") == 0)
        {
            context.cmd_args.resolve_count = (uint8_t) expect_arg_nonneg(i++, 1, UINT8_MAX);
        }
        else if (strcmp(argv[i], "--hashmap-size") == 0 || strcmp(argv[i], "-s") == 0)
        {
            context.cmd_args.hashmap_size = (size_t) expect_arg_nonneg(i++, 1, SIZE_MAX);
        }
        else if (strcmp(argv[i], "--processes") == 0)
        {
            context.cmd_args.num_processes = (size_t) expect_arg_nonneg(i++, 0, SIZE_MAX);
            if(context.cmd_args.num_processes == 0)
            {
#ifndef HAVE_SYSINFO
                    log_msg("No support for detecting the number of cores automatically.\n");
                    clean_exit(EXIT_FAILURE);
#else
                int cores = get_nprocs_conf();
                if(cores <= 0)
                {
                    log_msg("Failed to determine number of processor cores.\n");
                    clean_exit(EXIT_FAILURE);
                }
                context.cmd_args.num_processes = (size_t)cores;
#endif
            }
        }
        else if (strcmp(argv[i], "--socket-count") == 0)
        {
            context.cmd_args.socket_count = (size_t) expect_arg_nonneg(i++, 1, SIZE_MAX);
        }
        else if (strcmp(argv[i], "--interval") == 0 || strcmp(argv[i], "-i") == 0)
        {
            context.cmd_args.interval_ms = (unsigned int) expect_arg_nonneg(i++, 1, UINT_MAX);
        }
        else if (strcmp(argv[i], "--sndbuf") == 0)
        {
            context.cmd_args.sndbuf = (int) expect_arg_nonneg(i++, 0, INT_MAX);
        }
        else if (strcmp(argv[i], "--rcvbuf") == 0)
        {
            context.cmd_args.rcvbuf = (int) expect_arg_nonneg(i++, 0, INT_MAX);
        }
        else if (strcmp(argv[i], "--flush") == 0)
        {
            context.cmd_args.flush = true;
        }
        else if (strcmp(argv[i], "--verify-ip") == 0)
        {
            context.cmd_args.verify_ip = true;
        }
        else
        {
            if (context.cmd_args.domains == NULL)
            {
                context.cmd_args.domains = argv[i];
                domain_param = true;
                if (strcmp(argv[i], "-") == 0)
                {
                    use_stdin();
                }
                else
                {
                    // If we can seek through the domain file, we seek to the end and store the file size
                    // in order to be able to report an estimate progress of resolving.
                    context.domainfile = fopen(context.cmd_args.domains, "r");
                    if (context.domainfile == NULL)
                    {
                        log_msg("Failed to open domain file \"%s\".\n", argv[i]);
                        clean_exit(EXIT_FAILURE);
                    }
                    if(fseek(context.domainfile, 0, SEEK_END) != 0)
                    {
                        // Not a seekable stream.
                        context.domainfile_size = -1;
                    }
                    else
                    {
                        context.domainfile_size = ftell(context.domainfile);
                        if(fseek(context.domainfile, 0, SEEK_SET) != 0)
                        {
                            // Should never happen because seeking was possible before but we can still recover.
                            context.domainfile_size = -1;
                        }
                    }
                    fclose(context.domainfile);
                    context.domainfile = NULL;
                }
            }
            else
            {
                log_msg("The domain list may only be supplied once.\n");
                clean_exit(EXIT_FAILURE);
            }
        }
    }
    if (context.cmd_args.record_type == DNS_REC_INVALID)
    {
        context.cmd_args.record_type = DNS_REC_A;
    }
    if (context.cmd_args.record_type == DNS_REC_ANY)
    {
        // Some operators will not reply to ANY requests:
        // https://blog.cloudflare.com/deprecating-dns-any-meta-query-type/
        // https://lists.dns-oarc.net/pipermail/dns-operations/2013-January/009501.html
        log_msg("Note that DNS ANY scans might be unreliable.\n");
    }
    if (context.cmd_args.resolvers == NULL)
    {
        log_msg("Resolvers are required to be supplied.\n");
        clean_exit(EXIT_FAILURE);
    }
    if (!domain_param)
    {
        if(!isatty(STDIN_FILENO))
        {
            use_stdin();
        }
        else
        {
            log_msg("The domain list is required to be supplied.\n");
            clean_exit(EXIT_FAILURE);
        }
    }

    if(context.domainfile == stdin && context.cmd_args.num_processes > 1)
    {
        log_msg("In order to use multiprocessing, the domain list needs to be supplied as file.\n");
        clean_exit(EXIT_FAILURE);
    }

    return 0;
}

int main(int argc, char **argv)
{
#ifdef DEBUG
    // Create core dump on crash in debug mode
    struct rlimit core_limits;
    core_limits.rlim_cur = core_limits.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_CORE, &core_limits);
#endif

    int rcode = parse_cmd(argc, argv);
    if(rcode != 0)
    {
        return rcode;
    }

    run();
    cleanup();

    return 0;
}
