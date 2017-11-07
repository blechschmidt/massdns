#define _GNU_SOURCE


#include "massdns.h"
#include "string.h"
#include "random.h"
#include "net.h"
#include "cmd.h"
#include "dns.h"
#include <unistd.h>
#include <pwd.h>
#include <sys/ioctl.h>
#include <stddef.h>
#include <limits.h>

#define DEBUG

#ifdef DEBUG
#include <sys/resource.h>
#endif

void print_help()
{
    fprintf(stderr, ""
                    "Usage: %s [options] [domainlist]\n"
                    "  -b  --bindto           Bind to IP address and port. (Default: 0.0.0.0:0)\n"
                    "  -c  --resolve-count    Number of resolves for a name before giving up. (Default: 50)\n"
                    "      --drop-user        User to drop privileges to when running as root. (Default: nobody)\n"
                    "  -h  --help             Show this help.\n"
                    "  -i  --interval         Interval in milliseconds to wait between multiple resolves of the same\n"
                    "                         domain. (Default: 200)\n"
                    "  -l  --error-log        Error log file path. (Default: /dev/stderr)\n"
                    "  -n  --norecurse        Use non-recursive queries. Useful for DNS cache snooping.\n"
                    "  -o  --output           Flags for output formatting.\n"
                    "      --finalstats       Write final stats to STDERR when done.\n"
                    "  -q  --quiet            Quiet mode.\n"
                    "      --rcvbuf           Size of the receive buffer in bytes.\n"
                    "      --retry            Unacceptable DNS response codes. (Default: REFUSED)\n"
                    "  -r  --resolvers        Text file containing DNS resolvers.\n"
                    "      --root             Do not drop privileges when running as root. Not recommended.\n"
                    "  -s  --hashmap-size     Number of concurrent lookups. (Default: 100000)\n"
                    "      --sndbuf           Size of the send buffer in bytes.\n"
                    "      --sticky-resolver  Do not switch the resolver when retrying.\n"
                    "  -t  --type             Record type to be resolved. (Default: A)\n"
                    "  -w  --outfile          Write to the specified output file instead of standard output.\n"
                    "  -x  --extreme          Value between 0 and 2 specifying transmission aggression. (Default: 0)\n"
                    "\n"
                    "Output flags:\n"
                    "  S - simple text output\n"
                    "  F - full text output\n"
                    "  B - binary output\n",
            context.cmd_args.argv[0] ? context.cmd_args.argv[0] : "massdns"
    );
}

buffer_t massdns_resolvers_from_file(char *filename)
{
    char line[4096];
    FILE *f = fopen(filename, "r");
    if (f == NULL)
    {
        perror("Failed to open resolver file");
        exit(1);
    }
    single_list_t *list = single_list_new();
    while (!feof(f))
    {
        if (fgets(line, sizeof(line), f))
        {
            trim_end(line);
            struct sockaddr_storage *addr = safe_malloc(sizeof(addr));
            if (str_to_addr(line, 53, addr))
            {
                if(addr->ss_family == AF_INET && context.sockets.interfaces4.len > 0
                    || addr->ss_family == AF_INET6 && context.sockets.interfaces6.len > 0)
                {
                    single_list_push_back(list, addr);
                }
                else
                {
                    free(addr);
                    fprintf(stderr, "No query socket for resolver \"%s\" found.\n", line);
                }
            }
            else
            {
                free(addr);
                fprintf(stderr, "\"%s\" is not a valid resolver. Skipped.\n", line);
            }
        }
    }
    fclose(f);
    buffer_t resolvers = single_list_to_array(list);
    if(single_list_count(list) == 0)
    {
        fprintf(stderr, "No usable resolvers were found. Terminating.\n");
        exit(1);
    }
    single_list_free(list);
    return resolvers;
}

void cleanup()
{
    hashmapFree(context.map);
    timed_ring_destroy(&context.ring);

    for(size_t i = 0; i < context.resolvers.len; i++)
    {
        free(((struct sockaddr_storage**)context.resolvers.data)[i]);
    }
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
}

void set_sndbuf(int fd)
{
    if(context.cmd_args.sndbuf
        && setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &context.cmd_args.sndbuf, sizeof(context.cmd_args.sndbuf)) == 0)
    {
        fprintf(stderr, "Failed to adjust send buffer size: %s\n", strerror(errno));
    }
}

void set_rcvbuf(int fd)
{
    if(context.cmd_args.rcvbuf
        && setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &context.cmd_args.rcvbuf, sizeof(context.cmd_args.rcvbuf)) == 0)
    {
        fprintf(stderr, "Failed to adjust receive buffer size: %s\n", strerror(errno));
    }
}

void set_default_socket(int version)
{
    socket_info_t info;

    info.descriptor = socket(version == 4 ? PF_INET : PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    info.protocol = version == 4 ? PROTO_IPV4 : PROTO_IPV6;
    info.type = SOCKET_TYPE_QUERY;
    if(info.descriptor >= 0)
    {
        buffer_t *buffer = version == 4 ? &context.sockets.interfaces4 : &context.sockets.interfaces6;
        buffer->len = 1;
        buffer->data = flatcopy(&info, sizeof(info));
        set_rcvbuf(info.descriptor);
        set_sndbuf(info.descriptor);
    }
    else
    {
        fprintf(stderr, "Failed to create IPv%d socket: %s\n", version, strerror(errno));
    }
}

void set_user_sockets(single_list_t *bind_addrs, buffer_t *buffer)
{
    single_list_t sockets;
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
                fprintf(stderr, "Not adding socket due to bind failure: %s", strerror(errno));
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
            fprintf(stderr, "Failed to create IPv%d socket: %s\n", info.protocol, strerror(errno));
        }
        free(element->data);
    }
    single_list_init(bind_addrs);

    *buffer = single_list_to_array(&sockets);
    single_list_clear(&sockets);
}

void query_sockets_setup()
{
    if(single_list_count(&context.cmd_args.bind_addrs4) == 0 && single_list_count(&context.cmd_args.bind_addrs6) == 0)
    {
        set_default_socket(4);
        set_default_socket(6);
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

    while (fgets(line, sizeof(line), context.domainfile))
    {
        trim_end(line);
        if (strcmp(line, "") == 0)
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
    char *entry = ((lookup_key_t *)key)->domain;
    int c;
    while ((c = *entry++) != 0)
    {
        hash = ((hash << 5) + hash) + tolower(c); /* hash * 33 + c */
    }
    hash = ((hash << 5) + hash) + ((((lookup_key_t *)key)->type & 0xFF00) >> 8);
    hash = ((hash << 5) + hash) + (((lookup_key_t *)key)->type & 0x00FF);
    return (int)hash;
}


// Converts a DNS name to the heap and makes sure it is a FQDN (appends a trailing dot)
// The result needs to be freed
char *canonicalized_name_copy(const char *qname)
{
    size_t len = strlen(qname);
    bool canonical = len > 0 && qname[len - 1] == '.';
    if(canonical)
    {
        return strmcpy(qname);
    }
    else
    {
        char *result = safe_malloc(len + 2);
        memcpy(result, qname, len);
        result[len] = '.';
        result[len + 1] = 0;
        return result;
    }
}

void end_warmup()
{
    context.state = STATE_QUERYING;
    if(context.cmd_args.extreme <= 1)
    {
        // Reduce our CPU load from epoll interrupts by removing the EPOLLOUT event
        add_sockets(context.epollfd, EPOLLIN, EPOLL_CTL_MOD, &context.sockets.interfaces4);
        add_sockets(context.epollfd, EPOLLIN, EPOLL_CTL_MOD, &context.sockets.interfaces6);
    }
}

lookup_t *new_lookup(const char *qname, dns_record_type type)
{
    lookup_key_t *key = safe_malloc(sizeof(*key));

    key->domain = canonicalized_name_copy(qname);
    key->type = type;

    lookup_t *value = safe_calloc(sizeof(*value));
    value->ring_entry = timed_ring_add(&context.ring, context.cmd_args.interval_ms * TIMED_RING_MS, value);
    urandom_get(&value->transaction, sizeof(value->transaction));
    value->key = key;

    errno = 0;
    hashmapPut(context.map, key, value);
    if(errno != 0)
    {
        perror("Error");
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
        lookup->resolver = ((resolver_t **) context.resolvers.data)[urandom_size_t() % context.resolvers.len];
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

    // Pick a random socket from that pool
    // Pool of sockets cannot be empty due to check when parsing resolvers. Socket creation must have succeeded.
    size_t socket_index = urandom_size_t() % interfaces->len;
    int socket_descriptor = ((socket_info_t*)interfaces->data)[socket_index].descriptor;

    ssize_t result = dns_question_create(query_buffer, lookup->key->domain, lookup->key->type, lookup->transaction);
    if (result < DNS_PACKET_MINIMUM_SIZE)
    {
        fprintf(stderr, "Failed to create DNS question for query \"%s\".", lookup->key->domain);
        return;
    }

    // Set or unset the QD bit based on user preference
    dns_buf_set_rd(query_buffer, !context.cmd_args.norecurse);

    ssize_t sent = sendto(socket_descriptor, query_buffer, (size_t) result, 0,
                          (struct sockaddr *) &lookup->resolver->address,
                          sizeof(lookup->resolver->address));
    if(sent != result)
    {
        fprintf(stderr, "Error sending: %s\n", strerror(errno));
    }
}

void check_progress()
{
    static struct timespec last_time;
    static char timeouts[4096];
    static char timeouts_clear[4096 * 7 + 1]; // 7: length of the ANSI code for moving cursor up and clearing a line
    static struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);

    time_t elapsed_ns = (now.tv_sec - last_time.tv_sec) * 1000000000 + (now.tv_nsec - last_time.tv_nsec);
    size_t rate_pps = elapsed_ns == 0 ? 0 : context.stats.current_rate * TIMED_RING_S / elapsed_ns;
    last_time = now;
    context.stats.current_rate = 0;

    // TODO: Hashmap size adaption logic will be handled here.

    if(context.cmd_args.quiet)
    {
        return;
    }

    // Go on with printing stats.

    time_t total_elapsed_ns = (now.tv_sec - context.stats.start_time.tv_sec) * 1000000000
        + (now.tv_nsec - context.stats.start_time.tv_nsec); // since last output
    long long elapsed = now.tv_sec - context.stats.start_time.tv_sec; // resolution of one second should be okay
    long long sec = elapsed % 60;
    long long min = (elapsed / 60) % 60;
    long long h = elapsed / 3600;
    size_t average_pps = elapsed == 0 ? rate_pps : context.stats.numreplies * TIMED_RING_S / total_elapsed_ns;

    float progress = context.state == STATE_DONE ? 100 : 0;
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

    long long estimated_time = progress == 0 ? 0 : (long long)(elapsed / progress);
    if(estimated_time < elapsed)
    {
        estimated_time = elapsed;
    }
    long long prog_sec = estimated_time % 60;
    long long prog_min = (estimated_time / 60) % 60;
    long long prog_h = (estimated_time / 3600);


    // Print the detailed timeout stats (number of tries before timeout) to the timeouts buffer.
    int offset = 0;
    for(size_t i = 0; i <= context.cmd_args.resolve_count; i++)
    {
        float share = context.stats.numdomains == 0 ?
                      0 : context.stats.timeouts[i] * 100 / (float)context.stats.numdomains;
        int result = snprintf(timeouts + offset, sizeof(timeouts) - offset, "%zu: %.2f%%, ", i, share);
        if(result <= 0 || result >= sizeof(timeouts) - offset)
        {
            break;
        }
        offset += result;
    }

    fprintf(stderr,
            "\033[H\033[2J" // Clear screen (probably simplest and most portable solution)
                "Processed queries: %zu\n"
                "Received packets: %zu\n"
                "Progress: %6.2f%% (%02lld h %02lld min %02lld sec / %02lld h %02lld min %02lld sec)\n"
                "Current rate: %zu pps, average: %zu pps\n"
                "Finished total: %zu, success: %zu (%6.2f%%)\n"
                "OK: %zu (%6.2f%%), "
                "NXDOMAIN: %zu (%6.2f%%), "
                "SERVFAIL: %zu (%6.2f%%), "
                "REFUSED: %zu (%6.2f%%), "
                "FORMERR: %zu (%6.2f%%)\n"
                "Mismatched domains: %zu (%6.2f%%), IDs: %zu (%6.2f%%)\n"
                "Failures: %s\n",
            context.stats.numdomains,
            context.stats.numreplies,
            progress * 100, h, min, sec, prog_h, prog_min, prog_sec, rate_pps, average_pps,
            context.stats.finished, context.stats.finished_success,
            context.stats.finished_success / (float)context.stats.finished * 100,
            context.stats.final_rcodes[DNS_RCODE_OK],
            context.stats.final_rcodes[DNS_RCODE_OK] / (float)context.stats.finished_success * 100,
            context.stats.final_rcodes[DNS_RCODE_NXDOMAIN],
            context.stats.final_rcodes[DNS_RCODE_NXDOMAIN] / (float)context.stats.finished_success * 100,
            context.stats.final_rcodes[DNS_RCODE_SERVFAIL],
            context.stats.final_rcodes[DNS_RCODE_SERVFAIL] / (float)context.stats.finished_success * 100,
            context.stats.final_rcodes[DNS_RCODE_REFUSED],
            context.stats.final_rcodes[DNS_RCODE_REFUSED] / (float)context.stats.finished_success * 100,
            context.stats.final_rcodes[DNS_RCODE_FORMERR],
            context.stats.final_rcodes[DNS_RCODE_FORMERR] / (float)context.stats.finished_success * 100,
            context.stats.mismatch_domain, context.stats.mismatch_domain / (float)context.stats.numreplies * 100,
            context.stats.mismatch_id, context.stats.mismatch_id / (float)context.stats.numreplies * 100,
            timeouts);

    // Call this function in about one second again
    timed_ring_add(&context.ring, TIMED_RING_S, check_progress);
}

void done()
{
    context.state = STATE_DONE;
    check_progress();
}

void can_send()
{
    char *qname;

    while (hashmapSize(context.map) < context.cmd_args.hashmap_size && context.state <= STATE_QUERYING)
    {
        if(!next_query(&qname))
        {
            context.state = STATE_COOLDOWN; // We will not create any new queries
            if(hashmapSize(context.map) <= 0)
            {
                done();
            }
            break;
        }
        context.stats.numdomains++;
        lookup_t *lookup = new_lookup(qname, context.cmd_args.record_type);
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
    free(lookup->key->domain);
    free(lookup->key);
    free(lookup);


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

char *sockaddr2str(struct sockaddr_storage *addr)
{
    static char str[INET6_ADDRSTRLEN + sizeof(":65535") - 1 + 2]; // + 2 for [ and ]
    static uint16_t port;
    size_t len;

    if(addr->ss_family == AF_INET)
    {
        port = ntohs(((struct sockaddr_in*)addr)->sin_port);
        inet_ntop(addr->ss_family, &((struct sockaddr_in*)addr)->sin_addr, str, sizeof(str));
        len = strlen(str);
        // inet_ntop does not allow us to determine, how long the printed string was.
        // Thus, we have to use strlen.
    }
    else
    {
        str[0] = '[';
        port = ntohs(((struct sockaddr_in6*)addr)->sin6_port);
        inet_ntop(addr->ss_family, &((struct sockaddr_in6*)addr)->sin6_addr, str + 1, sizeof(str) - 1);
        len = strlen(str);
        str[len++] = ']';
        str[len] = 0;
    }

    snprintf(str + len, sizeof(str) - len, ":%" PRIu16, port);

    return str;
}

void can_read(socket_info_t *info)
{
    static uint8_t readbuf[0xFFFF];
    static struct sockaddr_storage recvaddr;
    static socklen_t fromlen;
    static ssize_t num_received;
    static dns_pkt_t packet;
    static uint8_t *parse_offset;
    static lookup_key_t search_key;
    static lookup_t *lookup;


    fromlen = sizeof(recvaddr);
    num_received = recvfrom(info->descriptor, readbuf, sizeof(readbuf), 0, (struct sockaddr *) &recvaddr, &fromlen);
    if(num_received <= 0)
    {
        return;
    }

    context.stats.current_rate++;
    context.stats.numreplies++;

    if(!dns_parse_question(readbuf, (size_t)num_received, &packet.head, &parse_offset))
    {
        return;
    }

    search_key.type = packet.head.question.type;
    search_key.domain = (char*)packet.head.question.name.name;
    lookup = hashmapGet(context.map, &search_key);
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
        lookup_done(lookup);
        context.stats.finished_success++;
        context.stats.final_rcodes[packet.head.header.rcode]++;

        // Print packet
        time_t now = time(NULL);
        uint16_t short_len = (uint16_t) num_received;
        uint8_t *next = parse_offset;
        dns_record_t rec;
        size_t rec_index = 0;

        switch(context.cmd_args.output)
        {
            case OUTPUT_BINARY:
                // The output file is platform dependent for performance reasons.
                fwrite(&now, sizeof(now), 1, context.outfile);
                fwrite(&recvaddr, sizeof(recvaddr), 1, context.outfile);
                fwrite(&short_len, sizeof(short_len), 1, context.outfile);
                fwrite(readbuf, short_len, 1, context.outfile);
                break;

            case OUTPUT_TEXT_FULL: // Print packet similar to dig style
                // Resolver and timestamp are not part of the packet, we therefore have to print it manually
                fprintf(context.outfile, ";; Server: %s\n;; Size: %" PRIu16 "\n;; Unix time: %lu\n",
                        sockaddr2str(&recvaddr), short_len, now);
                dns_print_packet(context.outfile, &packet, readbuf, (size_t)num_received, next);
                break;

            case OUTPUT_TEXT_SIMPLE: // Only print records from answer section that match the query name
                while(dns_parse_record_raw(readbuf, next, readbuf + num_received, &next, &rec)
                    && rec_index++ < packet.head.header.ans_count)
                {
                    if(!dns_names_eq(&rec.name, &packet.head.question.name))
                    {
                        continue;
                    }
                    fprintf(context.outfile,
                            "%s %s %s\n",
                            dns_name2str(&rec.name),
                            dns_record_type2str((dns_record_type) rec.type),
                            dns_raw_record_data2str(&rec, readbuf, readbuf + short_len));
                }
                break;
        }
    }
}

bool cmp_lookup(void *lookup1, void *lookup2)
{
    return strcasecmp(((lookup_key_t *) lookup1)->domain,((lookup_key_t *) lookup2)->domain) == 0;
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


    // Write byte length of sockaddr_storage size
    size_t sockaddr_storage_len = sizeof(struct sockaddr_storage);
    fwrite(&sockaddr_storage_len, sizeof(sockaddr_storage_len), 1, context.outfile);

    // Write offset of ss_family within sockaddr_storage
    size_t ss_family_offset = offsetof(struct sockaddr_storage, ss_family);
    fwrite(&ss_family_offset, sizeof(ss_family_offset), 1, context.outfile);

    // Write size of sa_family_size within sockaddr_storage
    size_t sa_family_size = sizeof(sa_family_t);
    fwrite(&sa_family_size, sizeof(sa_family_size), 1, context.outfile);


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
    if(!context.cmd_args.root)
    {
        struct passwd *drop_user = getpwnam(username);
        if (drop_user && setuid(drop_user->pw_uid) == 0)
        {
            if (!context.cmd_args.quiet)
            {
                fprintf(stderr, "Privileges have been dropped to \"%s\" for security reasons.\n\n", username);
            }
        }
        else
        {
            fprintf(stderr, "Privileges could not be dropped to \"%s\".\n"
                "For security reasons, this program will only run as root user when supplied with --root"
                "which is not recommended.\n"
                "It is better practice to run this program as a different user.\n", username);
            exit(1);
        }
    }
    else
    {
        if (!context.cmd_args.quiet)
        {
            fprintf(stderr, "[WARNING] Privileges were not dropped. This is not recommended.\n\n");
        }
    }
}

void run()
{
    if(!urandom_init())
    {
        fprintf(stderr, "Failed to open /dev/urandom: %s\n", strerror(errno));
        exit(1);
    }

    // It is important to call default interface sockets setup before reading the resolver list
    // because that way we can warn if the socket creation for a certain IP protocol failed although a resolver
    // requires the protocol.
    query_sockets_setup();
    context.resolvers = massdns_resolvers_from_file(context.cmd_args.resolvers);

    privilege_drop();

    context.map = hashmapCreate(context.cmd_args.hashmap_size, hash_lookup_key, cmp_lookup);
    context.epollfd = epoll_create(1);
    timed_ring_init(&context.ring, max(context.cmd_args.interval_ms, 1000), 2 * TIMED_RING_MS, context.cmd_args.timed_ring_buckets);

    if(context.cmd_args.output == OUTPUT_BINARY)
    {
        binfile_write_head();
    }

    add_sockets(context.epollfd, EPOLLIN | EPOLLOUT, EPOLL_CTL_ADD, &context.sockets.interfaces4);
    add_sockets(context.epollfd, EPOLLIN | EPOLLOUT, EPOLL_CTL_ADD, &context.sockets.interfaces6);

    struct epoll_event pevents[100000];
    bzero(pevents, sizeof(pevents));

    clock_gettime(CLOCK_MONOTONIC, &context.stats.start_time);
    check_progress();

    while(context.state < STATE_DONE)
    {
        int ready = epoll_wait(context.epollfd, pevents, sizeof(pevents) / sizeof(pevents[0]), 1);
        if (ready < 0)
        {
            perror("Epoll failure");
        }
        else if(ready == 0) // Epoll timeout
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
            }
            timed_ring_handle(&context.ring, ring_timeout);
        }
    }
}

void use_stdin()
{
    if (!context.cmd_args.quiet)
    {
        fprintf(stderr, "Reading domain list from stdin.\n");
    }
    context.domainfile = stdin;
}

int parse_cmd(int argc, char **argv)
{
    context.cmd_args.argc = argc;
    context.cmd_args.argv = argv;
    context.cmd_args.help_function = print_help;

    if (argc <= 1)
    {
        print_help();
        return 1;
    }


    context.cmd_args.record_type = DNS_REC_INVALID;
    context.domainfile_size = -1;
    context.state = STATE_WARMUP;
    context.logfile = stderr;
    context.outfile = stdout;

    context.cmd_args.resolve_count = 50;
    context.cmd_args.hashmap_size = 100000;
    context.cmd_args.interval_ms = 1000;
    context.cmd_args.timed_ring_buckets = 10000;
    context.cmd_args.output = OUTPUT_TEXT_FULL;
    context.cmd_args.retry_codes[DNS_RCODE_REFUSED] = true;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
        {
            print_help();
            return 1;
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
                fprintf(stderr, "Resolvers may only be supplied once.\n\n");
                print_help();
                return 1;
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
                fprintf(stderr, "Invalid retry code: %s.\n", argv[i]);
            }
        }
        else if (strcmp(argv[i], "--bindto") == 0 || strcmp(argv[i], "-b") == 0)
        {
            expect_arg(i);
            struct sockaddr_storage *addr = safe_malloc(sizeof(addr));
            if (!str_to_addr(argv[++i], 0, addr))
            {
                free(addr);
                fprintf(stderr, "Invalid address for socket binding.\n\n");
                print_help();
                return 1;

            }
            single_list_push_back(addr->ss_family == AF_INET ? &context.cmd_args.bind_addrs4 :
                                  &context.cmd_args.bind_addrs6, addr);
        }
        else if (strcmp(argv[i], "--outfile") == 0 || strcmp(argv[i], "-w") == 0)
        {
            expect_arg(i);
            char *filename = argv[++i];
            if(strcmp(filename, "-") != 0)
            {
                context.outfile = fopen(filename, "w");
                if(!context.outfile)
                {
                    perror("Failed to open output file");
                    return 1;
                }
            }
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
                    perror("Failed to open log file");
                    return 1;
                }
            }
        }
        else if (strcmp(argv[i], "--types") == 0 || strcmp(argv[i], "-t") == 0)
        {
            expect_arg(i);
            if (context.cmd_args.record_type != DNS_REC_INVALID)
            {
                fprintf(stderr, "Currently, only one record type is supported.\n\n");
                return 1;
            }
            dns_record_type rtype = dns_str_to_record_type(argv[++i]);
            if (rtype == DNS_REC_INVALID)
            {
                fprintf(stderr, "Unsupported record type: %s\n\n", argv[i]);
                print_help();
                return 1;
            }
            context.cmd_args.record_type = rtype;
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
        else if (strcmp(argv[i], "--output") == 0)
        {
            expect_arg(i++);
            if(strchr(argv[i], 'B'))
            {
                context.cmd_args.output = OUTPUT_BINARY;
            }
            else if(strchr(argv[i], 'S'))
            {
                context.cmd_args.output = OUTPUT_TEXT_SIMPLE;
            }
            else if(strchr(argv[i], 'F'))
            {
                context.cmd_args.output = OUTPUT_TEXT_FULL;
            }
        }
        else if (strcmp(argv[i], "--sticky-resolver") == 0)
        {
            context.cmd_args.sticky = true;
        }
        else if (strcmp(argv[i], "--finalstats") == 0)
        {
            context.cmd_args.finalstats = true;
        }
        else if (strcmp(argv[i], "--quiet") == 0 || strcmp(argv[i], "-q") == 0)
        {
            context.cmd_args.quiet = true;
        }
        else if (strcmp(argv[i], "--extreme") == 0 || strcmp(argv[i], "-x") == 0)
        {
            context.cmd_args.extreme = (int)expect_arg_nonneg(i++, 0, 2);
        }
        else if (strcmp(argv[i], "--resolve-count") == 0 || strcmp(argv[i], "-c") == 0)
        {
            context.cmd_args.resolve_count = (uint8_t)expect_arg_nonneg(i++, 1, UINT8_MAX);
        }
        else if (strcmp(argv[i], "--hashmap-size") == 0 || strcmp(argv[i], "-s") == 0)
        {
            context.cmd_args.hashmap_size = (size_t) expect_arg_nonneg(i++, 1, SIZE_MAX);
        }
        else if (strcmp(argv[i], "--interval") == 0 || strcmp(argv[i], "-i") == 0)
        {
            context.cmd_args.interval_ms = (unsigned int) expect_arg_nonneg(i++, 1, UINT_MAX);
        }
        else if (strcmp(argv[i], "--sndbuf") == 0)
        {
            context.cmd_args.sndbuf = (int)expect_arg_nonneg(i++, 0, INT_MAX);
        }
        else if (strcmp(argv[i], "--rcvbuf") == 0)
        {
            context.cmd_args.rcvbuf = (int)expect_arg_nonneg(i++, 0, INT_MAX);
        }
        else
        {
            if (context.cmd_args.domains == NULL)
            {
                context.cmd_args.domains = argv[i];
                if (strcmp(argv[i], "-") == 0)
                {
                    use_stdin();
                }
                else
                {
                    // If we can seek through the domain file, we seek to the end and store the file size
                    // in order to be able to report an estimate progress of resolving.
                    context.domainfile = fopen(argv[i], "r");
                    if (context.domainfile == NULL)
                    {
                        fprintf(stderr, "Failed to open domain file.\n");
                        exit(1);
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
                }
            }
            else
            {
                fprintf(stderr, "The domain list may only be supplied once.\n\n");
                print_help();
                return 1;
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
        fprintf(stderr, "Note that DNS ANY scans might be unreliable.\n");
    }
    if (context.cmd_args.resolvers == NULL)
    {
        fprintf(stderr, "Resolvers are required to be supplied.\n\n");
        print_help();
        return 1;
    }
    if (context.domainfile == NULL)
    {
        if(!isatty(STDIN_FILENO))
        {
            use_stdin();
        }
        else
        {
            fprintf(stderr, "The domain list is required to be supplied.\n\n");
            print_help();
            return 1;
        }
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
