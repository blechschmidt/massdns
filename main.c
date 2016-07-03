/*
	B. Blechschmidt
	https://cysec.biz/
*/
#define _GNU_SOURCE


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/time.h>
#include <unistd.h>
#include <pwd.h>
#include <ldns/packet.h>
#include <ldns/host2wire.h>
#include <ldns/wire2host.h>
#include <ldns/dnssec.h>

#include "security.h"
#include "string.h"
#include "list.h"
#include "hashmap.h"

#ifdef DEBUG
#include <sys/resource.h>
#endif

#define UNPRIVILEGED_USER "nobody"

typedef struct sockaddr_in sockaddr_in_t;
typedef struct sockaddr sockaddr_t;

void print_help(char *file)
{
    fprintf(stderr, ""
                    "Usage: %s [options] domainlist\n"
                    "  -a  --no-authority     Omit records from the authority section of the response packets.\n"
                    "  -c  --resolve-count    Number of resolves for a name before giving up. (Default: 50)\n"
                    "  -e  --additional       Include response records within the additional section.\n"
                    "  -h  --help             Show this help.\n"
                    "  -i  --interval         Interval in milliseconds to wait between multiple resolves of the same"
                    " domain. (Default: 200)\n"
                    "  -n  --norecurse        Use non-recursive queries. Useful for DNS cache snooping.\n"
                    "  -o  --only-responses   Do not output DNS questions.\n"
                    "  -p  --progress         Show the progress and remaining time.\n"
                    "  -r  --resolvers        Text file containing DNS resolvers.\n"
                    "      --root             Allow running the program as root. Not recommended.\n"
                    "  -s  --hashmap-size     Set the size of the hashmap used for resolving. (Default: 100000)\n"
                    "  -t  --type             Record type to be resolved. (Default: A)\n"
                    "\n"
                    "Supported record types:\n"
                    "  A\n"
                    "  AAAA\n"
                    "  ANY\n"
                    "  CNAME\n"
                    "  DNAME\n"
                    "  MX\n"
                    "  NS\n"
                    "  PTR\n"
                    "  TXT\n",
            file
    );
}

int record_from_str(char *str)
{
    strtolower(str);
    if (strcmp(str, "a") == 0)
    {
        return LDNS_RR_TYPE_A;
    }
    if (strcmp(str, "aaaa") == 0)
    {
        return LDNS_RR_TYPE_AAAA;
    }
    if (strcmp(str, "cname") == 0)
    {
        return LDNS_RR_TYPE_CNAME;
    }
    if (strcmp(str, "mx") == 0)
    {
        return LDNS_RR_TYPE_MX;
    }
    if (strcmp(str, "ns") == 0)
    {
        return LDNS_RR_TYPE_NS;
    }
    if (strcmp(str, "ptr") == 0)
    {
        return LDNS_RR_TYPE_PTR;
    }
    if (strcmp(str, "txt") == 0)
    {
        return LDNS_RR_TYPE_TXT;
    }
    if (strcmp(str, "soa") == 0)
    {
        return LDNS_RR_TYPE_SOA;
    }
    if (strcmp(str, "any") == 0)
    {
        return LDNS_RR_TYPE_ANY;
    }
    return 0;
}

typedef struct dns_stats_t
{
    size_t noerr;
    size_t formerr;
    size_t servfail;
    size_t nxdomain;
    size_t notimp;
    size_t refused;
    size_t other;
} dns_stats_t;

dns_stats_t stats;

typedef struct lookup
{
    char *domain;
    unsigned char tries;
    uint16_t transaction;
    struct timeval next_lookup;
} lookup_t;

typedef struct lookup_context
{
    int sock;
    buffer_t resolvers;
    Hashmap *map;
    struct timeval next_update;
    size_t current_rate;
    bool initial;
    struct timeval start_time;
    size_t total_domains;
    struct timeval cooldown_time;
    bool cooldown;
    struct cmd_args
    {
        bool root;
        char *resolvers;
        char *domains;
        enum ldns_enum_rr_type record_types;
        unsigned char resolve_count;
        size_t hashmap_size;
        unsigned int interval_ms;
        bool no_authority;
        bool only_responses;
        bool additional;
        bool norecurse;
        bool show_progress;
    } cmd_args;
} lookup_context_t;

// http://www.cse.yorku.ca/~oz/hash.html
unsigned long djb2(unsigned char *str)
{
    unsigned long hash = 5381;
    int c;
    while ((c = *str++) != 0)
    {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    return hash;
}

long timediff(struct timeval *starttime, struct timeval *endtime)
{
    return (endtime->tv_sec - starttime->tv_sec) * 1000 + (endtime->tv_usec - starttime->tv_usec) / 1000;
}

int hash_string(void *str)
{
    return (int) djb2((unsigned char *) str);
}

ldns_status output_packet(ldns_buffer *output, const ldns_pkt *pkt, struct sockaddr_storage sa, lookup_context_t* context)
{
    const ldns_output_format *fmt = ldns_output_format_nocomments;
    uint16_t i;
    ldns_status status = LDNS_STATUS_OK;

    time_t now = time(NULL);
    char nsbuffer[INET6_ADDRSTRLEN];
    char* ip_prefix = "";
    char* ip_suffix = "";
    switch (((struct sockaddr *) &sa)->sa_family)
    {
        case AF_INET:
            inet_ntop(AF_INET, &(((struct sockaddr_in *) &sa)->sin_addr), nsbuffer, INET_ADDRSTRLEN);
            break;
        case AF_INET6:
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *) &sa)->sin6_addr), nsbuffer, INET6_ADDRSTRLEN);
            ip_prefix = "[";
            ip_suffix = "]";
            break;
        default:
            exit(1);
    }

    if (!pkt)
    {
        if(0 > ldns_buffer_printf(output, ""))
        {
            abort();
        }
        return LDNS_STATUS_OK;
    }

    if(!context->cmd_args.only_responses)
    {
        if(0 > ldns_buffer_printf(output, "%s%s%s:%u %ld ", ip_prefix, ip_suffix, nsbuffer, ntohs(((struct sockaddr_in *) &sa)->sin_port), now))
        {
            abort();
        }
        for (i = 0; i < ldns_pkt_qdcount(pkt); i++)
        {
            status = ldns_rr2buffer_str_fmt(output, fmt, ldns_rr_list_rr(ldns_pkt_question(pkt), i));
            if (status != LDNS_STATUS_OK)
            {
                return status;
            }
        }
    }

    if (ldns_buffer_status_ok(output))
    {
        for (i = 0; i < ldns_pkt_ancount(pkt); i++)
        {
            if(!context->cmd_args.only_responses)
            {
                if(0 > ldns_buffer_printf(output, "\t"))
                {
                    abort();
                }
            }
            status = ldns_rr2buffer_str_fmt(output, fmt, ldns_rr_list_rr(ldns_pkt_answer(pkt), i));
            if (status != LDNS_STATUS_OK)
            {
                return status;
            }

        }
        if(!context->cmd_args.no_authority)
        {
            if(0 > ldns_buffer_printf(output, "\n"))
            {
                abort();
            }
            for (i = 0; i < ldns_pkt_nscount(pkt); i++)
            {
                if(!context->cmd_args.only_responses)
                {
                    ldns_buffer_printf(output, "\t");
                }
                status = ldns_rr2buffer_str_fmt(output, fmt, ldns_rr_list_rr(ldns_pkt_authority(pkt), i));
                if (status != LDNS_STATUS_OK)
                {
                    return status;
                }
            }
        }
        if(context->cmd_args.additional)
        {
            for (i = 0; i < ldns_pkt_arcount(pkt); i++)
            {
                if(!context->cmd_args.only_responses)
                {
                    ldns_buffer_printf(output, "\t");
                }
                status = ldns_rr2buffer_str_fmt(output, fmt, ldns_rr_list_rr(ldns_pkt_additional(pkt), i));
                if (status != LDNS_STATUS_OK)
                {
                    return status;
                }

            }
        }
    }
    else
    {
        return ldns_buffer_status(output);
    }
    return status;
}

void print_stats(lookup_context_t *context)
{
    size_t total = stats.noerr + stats.formerr + stats.servfail + stats.nxdomain + stats.notimp + stats.refused +
                   stats.other;
    struct timeval now;
    gettimeofday(&now, NULL);
    context->next_update = now;
    context->next_update.tv_sec += 1;
    long elapsed = timediff(&context->start_time, &now) / 1000;
    long estimated = 0;
    if(total != 0 && !context->initial)
    {
        estimated = elapsed * ((long)context->total_domains) / ((long)total) - elapsed + context->cmd_args.interval_ms * context->cmd_args.resolve_count / 1000;
    }
    if(context->cooldown)
    {
        estimated = (context->cmd_args.interval_ms * context->cmd_args.resolve_count - timediff(&context->cooldown_time, &now)) / 1000 + 1;
        if(estimated < 0)
        {
            estimated = 0;
        }
    }
    FILE *print = stderr;
    if (!context->initial)
    {
        if(context->cmd_args.show_progress)
        {
            fprintf(print, "\033[F\033[F");
        }
        fprintf(print, "\033[F\033[F\033[F\033[F\033[F\033[F\033[F\033[F\033[F\033[J");
    }
    else
    {
        context->initial = false;
    }
    fprintf(print, "Succeeded queries: %zu (%.2f%%)\n", stats.noerr, total == 0 ? 0 : (float) stats.noerr / total * 100);
    fprintf(print, "Format errors: %zu (%.2f%%)\n", stats.formerr, total == 0 ? 0 : (float) stats.formerr / total * 100);
    fprintf(print, "Server failures: %zu (%.2f%%)\n", stats.servfail, total == 0 ? 0 : (float) stats.servfail / total * 100);
    fprintf(print, "Non-existent domains: %zu (%.2f%%)\n", stats.nxdomain, total == 0 ? 0 : (float) stats.nxdomain / total * 100);
    fprintf(print, "Refused: %zu (%.2f%%)\n", stats.refused, total == 0 ? 0 : (float) stats.refused / total * 100);
    fprintf(print, "Total: %zu\n", total);
    fprintf(print, "Current rate: %zu pps\n", context->current_rate);
    fprintf(print, "Average rate: %zu pps\n", elapsed == 0 ? 0 : total / elapsed);
    fprintf(print, "Elapsed: %02ld h %02ld min %02ld sec\n", elapsed / 3600, (elapsed / 60) % 60, elapsed % 60);
    if(context->cmd_args.show_progress)
    {
        fprintf(print, "Estimated time left: %02ld h %02ld min %02ld sec\n", estimated / 3600, (estimated / 60) % 60, estimated % 60);
        fprintf(print, "Progress: %.2f%%\n", context->total_domains == 0 ? 0: (float) total / context->total_domains * 100);
    }
    fflush(print);
    context->current_rate = 0;
}

void massdns_handle_packet(ldns_pkt *packet, struct sockaddr_storage ns, void *ctx)
{
    if (!packet || ldns_pkt_qdcount(packet) != 1)
    {
        return;
    }
    struct timeval now;
    gettimeofday(&now, NULL);
    lookup_context_t *context = (lookup_context_t *) ctx;
    ldns_pkt_rcode response_code = ldns_pkt_get_rcode(packet);
    ldns_rr_list l = ldns_pkt_question(packet)[0];
    ldns_rr *question = ldns_rr_list_rr(&l, 0);
    ldns_rdf* owner = ldns_rr_owner(question);
    char* name = ldns_rdf2str(owner);
    size_t name_len = strlen(name);
    if(name_len > 0 && name[name_len - 1] == '.')
    {
        name[name_len - 1] = 0;
    }
    lookup_t *lookup = hashmapGet(context->map, name);
    free(name);
    if (lookup == NULL)
    {
        return;
    }
    if (response_code == LDNS_RCODE_NOERROR || response_code == LDNS_RCODE_NXDOMAIN ||
        lookup->tries == context->cmd_args.resolve_count)
    {
        switch (response_code)
        {
            case LDNS_RCODE_NOERROR:
                stats.noerr++;
                break;
            case LDNS_RCODE_FORMERR:
                stats.formerr++;
                break;
            case LDNS_RCODE_SERVFAIL:
                stats.servfail++;
                break;
            case LDNS_RCODE_NXDOMAIN:
                stats.nxdomain++;
                break;
            case LDNS_RCODE_NOTIMPL:
                stats.notimp++;
                break;
            case LDNS_RCODE_REFUSED:
                stats.refused++;
                break;
            default:
                stats.other++;
                break;
        }
        context->current_rate++;
        ldns_buffer *buf = ldns_buffer_new(LDNS_MAX_PACKETLEN);
        if(buf == NULL)
        {
            abort();
        }
        if(LDNS_STATUS_OK != output_packet(buf, packet, ns, context))
        {
            abort();
        }
        char* packetstr = ldns_buffer_export2str(buf);
        if(packetstr == NULL)
        {
            abort();
        }
        fprintf(stdout, "%s", packetstr);
        free(packetstr);
        if (timediff(&now, &context->next_update) <= 0)
        {
            print_stats(context);
        }
        ldns_buffer_free(buf);
        hashmapRemove(context->map, lookup->domain);
        free(lookup->domain);
        free(lookup);
    }
}

int massdns_receive_packet(int socket, void (*handle_packet)(ldns_pkt *, struct sockaddr_storage, void *),
                           void *ctx)
{
    uint8_t recvbuf[0xFFFF];
    struct sockaddr_storage recvaddr;
    socklen_t fromlen = sizeof(recvaddr);
    ssize_t num_received = recvfrom(socket, recvbuf, sizeof(recvbuf), 0, (struct sockaddr *) &recvaddr, &fromlen);
    if (num_received > 0)
    {
        ldns_pkt *packet;
        if(LDNS_STATUS_OK != ldns_wire2pkt(&packet, recvbuf, (size_t)num_received))
        {
            // We have received a packet with an invalid format
            return 1;
        }
        handle_packet(packet, recvaddr, ctx);
        ldns_pkt_free(packet);
        return 1;
    }
    return 0;
}

sockaddr_in_t *str_to_addr(char *str)
{
    struct sockaddr_in *addr = safe_malloc(sizeof(*addr));
    addr->sin_port = htons(53);
    if (inet_pton(AF_INET, str, &addr->sin_addr) == 1)
    {
        addr->sin_family = AF_INET;
    }
    else if (inet_pton(AF_INET6, str, &addr->sin_addr) == 1)
    {
        addr->sin_family = AF_INET6;
    }
    else
    {
        free(addr);
        return NULL;
    }
    return addr;
}

void free_element(single_list_t *list, size_t index, void *param)
{
    free(list);
}

buffer_t massdns_resolvers_from_file(char *filename)
{
    size_t line_buflen = 4096;
    char *line = safe_malloc(line_buflen);
    FILE *f = fopen(filename, "r");
    if (f == NULL)
    {
        perror("Failed to open resolver file");
        exit(1);
    }
    single_list_t *list = safe_malloc(sizeof(*list));
    list->next = NULL;
    list->data = NULL;
    single_list_t *start = list;
    single_list_t *previous = NULL;
    while (!feof(f))
    {
        if (0 <= getline(&line, &line_buflen, f))
        {
            trim_end(line);
            struct sockaddr_in *addr = str_to_addr(line);
            if (addr != NULL)
            {
                list->data = addr;
                list->next = safe_malloc(sizeof(*list));
                previous = list;
                list = list->next;
            }
            else
            {
                fprintf(stderr, "\"%s\" is not a valid resolver. Skipped.\n", line);
            }
        }
        else if (previous != NULL)
        {
            free(list);
            list = NULL;
            previous->next = NULL;
        }
        free(line);
        line = NULL;
    }
    fclose(f);
    buffer_t resolvers = single_list_to_array(start);
    single_list_iterate(start, free_element, NULL);
    free(list);
    return resolvers;
}

sockaddr_in_t *massdns_get_resolver(size_t index, buffer_t *resolvers)
{
    return ((sockaddr_in_t **) resolvers->data)[index % resolvers->len];
}

bool handle_domain(void *k, void *l, void *c)
{
    lookup_t *lookup = (lookup_t *) l;
    lookup_context_t *context = (lookup_context_t *) c;
    struct timeval now;
    gettimeofday(&now, NULL);
    if (timediff(&now, &lookup->next_lookup) < 0)
    {
        uint16_t query_flags = 0;
        if (!context->cmd_args.norecurse)
        {
            query_flags |= LDNS_RD;
        }
        ldns_pkt *packet;
        if(LDNS_STATUS_OK != ldns_pkt_query_new_frm_str(&packet, lookup->domain, context->cmd_args.record_types, LDNS_RR_CLASS_IN,
                                   query_flags))
        {
            abort();
        }
        ldns_pkt_set_id(packet, lookup->transaction);
        uint8_t *buf = NULL;
        size_t packet_size = 0;
        if(LDNS_STATUS_OK != ldns_pkt2wire(&buf, packet, &packet_size))
        {
            abort();
        }
        ldns_pkt_free(packet);
        packet = NULL;
        sockaddr_in_t *resolver = massdns_get_resolver((size_t) rand(), &context->resolvers);
        ssize_t n = -1;
        while (n < 0)
        {
            n = sendto(context->sock, buf, packet_size, 0, (sockaddr_t *) resolver, sizeof(*resolver));
        }
        free(buf);
        long addusec = context->cmd_args.interval_ms * 1000;
        addusec += rand() % (addusec / 5); // Avoid congestion by adding some randomness
        lookup->next_lookup.tv_usec = (now.tv_usec + addusec) % 1000000;
        lookup->next_lookup.tv_sec = now.tv_sec + (now.tv_usec + addusec) / 1000000;
        lookup->tries++;
        if (lookup->tries == context->cmd_args.resolve_count)
        {
            hashmapRemove(context->map, lookup->domain);
            free(lookup->domain);
            free(lookup);
        }
    }
    return true;
}

bool cmp_lookup(void *lookup1, void *lookup2)
{
    return strcmp((char *) lookup1, (char *) lookup2) == 0;
}

void massdns_scan(lookup_context_t *context)
{
    memset(&stats, 0, sizeof(dns_stats_t));
    size_t line_buflen = 4096;
    char *line = safe_malloc(line_buflen);
    size_t line_len = 0;
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = 0;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    int socketbuf = 1024 * 1024 * 100;
    if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &socketbuf, sizeof(socketbuf)) != 0)
    {
        perror("Failed to adjust socket send buffer size.");
    }
    if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &socketbuf, sizeof(socketbuf)) != 0)
    {
        perror("Failed to adjust socket receive buffer size.");
    }
    bind(sock, (sockaddr_t *) &server_addr, sizeof(server_addr));

    fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);

    if (sock < 0)
    {
        perror("Failed to create socket");
        exit(1);
    }
    FILE *f;
    if(context->cmd_args.show_progress)
    {
        f = fopen(context->cmd_args.domains, "r");
        if (f == NULL)
        {
            perror("Failed to open domain file");
            exit(1);
        }
        while(!feof(f))
        {
            if (0 <= getline(&line, &line_buflen, f))
            {
                trim_end(line);
                strtolower(line);
                if (strcmp(line, "") != 0)
                {
                    context->total_domains++;
                }
            }
        }
        fclose(f);
    }
    f = fopen(context->cmd_args.domains, "r");
    if (f == NULL)
    {
        perror("Failed to open domain file");
        exit(1);
    }
    if (geteuid() == 0)
    {
        fprintf(stderr, "You have started the program with root privileges.\n");
        struct passwd *nobody = getpwnam(UNPRIVILEGED_USER);
        if (!context->cmd_args.root)
        {
            if (nobody && setuid(nobody->pw_uid) == 0)
            {
                fprintf(stderr, "Privileges have been dropped to \"%s\" for security reasons.\n\n", UNPRIVILEGED_USER);
            }
            else if (!context->cmd_args.root)
            {
                fprintf(stderr, "Privileges could not be dropped to \"%s\".\n"
                        "For security reasons, this program will only run as root user when supplied with --root"
                        "which is not recommended.\n"
                        "It is better practice to run this program as a different user.\n", UNPRIVILEGED_USER);
                exit(1);
            }
        }
        else
        {
            fprintf(stderr, "[WARNING] Privileges were not dropped. This is not recommended.\n\n");
        }
    }
    FILE *randomness = fopen("/dev/urandom", "r");
    if (!randomness)
    {
        fprintf(stderr, "Failed to open /dev/urandom.\n");
        exit(1);
    }
    context->current_rate = 0;
    context->sock = sock;
    context->resolvers = massdns_resolvers_from_file(context->cmd_args.resolvers);
    context->map = hashmapCreate(context->cmd_args.hashmap_size, hash_string, cmp_lookup);
    context->initial = true;
    gettimeofday(&context->start_time, NULL);
    context->next_update = context->start_time;
    while (true)
    {
        while (hashmapSize(context->map) < context->cmd_args.hashmap_size && !feof(f))
        {
            if (0 <= getline(&line, &line_buflen, f))
            {
                trim_end(line);
                line_len = strlen(line);
                strtolower(line);
                if(strcmp(line, "") == 0)
                {
                    continue;
                }
                if (line_len > 0 && line[line_len - 1] == '.')
                {
                    // Remove trailing dot from FQDN
                    line[line_len] = 0;
                }
                lookup_t *lookup = hashmapGet(context->map, line);
                if (lookup == NULL)
                {
                    char *value = safe_malloc(line_len + 1);
                    strcpy(value, line);
                    lookup = safe_malloc(sizeof(*lookup));
                    lookup->domain = value;
                    lookup->tries = 0;
                    if (fread(&lookup->transaction, 1, sizeof(lookup->transaction), randomness) !=
                        sizeof(lookup->transaction))
                    {
                        fprintf(stderr, "Failed to get randomness for transaction id.\n");
                        exit(1);
                    }
                    gettimeofday(&lookup->next_lookup, NULL);
                    hashmapPut(context->map, value, lookup);
                }

            }
        }
        if(!context->cooldown && hashmapSize(context->map) < context->cmd_args.hashmap_size)
        {
            context->cooldown = true;
            gettimeofday(&context->cooldown_time, NULL);
        }
        while (massdns_receive_packet(sock, massdns_handle_packet, context));
        if (feof(f) && hashmapSize(context->map) == 0)
        {
            break;
        }
        hashmapForEach(context->map, handle_domain, context);
    }
    for (size_t i = 0; i < context->resolvers.len; i++)
    {
        free(((sockaddr_in_t **) context->resolvers.data)[i]);
        ((sockaddr_in_t **) context->resolvers.data)[i] = NULL;
    }
    free(line);
    free(context->resolvers.data);
    context->resolvers.data = NULL;
    print_stats(context);
    hashmapFree(context->map);
    context->map = NULL;
    fclose(f);
    fclose(randomness);
}

int main(int argc, char **argv)
{
#ifdef DEBUG
    struct rlimit core_limits;
    core_limits.rlim_cur = core_limits.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_CORE, &core_limits);
#endif
    if (argc <= 1)
    {
        print_help(argc > 0 ? argv[0] : "massdns");
        return 1;
    }
    lookup_context_t ctx;
    lookup_context_t *context = &ctx;
    memset(&context->cmd_args, 0, sizeof(context->cmd_args));
    context->cmd_args.resolve_count = 50;
    context->cmd_args.hashmap_size = 100000;
    context->cmd_args.interval_ms = 200;
    context->cooldown = false;
    context->total_domains = 0;
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
        {
            print_help(argv[0]);
            return 1;
        }
        else if (strcmp(argv[i], "--resolvers") == 0 || strcmp(argv[i], "-r") == 0)
        {
            if (context->cmd_args.resolvers == NULL)
            {
                if (i + 1 >= argc)
                {
                    fprintf(stderr, "The argument -r requires a valid file.\n\n");
                    print_help(argv[0]);
                    return 1;
                }
                context->cmd_args.resolvers = argv[++i];
            }
            else
            {
                fprintf(stderr, "Resolvers may only be supplied once.\n\n");
                print_help(argv[0]);
                return 1;
            }
        }
        else if (strcmp(argv[i], "--types") == 0 || strcmp(argv[i], "-t") == 0)
        {
            if (context->cmd_args.record_types != 0)
            {
                fprintf(stderr, "Currently, only one record type is supported.\n\n");
                return 1;
            }
            if (i + 1 >= argc)
            {
                fprintf(stderr, "The argument -t requires a valid record type.\n\n");
                print_help(argv[0]);
                return 1;
            }
            int record = record_from_str(argv[++i]);
            if (record == 0)
            {
                fprintf(stderr, "Unsupported record type: %s\n\n", argv[i]);
                print_help(argv[0]);
                return 1;
            }
            context->cmd_args.record_types |= record;
        }
        else if (strcmp(argv[i], "--root") == 0)
        {
            context->cmd_args.root = true;
        }
        else if (strcmp(argv[i], "--no-authority") == 0 || strcmp(argv[i], "-a") == 0)
        {
            context->cmd_args.no_authority = true;
        }
        else if (strcmp(argv[i], "--only-responses") == 0 || strcmp(argv[i], "-o") == 0)
        {
            context->cmd_args.only_responses = true;
        }
        else if (strcmp(argv[i], "--norecurse") == 0 || strcmp(argv[i], "-n") == 0)
        {
            context->cmd_args.norecurse = true;
        }
        else if (strcmp(argv[i], "--additional") == 0 || strcmp(argv[i], "-e") == 0)
        {
            context->cmd_args.additional = true;
        }
        else if (strcmp(argv[i], "--progress") == 0 || strcmp(argv[i], "-p") == 0)
        {
            context->cmd_args.show_progress = true;
        }
        else if (strcmp(argv[i], "--resolve-count") == 0 || strcmp(argv[i], "-c") == 0)
        {
            if (i + 1 >= argc || atoi(argv[i + 1]) < 1 || atoi(argv[i + 1]) > 255)
            {
                fprintf(stderr, "The resolve count must be a valid number between 1 and 255.\n\n");
                print_help(argv[0]);
                return 1;
            }
            context->cmd_args.resolve_count = (unsigned char) atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "--hashmap-size") == 0 || strcmp(argv[i], "-s") == 0)
        {
            if (i + 1 >= argc || strtol(argv[i + 1], NULL, 10) < 1)
            {
                fprintf(stderr, "The hashmap size has to be a valid number larger than 0.\n\n");
                print_help(argv[0]);
                return 1;
            }
            context->cmd_args.hashmap_size = (size_t) strtol(argv[++i], NULL, 10);
        }
        else if (strcmp(argv[i], "--interval") == 0 || strcmp(argv[i], "-i") == 0)
        {
            if (i + 1 >= argc || atoi(argv[i + 1]) < 0)
            {
                fprintf(stderr, "The interval has to be a valid number larger than or equal to 0.\n\n");
                print_help(argv[0]);
                return 1;
            }
            context->cmd_args.interval_ms = (unsigned int) atoi(argv[++i]);
        }
        else
        {
            if (context->cmd_args.domains == NULL)
            {
                context->cmd_args.domains = argv[i];
            }
            else
            {
                fprintf(stderr, "The domain list may only be supplied once.\n\n");
                print_help(argv[0]);
                return 1;
            }
        }
    }
    if (context->cmd_args.record_types == 0)
    {
        context->cmd_args.record_types = LDNS_RR_TYPE_A;
    }
    if (context->cmd_args.resolvers == NULL)
    {
        fprintf(stderr, "Resolvers are required to be supplied.\n\n");
        print_help(argv[0]);
        return 1;
    }
    if (context->cmd_args.domains == NULL)
    {
        fprintf(stderr, "The domain list is required to be supplied.\n\n");
        print_help(argv[0]);
        return 1;
    }
    massdns_scan(context);
    return 0;
}
