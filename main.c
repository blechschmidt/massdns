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
#include <time.h>
#include <unistd.h>
#include <pwd.h>
#include "security.h"
#include "dns.h"
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
                    "  -h  --help             Show this help.\n"
                    "  -i  --interval         Interval in milliseconds to wait between multiple resolves of the same"
                    " domain. (Default: 200)\n"
                    "  -n  --norecurse        Use non-recursive queries. Useful for DNS cache snooping.\n"
                    "  -o  --only-responses   Do not output DNS questions.\n"
                    "  -r  --resolvers        Text file containing DNS resolvers.\n"
                    "      --root             Allow running the program as root. Not recommended.\n"
                    "  -s  --hashmap-size     Set the size of the hashmap used for resolving. (Default: 500000)\n"
                    "  -t  --type             Record type to be resolved. (Default: A)\n"
                    "  -u  --unknown-records  Include unknown/unimplemented DNS records.\n"
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
        return RECORD_A;
    }
    if (strcmp(str, "aaaa") == 0)
    {
        return RECORD_AAAA;
    }
    if (strcmp(str, "cname") == 0)
    {
        return RECORD_CNAME;
    }
    if (strcmp(str, "mx") == 0)
    {
        return RECORD_MX;
    }
    if (strcmp(str, "ns") == 0)
    {
        return RECORD_NS;
    }
    if (strcmp(str, "ptr") == 0)
    {
        return RECORD_PTR;
    }
    if (strcmp(str, "txt") == 0)
    {
        return RECORD_TXT;
    }
    if (strcmp(str, "soa") == 0)
    {
        return RECORD_SOA;
    }
    if (strcmp(str, "any") == 0)
    {
        return RECORD_ANY;
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
    int records;
    int sock;
    buffer_t resolvers;
    Hashmap *map;
    struct timeval next_update;
    size_t current_rate;
    bool initial;
    struct timeval start_time;
    struct cmd_args
    {
        bool root;
        char *resolvers;
        char *domains;
        int record_types;
        unsigned char resolve_count;
        size_t hashmap_size;
        unsigned int interval_ms;
        bool no_authority;
        bool unknown_records;
        bool only_responses;
        bool norecurse;
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

void output_response(dns_packet *packet, struct sockaddr_storage sa, lookup_context_t *context)
{
    time_t now = time(NULL);
    dns_record *record = packet->answer;
    char nsbuffer[INET6_ADDRSTRLEN];
    switch (((struct sockaddr *) &sa)->sa_family)
    {
        case AF_INET:
            inet_ntop(AF_INET, &(((struct sockaddr_in *) &sa)->sin_addr), nsbuffer, INET_ADDRSTRLEN);
            break;
        case AF_INET6:
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *) &sa)->sin6_addr), nsbuffer, INET6_ADDRSTRLEN);
            break;
        default:
            exit(1);
    }
    const char* const record_class = dns_record_class_to_string(packet->question->class);
    const char* const record_type = dns_record_type_to_string(packet->question->type);
    if(!context->cmd_args.only_responses)
    {
        fprintf(stdout, "%s %s %s %s %ld\n", nsbuffer, packet->question->name, record_class, record_type, now);
    }
    while (record)
    {
        char *buf = dns_record_to_string(record, context->cmd_args.unknown_records);
        if(buf != NULL)
        {
            fprintf(stdout, "%s%s\n", context->cmd_args.only_responses ? "" : "\t", buf);
            free(buf);
        }
        record = record->next_record;
    }
    if(!context->cmd_args.no_authority)
    {
        fprintf(stdout, "\n");
        record = packet->authority;
        while (record)
        {
            char *buf = dns_record_to_string(record, context->cmd_args.unknown_records);
            if (buf != NULL)
            {
                fprintf(stdout, "%s%s\n", context->cmd_args.only_responses ? "" : "\t", buf);
                free(buf);
            }
            record = record->next_record;
        }
        fprintf(stdout, "\n\n");
    }
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
    FILE *print = stderr;
    if (!context->initial)
    {
        fprintf(print, "\033[F\033[F\033[F\033[F\033[F\033[F\033[F\033[F\033[F\033[J");
    }
    else
    {
        context->initial = false;
    }
    fprintf(print, "Succeeded queries: %zu (%.2f%%)\n", stats.noerr, (float) stats.noerr / total * 100);
    fprintf(print, "Format errors: %zu (%.2f%%)\n", stats.formerr, (float) stats.formerr / total * 100);
    fprintf(print, "Server failures: %zu (%.2f%%)\n", stats.servfail, (float) stats.servfail / total * 100);
    fprintf(print, "Non-existent domains: %zu (%.2f%%)\n", stats.nxdomain, (float) stats.nxdomain / total * 100);
    fprintf(print, "Refused: %zu (%.2f%%)\n", stats.refused, (float) stats.refused / total * 100);
    fprintf(print, "Total: %zu\n", total);
    fprintf(print, "Current rate: %zu pps\n", context->current_rate);
    fprintf(print, "Average rate: %zu pps\n", elapsed == 0 ? 0 : total / elapsed);
    fprintf(print, "Elapsed: %02ld h %02ld min %02ld sec\n", elapsed / 3600, (elapsed / 60) % 60, elapsed % 60);
    fflush(print);
    context->current_rate = 0;
}

void massdns_handle_packet(dns_packet *packet, struct sockaddr_storage ns, void *ctx)
{
    if (!packet || !packet->question)
    {
        return;
    }
    struct timeval now;
    gettimeofday(&now, NULL);
    lookup_context_t *context = (lookup_context_t *) ctx;
    char response_code = (char) (packet->flags & 0xF);
    lookup_t *lookup = hashmapGet(context->map, packet->question->name);
    if (lookup == NULL)
    {
        return;
    }
    if (lookup->transaction != packet->transaction)
    {
        response_code = DNS_REPLY_FORMERR;
    }
    if (response_code == DNS_REPLY_NOERR || response_code == DNS_REPLY_NXDOMAIN || lookup->tries == context->cmd_args.resolve_count)
    {
        switch (response_code)
        {
            case DNS_REPLY_NOERR:
                stats.noerr++;
                break;
            case DNS_REPLY_FORMERR:
                stats.formerr++;
                break;
            case DNS_REPLY_SERVFAIL:
                stats.servfail++;
                break;
            case DNS_REPLY_NXDOMAIN:
                stats.nxdomain++;
                break;
            case DNS_REPLY_NOTIMP:
                stats.notimp++;
                break;
            case DNS_REPLY_REFUSED:
                stats.refused++;
                break;
            default:
                stats.other++;
                break;
        }
        context->current_rate++;
        output_response(packet, ns, context);
        if (timediff(&now, &context->next_update) <= 0)
        {
            print_stats(context);
        }
        hashmapRemove(context->map, packet->question->name);
        free(lookup->domain);
        free(lookup);
    }
}

int massdns_receive_packet(int socket, void (*handle_packet)(dns_packet *, struct sockaddr_storage, void *),
                           void *ctx)
{
    char recvbuf[0xFFFF];
    struct sockaddr_storage recvaddr;
    socklen_t fromlen = sizeof(recvaddr);
    ssize_t num_received = recvfrom(socket, recvbuf, sizeof(recvbuf), 0, (struct sockaddr *) &recvaddr, &fromlen);
    if (num_received > 0)
    {
        dns_packet *packet = safe_malloc(sizeof(*packet));
        int result = dns_parse_raw_packet(packet, recvbuf, (size_t) num_received);
        if (result == DNS_REPLY_FORMERR)
        {
            dns_destroy_packet(packet);
            return 1;
        }
        handle_packet(packet, recvaddr, ctx);
        dns_destroy_packet(packet);
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
    char *key = (char *) k;
    lookup_t *lookup = (lookup_t *) l;
    lookup_context_t *context = (lookup_context_t *) c;
    while (massdns_receive_packet(context->sock, massdns_handle_packet, context));
    struct timeval now;
    gettimeofday(&now, NULL);
    if (timediff(&now, &lookup->next_lookup) < 0)
    {
        char *buf = NULL;
        uint16_t query_flags = DNS_ANSWER_AUTHENTICATED_FLAG;
        if(!context->cmd_args.norecurse)
        {
            query_flags |= DNS_RECURSION_DESIRED_FLAG;
        }
        dns_packet *packet = dns_create_packet(key, context->records, lookup->transaction, query_flags);
        size_t packet_size = dns_packet_to_bytes(packet, &buf);
        dns_destroy_packet(packet);
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
        if(lookup->tries == context->cmd_args.resolve_count)
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
    char* line = safe_malloc(line_buflen);
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
    FILE *f = fopen(context->cmd_args.domains, "r");
    if (f == NULL)
    {
        perror("Failed to open domain file");
        exit(1);
    }

    if (geteuid() == 0)
    {
        fprintf(stderr, "You have started the program with root privileges.\n");
        struct passwd *nobody = getpwnam(UNPRIVILEGED_USER);
        if(!context->cmd_args.root)
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

    context->current_rate = 0;
    context->records = context->cmd_args.record_types;
    context->sock = sock;
    context->resolvers = massdns_resolvers_from_file(context->cmd_args.resolvers);
    context->map = hashmapCreate(context->cmd_args.hashmap_size, hash_string, cmp_lookup);
    context->initial = true;
    gettimeofday(&context->start_time, NULL);
    context->next_update = context->start_time;
    while (true)
    {
        while (massdns_receive_packet(sock, massdns_handle_packet, context));
        while (hashmapSize(context->map) < context->cmd_args.hashmap_size && !feof(f))
        {
            if (0 <= getline(&line, &line_buflen, f))
            {
                trim_end(line);
                line_len = strlen(line);
                strtolower(line);
                if (line_len > 0 && line[line_len - 1] == '.')
                {
                    // Remove trailing dot from FQDN
                    line[line_len - 1] = 0;
                }
                lookup_t *lookup = hashmapGet(context->map, line);
                if (lookup == NULL)
                {
                    char *value = safe_malloc(line_len + 1);
                    strcpy(value, line);
                    lookup = safe_malloc(sizeof(*lookup));
                    lookup->domain = value;
                    lookup->tries = 0;
                    lookup->transaction = (uint16_t) rand();
                    gettimeofday(&lookup->next_lookup, NULL);
                    hashmapPut(context->map, value, lookup);
                }

            }
        }
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
    free(context);
    fclose(f);
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
    lookup_context_t *context = safe_malloc(sizeof(*context));
    memset(&context->cmd_args, 0, sizeof(context->cmd_args));
    context->cmd_args.resolve_count = 50;
    context->cmd_args.hashmap_size = 500000;
    context->cmd_args.interval_ms = 200;
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
            if(context->cmd_args.record_types != 0)
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
        else if (strcmp(argv[i], "--unknown-records") == 0 || strcmp(argv[i], "-u") == 0)
        {
            context->cmd_args.unknown_records = true;
        }
        else if (strcmp(argv[i], "--only-responses") == 0 || strcmp(argv[i], "-o") == 0)
        {
            context->cmd_args.only_responses = true;
        }
        else if (strcmp(argv[i], "--norecurse") == 0 || strcmp(argv[i], "-n") == 0)
        {
            context->cmd_args.norecurse = true;
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
            if(i+1 >= argc || strtol(argv[i + 1], NULL, 10) < 1)
            {
                fprintf(stderr, "The hashmap size has to be a valid number larger than 0.\n\n");
                print_help(argv[0]);
                return 1;
            }
            context->cmd_args.hashmap_size = (size_t)strtol(argv[++i], NULL, 10);
        }
        else if (strcmp(argv[i], "--interval") == 0 || strcmp(argv[i], "-i") == 0)
        {
            if(i+1 >= argc || atoi(argv[i + 1]) < 0)
            {
                fprintf(stderr, "The interval has to be a valid number larger than or equal to 0.\n\n");
                print_help(argv[0]);
                return 1;
            }
            context->cmd_args.interval_ms = (unsigned int)atoi(argv[++i]);
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
        context->cmd_args.record_types = RECORD_A;
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
