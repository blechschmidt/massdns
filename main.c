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
#include <ldns/rbtree.h>
#include <ldns/packet.h>
#include <ldns/host2wire.h>
#include <ldns/wire2host.h>
#include <ldns/dnssec.h>

#include "security.h"
#include "string.h"
#include "list.h"
#include "massdns.h"
#include "module.h"

#ifdef DEBUG
#include <sys/resource.h>
#endif

#define UNPRIVILEGED_USER "nobody"

typedef struct sockaddr_in sockaddr_in_t;
typedef struct sockaddr sockaddr_t;
typedef struct sockaddr_in6 sockaddr_in6_t;

void print_help(char *file)
{
    fprintf(stderr, ""
                    "Usage: %s [options] domainlist (- for stdin) \n"
                    "  -6                     Use IPv6.\n"
                    "  -a  --no-authority     Omit records from the authority section of the response packets.\n"
                    "  -b  --bindto           Bind to IP address and port. (Default: 0.0.0.0:0)\n"
                    "  -c  --resolve-count    Number of resolves for a name before giving up. (Default: 50)\n"
                    "  -e  --additional       Include response records within the additional section.\n"
                    "  -h  --help             Show this help.\n"
                    "  -i  --interval         Interval in milliseconds to wait between multiple resolves of the same"
                    " domain. (Default: 200)\n"
                    "  -l  --error-log        Error log file path. (Default: /dev/stderr)\n"
                    "  -m  --module           Load a shared module in order to handle packets.\n"
                    "  -n  --norecurse        Use non-recursive queries. Useful for DNS cache snooping.\n"
                    "  -o  --only-responses   Do not output DNS questions.\n"
                    "  -p  --progress         Show the progress and remaining time.\n"
                    "      --finalstats       Write final stats to STDERR when done.\n"
                    "  -q  --quiet            Quiet mode.\n"
                    "      --rcvbuf           Size of the receive buffer in bytes.\n"
                    "  -r  --resolvers        Text file containing DNS resolvers.\n"
                    "      --root             Allow running the program as root. Not recommended.\n"
                    "  -s  --hashmap-size     Set the size of the hashmap used for resolving. (Default: 100000)\n"
                    "      --sndbuf           Size of the send buffer in bytes.\n"
                    "  -t  --type             Record type to be resolved. (Default: A)\n"
                    "  -w  --outfile          Write to the specified output file instead of standard output.\n"
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
                    "  SOA\n"
                    "  TXT\n"
                    "  CAA\n"
                    "  TLSA\n",
            file
    );
}

int record_from_str(char *str)
{
    if (strcasecmp(str, "a") == 0)
    {
        return LDNS_RR_TYPE_A;
    }
    if (strcasecmp(str, "aaaa") == 0)
    {
        return LDNS_RR_TYPE_AAAA;
    }
    if (strcasecmp(str, "cname") == 0)
    {
        return LDNS_RR_TYPE_CNAME;
    }
    if (strcasecmp(str, "dname") == 0)
    {
        return LDNS_RR_TYPE_DNAME;
    }
    if (strcasecmp(str, "mx") == 0)
    {
        return LDNS_RR_TYPE_MX;
    }
    if (strcasecmp(str, "ns") == 0)
    {
        return LDNS_RR_TYPE_NS;
    }
    if (strcasecmp(str, "ptr") == 0)
    {
        return LDNS_RR_TYPE_PTR;
    }
    if (strcasecmp(str, "txt") == 0)
    {
        return LDNS_RR_TYPE_TXT;
    }
    if (strcasecmp(str, "soa") == 0)
    {
        return LDNS_RR_TYPE_SOA;
    }
    if (strcasecmp(str, "any") == 0)
    {
        return LDNS_RR_TYPE_ANY;
    }
    if (strcasecmp(str, "tlsa") == 0)
    {
        return LDNS_RR_TYPE_TLSA;
    }
    if (strcasecmp(str, "caa") == 0)
    {
        return LDNS_RR_TYPE_CAA;
    }
    return 0;
}

typedef struct dns_stats_t
{
    size_t answers;
    size_t noerr;
    size_t formerr;
    size_t servfail;
    size_t nxdomain;
    size_t notimp;
    size_t refused;
    size_t yxdomain;
    size_t yxrrset;
    size_t nxrrset;
    size_t notauth;
    size_t notzone;
    size_t timeout;
    size_t mismatch;
    size_t other;
    size_t qsent;
} dns_stats_t;

dns_stats_t stats;
unsigned int * timeout_stats;

typedef struct lookup
{
    char *domain;
    unsigned char tries;
    uint16_t transaction;
    struct timeval next_lookup;
} lookup_t;

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

ldns_status
output_packet(ldns_buffer *output, const ldns_pkt *pkt, struct sockaddr_storage sa, massdns_context_t *context)
{
    const ldns_output_format *fmt = ldns_output_format_nocomments;
    uint16_t i;
    ldns_status status = LDNS_STATUS_OK;

    time_t now = time(NULL);
    char nsbuffer[INET6_ADDRSTRLEN];
    char *ip_prefix = "";
    char *ip_suffix = "";
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
        if (0 > ldns_buffer_printf(output, ""))
        {
            fprintf(stdout, "ABORT: some ldns buffer printf fail \n");
            abort();
        }
        return LDNS_STATUS_OK;
    }

    if (!context->cmd_args.only_responses)
    {
        char *rcode_str = ldns_pkt_rcode2str(ldns_pkt_get_rcode(pkt));
        if (0 > ldns_buffer_printf(output, "%s%s%s:%u %ld %s ", ip_prefix, nsbuffer, ip_suffix,
                                   ntohs(((struct sockaddr_in *) &sa)->sin_port), now, rcode_str))
        {
            fprintf(stdout, "ABORT: another ldns printf buffer fail \n");
            abort();
        }
        free(rcode_str);
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
            if (!context->cmd_args.only_responses)
            {
                if (0 > ldns_buffer_printf(output, "\t"))
                {
                    fprintf(stdout, "ABORT: yet another ldns printf buffer fail \n");
                    abort();
                }
            }
            status = ldns_rr2buffer_str_fmt(output, fmt, ldns_rr_list_rr(ldns_pkt_answer(pkt), i));
            if (status != LDNS_STATUS_OK)
            {
                return status;
            }

        }
        if (!context->cmd_args.no_authority)
        {
            if (0 > ldns_buffer_printf(output, "\n"))
            {
                fprintf(stdout, "ABORT: yet another ldns printf buffer fail #10 \n");
                abort();
            }
            for (i = 0; i < ldns_pkt_nscount(pkt); i++)
            {
                if (!context->cmd_args.only_responses)
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
        if (context->cmd_args.additional)
        {
            for (i = 0; i < ldns_pkt_arcount(pkt); i++)
            {
                if (!context->cmd_args.only_responses)
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

void print_stats(massdns_context_t *context)
{
    if (context->cmd_args.quiet)
    { return; }
    size_t total = stats.noerr + stats.formerr + stats.servfail + stats.nxdomain + stats.notimp + stats.refused +
                   stats.yxdomain + stats.yxrrset + stats.nxrrset + stats.notauth + stats.notzone + stats.other;
    struct timeval now;
    gettimeofday(&now, NULL);
    context->next_update = now;
    context->next_update.tv_sec += 1;
    long elapsed = timediff(&context->start_time, &now) / 1000;
    long estimated = 0;
    if (total != 0 && !context->initial)
    {
        estimated = elapsed * ((long) context->total_domains) / ((long) total) - elapsed +
                    context->cmd_args.interval_ms * context->cmd_args.resolve_count / 1000;
    }
    if (context->cooldown)
    {
        estimated = (context->cmd_args.interval_ms * context->cmd_args.resolve_count -
                     timediff(&context->cooldown_time, &now)) / 1000 + 1;
        if (estimated < 0)
        {
            estimated = 0;
        }
    }
    FILE *print = stderr;
    if(context->initial)
    {
        context->initial = false;
    }
    fprintf(print, "\033[H\033[2J");
    fprintf(print, "Succeeded queries (only with RR answer): %zu (%.2f%%)\n", stats.answers,
            total == 0 ? 0 : (float) stats.answers / total * 100);
    fprintf(print, "Succeeded queries (includes empty answer): %zu (%.2f%%)\n", stats.noerr,
            total == 0 ? 0 : (float) stats.noerr / total * 100);
    fprintf(print, "Format errors: %zu (%.2f%%)\n", stats.formerr,
            total == 0 ? 0 : (float) stats.formerr / total * 100);
    fprintf(print, "SERVFAIL: %zu (%.2f%%)\n", stats.servfail, total == 0 ? 0 : (float) stats.servfail / total * 100);
    fprintf(print, "NXDOMAIN: %zu (%.2f%%)\n", stats.nxdomain, total == 0 ? 0 : (float) stats.nxdomain / total * 100);
    fprintf(print, "Final Timeout: %zu (%.2f%%)\n", stats.timeout,
            total == 0 ? 0 : (float) stats.timeout / (total + stats.timeout * 100));
    fprintf(print, "Timeout Details: ");
    for(int i=0;i<context->cmd_args.resolve_count;i++){
      fprintf(print, "%u: %u (%.0f%%), ",i+1,timeout_stats[i],100*(float)timeout_stats[i]/timeout_stats[0]);
    }
    fprintf(print, "\n");
    fprintf(print, "Refused: %zu (%.2f%%)\n", stats.refused, total == 0 ? 0 : (float) stats.refused / total * 100);
    fprintf(print, "Mismatch: %zu (%.2f%%)\n", stats.mismatch, total == 0 ? 0 : (float) stats.mismatch / total * 100);
    fprintf(print, "Total queries sent: %zu \n", stats.qsent);
    fprintf(print, "Total received: %zu of %zu \n", total, context->total_domains);
    fprintf(print, "Hashtable size: %zu \n", hashmapSize(context->map));
    fprintf(print, "Current rate: %zu pps\n", context->current_rate);
    fprintf(print, "Average rate: %zu pps\n", elapsed == 0 ? 0 : total / elapsed);
    fprintf(print, "Elapsed: %02ld h %02ld min %02ld sec\n", elapsed / 3600, (elapsed / 60) % 60, elapsed % 60);
    if (context->cmd_args.show_progress)
    {
        fprintf(print, "Estimated time left: %02ld h %02ld min %02ld sec\n", estimated / 3600, (estimated / 60) % 60,
                estimated % 60);
        fprintf(print, "Progress: %.2f%%\n",
                context->total_domains == 0 ? 0 : (float) total / context->total_domains * 100);
    }
    fflush(print);
    context->current_rate = 0;
}

void print_stats_final(massdns_context_t *context)
{
    size_t total = stats.noerr + stats.formerr + stats.servfail + stats.nxdomain + stats.notimp + stats.refused +
                   stats.yxdomain + stats.yxrrset + stats.nxrrset + stats.notauth + stats.notzone + stats.other;
    FILE *print = stderr;
    struct timeval now;
    gettimeofday(&now, NULL);
    long elapsed = timediff(&context->start_time, &now) / 1000;
    fprintf(print, "FINALSTATS: Succeeded queries (only with RR answer): %zu (%.2f%%)\n", stats.answers,
            total == 0 ? 0 : (float) stats.answers / total * 100);
    fprintf(print, "FINALSTATS: Succeeded queries (includes empty answer): %zu (%.2f%%)\n", stats.noerr,
            total == 0 ? 0 : (float) stats.noerr / total * 100);
    fprintf(print, "FINALSTATS: SERVFAIL: %zu (%.2f%%)\n", stats.servfail,
            total == 0 ? 0 : (float) stats.servfail / total * 100);
    fprintf(print, "FINALSTATS: NXDOMAIN: %zu (%.2f%%)\n", stats.nxdomain,
            total == 0 ? 0 : (float) stats.nxdomain / total * 100);
    fprintf(print, "FINALSTATS: Final Timeout: %zu (%.2f%%)\nDEBUG: FINALSTATS: ", stats.timeout,
            total == 0 ? 0 : (float) stats.timeout / (total + stats.timeout * 100));
    fprintf(print, "DEBUG: FINALSTATS: Timeout Details: ");
    for(int i=0;i<context->cmd_args.resolve_count;i++){
      fprintf(print, "%u: %u (%.0f%%), ",i+1,timeout_stats[i],100*(float)timeout_stats[i]/timeout_stats[0]);
    }
    fprintf(print, "\n");
    fprintf(print, "FINALSTATS: Refused: %zu (%.2f%%)\n", stats.refused,
            total == 0 ? 0 : (float) stats.refused / total * 100);
    fprintf(print, "FINALSTATS: Mismatch: %zu (%.2f%%)\n", stats.mismatch,
            total == 0 ? 0 : (float) stats.mismatch / total * 100);
    fprintf(print, "FINALSTATS: Total queries sent: %zu \n", stats.qsent);
    fprintf(print, "FINALSTATS: Total received: %zu \n", total);
    fprintf(print, "FINALSTATS: config:  hashtable %zu, timeout %u seconds, retries %u \n",
            context->cmd_args.hashmap_size, context->cmd_args.interval_ms / 1000, context->cmd_args.resolve_count);
    fprintf(print, "FINALSTATS: Average rate: %zu pps\n", elapsed == 0 ? 0 : total / elapsed);
    fprintf(print, "FINALSTATS: Elapsed: %02ld h %02ld min %02ld sec\n", elapsed / 3600, (elapsed / 60) % 60,
            elapsed % 60);
    fflush(print);
}

void massdns_handle_packet(ldns_pkt *packet, struct sockaddr_storage ns, void *ctx)
{
    if (!packet || ldns_pkt_qdcount(packet) != 1)
    {
        return;
    }
    struct timeval now;
    gettimeofday(&now, NULL);
    massdns_context_t *context = (massdns_context_t *) ctx;
    ldns_pkt_rcode response_code = ldns_pkt_get_rcode(packet);
    ldns_rr_list l = ldns_pkt_question(packet)[0];
    ldns_rr *question = ldns_rr_list_rr(&l, 0);
    ldns_rdf *owner = ldns_rr_owner(question);
    char *name = ldns_rdf2str(owner);
    size_t name_len = strlen(name);
    if (name_len > 0 && name[name_len - 1] == '.')
    {
        name[name_len - 1] = 0;
    }
    lookup_t *lookup = hashmapGet(context->map, name);

    if (lookup == NULL) // domain is not in hashmap
    {
        stats.mismatch++;
        // not neccessarily a problem, sometimes we receive duplicate answers
#ifdef DEBUG
        fprintf(stdout, "ERROR: MISMATCH: Received answer for domain not in hashmap: \"%s\" \n", name);
#endif
        free(name);
        return;
    }
    free(name);
    ldns_buffer *buf = ldns_buffer_new(LDNS_MAX_PACKETLEN);
    if (buf == NULL)
    {
        fprintf(stderr, "ABORT: buffer == NULL \n");
        fprintf(stdout, "ABORT: buffer == NULL \n");
        abort();
    }
    if(context->module.handle_response)
    {
        context->module.handle_response(context, packet, &ns);
    }
    else
    {
        if (LDNS_STATUS_OK != output_packet(buf, packet, ns, context))
        {
            ldns_buffer_free(buf);
            fprintf(stderr, "CRITICAL: output packet status not OK for domain %s -- check log file\n", lookup->domain);
            fprintf(stdout, "CRITICAL: output packet status not OK for domain %s -- check log file\n", lookup->domain);

            fprintf(context->logfile, "ERR_STATUS,%d,%s\n", (int)now.tv_sec, lookup->domain);

            stats.formerr++;

            // do not try again
            hashmapRemove(context->map, lookup->domain);
            free(lookup->domain);
            free(lookup);

            return;
        }
        else
        {
            char *packetstr = ldns_buffer_export2str(buf);
            if (packetstr == NULL)
            {
                fprintf(stderr, "ABORT: packetstr == NULL \n");
                fprintf(stdout, "ABORT: packetstr == NULL \n");
                abort();
            }
            if (strcmp(packetstr, "") == 0)
            {
#ifdef DEBUG
                fprintf(stdout, "DEBUG: empty reply for %s\n", lookup->domain);
#endif
            }
            else
            {
                fprintf(context->outfile, "%s", packetstr);
                stats.answers++;
            }
            free(packetstr);
        }
    }
    if (timediff(&now, &context->next_update) <= 0)
    {
        print_stats(context);
    }
    ldns_buffer_free(buf);
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
        case LDNS_RCODE_YXDOMAIN:
            stats.yxdomain++;
            break;
        case LDNS_RCODE_YXRRSET:
            stats.yxrrset++;
            break;
        case LDNS_RCODE_NXRRSET:
            stats.nxrrset++;
            break;
        case LDNS_RCODE_NOTAUTH:
            stats.notauth++;
            break;
        case LDNS_RCODE_NOTZONE:
            stats.notzone++;
            break;
        default:
            stats.other++;
            break;
    }
    context->current_rate++;
#ifdef DEBUG
    fprintf(stdout, "DEBUG: Removing %s from hashtable. \n", lookup->domain);
#endif
    hashmapRemove(context->map, lookup->domain);
    free(lookup->domain);
    free(lookup);
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
        if (LDNS_STATUS_OK != ldns_wire2pkt(&packet, recvbuf, (size_t) num_received))
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

struct sockaddr_storage *str_to_addr(char *str)
{
    if(str == NULL || str[0] == 0)
    {
        return NULL;
    }
    sockaddr_in_t *ip4addr = safe_calloc(sizeof(*ip4addr));
    sockaddr_in6_t *ip6addr = safe_calloc(sizeof(*ip6addr));
    if (inet_pton(AF_INET, str, &ip4addr->sin_addr) == 1)
    {
        ip4addr->sin_port = htons(53);
        ip4addr->sin_family = AF_INET;
        free(ip6addr);
        return (struct sockaddr_storage *) ip4addr;
    }
    else if (inet_pton(AF_INET6, str, &ip6addr->sin6_addr) == 1)
    {
        ip6addr->sin6_port = htons(53);
        ip6addr->sin6_family = AF_INET6;
        free(ip4addr);
        return (struct sockaddr_storage *) ip6addr;
    }
    else
    {
        char *closing_square_bracket = strstr(str, "]");
        if(closing_square_bracket && str[0] == '[')
        {
            char *colon = strstr(closing_square_bracket, ":");
            *closing_square_bracket = 0;
            if(colon)
            {
                *colon = 0;
                if (inet_pton(AF_INET6, str + 1, &ip6addr->sin6_addr) == 1)
                {
                    int port = atoi(colon + 1);
                    if (port == 0 || port > 0xFFFF)
                    {
                        goto str_to_addr_error;
                    }
                    ip6addr->sin6_port = htons((uint16_t) port);
                    ip6addr->sin6_family = AF_INET6;
                    free(ip4addr);
                    return (struct sockaddr_storage *) ip6addr;
                }
            }
        }
        else
        {
            char *colon = strstr(str, ":");
            if (colon)
            {
                *colon = 0;
                if (inet_pton(AF_INET, str, &ip4addr->sin_addr) == 1)
                {
                    int port = atoi(colon + 1);
                    if (port == 0 || port > 0xFFFF)
                    {
                        goto str_to_addr_error;
                    }
                    ip4addr->sin_port = htons((uint16_t) port);
                    ip4addr->sin_family = AF_INET;
                    free(ip6addr);
                    return (struct sockaddr_storage *) ip4addr;
                }
            }
        }
        str_to_addr_error:
        free(ip4addr);
        free(ip6addr);
        return NULL;
    }
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
    single_list_t *list = single_list_new();
    while (!feof(f))
    {
        if (0 <= getline(&line, &line_buflen, f))
        {
            trim_end(line);
            struct sockaddr_storage *addr = str_to_addr(line);
            if (addr != NULL)
            {
                single_list_push_back(list, addr);
            }
            else
            {
                fprintf(stderr, "\"%s\" is not a valid resolver. Skipped.\n", line);
            }
        }
        free(line);
        line = NULL;
    }
    fclose(f);
    buffer_t resolvers = single_list_to_array(list);
    single_list_free(list);
    return resolvers;
}

struct sockaddr_storage *massdns_get_resolver(size_t index, buffer_t *resolvers)
{
    return ((struct sockaddr_storage **) resolvers->data)[index % resolvers->len];
}

bool handle_domain(void *k, void *l, void *c)
{
    lookup_t *lookup = (lookup_t *) l;
    massdns_context_t *context = (massdns_context_t *) c;
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
        if (LDNS_STATUS_OK !=
            ldns_pkt_query_new_frm_str(&packet, lookup->domain, context->cmd_args.record_types, LDNS_RR_CLASS_IN,
                                       query_flags))
        {
#ifdef DEBUG
            fprintf(stdout, "ERROR: new query from string fail for domain %s , skipping... \n", lookup->domain);
#endif
            // TODO: I do not think we have to free *packet, validate
            hashmapRemove(context->map, lookup->domain);
            return true;
        }
        ldns_pkt_set_id(packet, lookup->transaction);
        uint8_t *buf = NULL;
        size_t packet_size = 0;
        if (LDNS_STATUS_OK != ldns_pkt2wire(&buf, packet, &packet_size))
        {
#ifdef DEBUG
            fprintf(stdout, "ERROR: pkt2wire fail, treating as timeout! \n");
#endif
            goto TIMEOUT;
        }
        ldns_pkt_free(packet);
        packet = NULL;
        struct sockaddr_storage *resolver = massdns_get_resolver((size_t) rand(), &context->resolvers);
        ssize_t n = -1;
        while (n < 0)
        {
            errno = 0;
            n = sendto(context->sock, buf, packet_size, 0, (sockaddr_t *) resolver, sizeof(*resolver));
            //if(n<1) perror("err sending");
#ifdef DEBUG
            if(n<1) fprintf(stdout,"DEBUG: Sending for domain %s failed with ret code %zu, retrying... \n",lookup->domain,n);
#endif
        }
        stats.qsent++;
        free(buf);
        TIMEOUT:; // label requires statement, hence empty statement
        unsigned int timeout_random_scale = 2; // 2 -> 50%
        long addusec = context->cmd_args.interval_ms * 1000 / timeout_random_scale;
        addusec += rand() % (addusec / timeout_random_scale); // Avoid congestion by adding some randomness
        //addusec += rand() % (addusec / 5); // Avoid congestion by adding some randomness
        lookup->next_lookup.tv_usec = (now.tv_usec + addusec) % 1000000;
        lookup->next_lookup.tv_sec = now.tv_sec + (now.tv_usec + addusec) / 1000000;
        timeout_stats[lookup->tries]++;
        lookup->tries++;
#ifdef DEBUG
        fprintf(stdout, "DEBUG: TIMEOUT #%2u for domain %s.\n", lookup->tries, lookup->domain);
#endif
        if (lookup->tries == context->cmd_args.resolve_count)
        {
#ifdef DEBUG
            fprintf(stdout, "ERROR: TIMEOUT: Final timeout for domain %s after %u tries with %u s interval. \n", lookup->domain, lookup->tries, context->cmd_args.interval_ms/1000);
#endif
            stats.timeout++;
            hashmapRemove(context->map, lookup->domain);
            free(lookup->domain);
            free(lookup);
        }
    }
    return true;
}

bool cmp_lookup(void *lookup1, void *lookup2)
{
    return strcasecmp((char *) lookup1, (char *) lookup2) == 0;
}

void massdns_scan(massdns_context_t *context)
{
    memset(&stats, 0, sizeof(dns_stats_t));
    size_t line_buflen = 4096;
    char *line = safe_malloc(line_buflen);
    size_t line_len = 0;
    int sock = socket(context->cmd_args.ip6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
    if (context->cmd_args.sndbuf && setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &context->cmd_args.sndbuf, sizeof(context->cmd_args.sndbuf)) != 0)
    {
        perror("Failed to adjust socket send buffer size.");
    }
    if (context->cmd_args.rcvbuf && setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &context->cmd_args.rcvbuf, sizeof(context->cmd_args.rcvbuf)) != 0)
    {
        perror("Failed to adjust socket receive buffer size.");
    }
    bind(sock, (sockaddr_t *) &context->server_addr, sizeof(context->server_addr));

    fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);

    if (sock < 0)
    {
        perror("Failed to create socket");
        exit(1);
    }
    FILE *f;
    if (context->stdin)
    {
        context->total_domains = 1; // this is only for stats, so a false value is ok
    }
    else if (context->cmd_args.show_progress)
    {
        f = fopen(context->cmd_args.domains, "r");
        if (f == NULL)
        {
            perror("Failed to open domain file");
            exit(1);
        }
        while (!feof(f))
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
    if (!context->stdin)
    {
        f = fopen(context->cmd_args.domains, "r");
        if (f == NULL)
        {
            perror("Failed to open domain file");
            exit(1);
        }
    }
    else
    {
        f = stdin;
    }
    if (geteuid() == 0)
    {
        if (!context->cmd_args.quiet)
        {
            fprintf(stderr, "You have started the program with root privileges.\n");
        }
        struct passwd *nobody = getpwnam(UNPRIVILEGED_USER);
        if (!context->cmd_args.root)
        {
            if (nobody && setuid(nobody->pw_uid) == 0)
            {
                if (!context->cmd_args.quiet)
                {
                    fprintf(stderr, "Privileges have been dropped to \"%s\" for security reasons.\n\n",
                            UNPRIVILEGED_USER);
                }
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

    if (context->resolvers.len == 0)
    {
        fprintf(stderr, "No valid resolver supplied. Exiting.\n");
        exit(1);
    }

    while (true)
    {
        while (hashmapSize(context->map) < context->cmd_args.hashmap_size && !feof(f))
        {
            if (0 <= getline(&line, &line_buflen, f))
            {
                trim_end(line);
                line_len = strlen(line);
                strtolower(line);
                if (strcmp(line, "") == 0)
                {
                    continue;
                }
                if (line_len > 0 && line[line_len - 1] == '.')
                {
                    // Remove trailing dot from FQDN
                    line[line_len-1] = '\0';
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
        if (!context->cooldown && hashmapSize(context->map) < context->cmd_args.hashmap_size)
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
    if(context->cmd_args.finalstats)
    {
        print_stats_final(context);
    }
    hashmapFree(context->map);
    context->map = NULL;
    if(f)
    {
        fclose(f);
    }
    if(randomness)
    {
        fclose(randomness);
    }
    if(context->outfile)
    {
        fclose(context->outfile);
    }
    if(context->logfile)
    {
        fclose(context->logfile);
    }
}


massdns_context_t ctx;

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
    massdns_context_t *context = &ctx;
    struct sockaddr_in *default_addr = (struct sockaddr_in*)&context->server_addr;
    default_addr->sin_family = AF_INET;
    default_addr->sin_addr.s_addr = INADDR_ANY;
    default_addr->sin_port = 0;
    context->cmd_args.resolve_count = 50;
    context->cmd_args.hashmap_size = 100000;
    context->cmd_args.interval_ms = 200;
    context->cmd_args.sndbuf = context->cmd_args.rcvbuf = 8 * 1024 * 1024;
    context->cooldown = false;
    context->stdin = false;
    context->total_domains = 0;
    context->outfile = stdout;
    module_init(&context->module);
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
        else if (strcmp(argv[i], "--bindto") == 0 || strcmp(argv[i], "-b") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "Missing address for socket binding.\n\n");
                print_help(argv[0]);
                return 1;
            }
            struct sockaddr_storage *server_addr = str_to_addr(argv[++i]);
            if (server_addr == NULL)
            {
                fprintf(stderr, "Invalid address for socket binding.\n\n");
                print_help(argv[0]);
                return 1;

            }
            context->server_addr = *server_addr;
            free(server_addr);
        }
        else if (strcmp(argv[i], "--module") == 0 || strcmp(argv[i], "-m") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "The argument -m requires a valid module.\n\n");
                print_help(argv[0]);
                return 1;
            }
            if(!module_load(&context->module, argv[++i]))
            {
                fprintf(stderr, "%s", dlerror());
                return 1;
            }
        }
        else if (strcmp(argv[i], "--outfile") == 0 || strcmp(argv[i], "-w") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "The argument -w requires a valid output file.\n\n");
                print_help(argv[0]);
                return 1;
            }
            char *filename = argv[++i];
            if(strcmp(filename, "-") == 0)
            {
                context->outfile = stdout;
            }
            else
            {
                context->outfile = fopen(filename, "w");
                if(!context->outfile)
                {
                    perror("Failed to open output file");
                    return 1;
                }
            }
        }
        else if (strcmp(argv[i], "--error-log") == 0 || strcmp(argv[i], "-l") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "The argument -l requires a valid log file.\n\n");
                print_help(argv[0]);
                return 1;
            }
            char *filename = argv[++i];
            if(strcmp(filename, "-") == 0)
            {
                context->logfile = stderr;
            }
            else
            {
                context->logfile = fopen(filename, "w");
                if(!context->logfile)
                {
                    perror("Failed to open log file");
                    return 1;
                }
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
        else if (strcmp(argv[i], "--finalstats") == 0)
        {
            context->cmd_args.finalstats = true;
        }
        else if (strcmp(argv[i], "--quiet") == 0 || strcmp(argv[i], "-q") == 0)
        {
            context->cmd_args.quiet = true;
        }
        else if (strcmp(argv[i], "-6") == 0)
        {
            context->cmd_args.ip6 = true;
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
        else if (strcmp(argv[i], "--sndbuf") == 0)
        {
            if (i + 1 >= argc || atoi(argv[i + 1]) < 0)
            {
                fprintf(stderr, "The send buffer size has to be a valid number larger than or equal to 0.\n\n");
                print_help(argv[0]);
                return 1;
            }
            context->cmd_args.sndbuf = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "--rcvbuf") == 0)
        {
            if (i + 1 >= argc || atoi(argv[i + 1]) < 0)
            {
                fprintf(stderr, "The receive buffer size has to be a valid number larger than or equal to 0.\n\n");
                print_help(argv[0]);
                return 1;
            }
            context->cmd_args.rcvbuf = atoi(argv[++i]);
        }
        else
        {
            if (context->cmd_args.domains == NULL)
            {
                if (strcmp(argv[i], "-") == 0)
                {
                    if (!context->cmd_args.quiet)
                    {
                        fprintf(stderr, "Reading domain list from stdin.\n");
                    }
                    context->stdin = true;
                }
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
    timeout_stats = safe_malloc(sizeof(unsigned int)*context->cmd_args.resolve_count);
    memset(timeout_stats,0,sizeof(unsigned int)*context->cmd_args.resolve_count);

    massdns_scan(context);
    return 0;
}
