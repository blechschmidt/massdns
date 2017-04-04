#ifndef MASSDNS_MASSDNS_H
#define MASSDNS_MASSDNS_H

#include "buffers.h"
#include "hashmap.h"

struct massdns_context;

typedef struct
{
    void (*handle_response)(struct massdns_context *context, ldns_pkt *packet, struct sockaddr_storage *server);
} massdns_module_t;

typedef struct massdns_context
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
    bool stdin;
    FILE *outfile;
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
        bool finalstats;
        bool quiet;
    } cmd_args;

    massdns_module_t module;
} massdns_context_t;

#endif // MASSDNS_MASSDNS_H