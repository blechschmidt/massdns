// SPDX-License-Identifier: GPL-3.0-only

#ifndef MASSDNS_MASSDNS_H
#define MASSDNS_MASSDNS_H

#include <stdint.h>
#include <time.h>
#include <sys/socket.h>
#ifdef HAVE_EPOLL
    #include <sys/epoll.h>
#endif
#include <netinet/in.h>
#include <arpa/inet.h>
//#define PCAP_SUPPORT
#ifdef PCAP_SUPPORT
#include <pcap.h>
#endif

#include "list.h"
#include "net.h"
#include "hashmap.h"
#include "dns.h"
#include "timed_ring.h"
#include "tcp.h"

#define COMMON_UNPRIVILEGED_USER "nobody"
#define COMMON_UNPRIVILEGED_GROUP "nogroup"

#define LOG_DEBUG 0
#define LOG_INFO 1
#define LOG_WARN 2
#define LOG_ERROR 3

#define LOGLEVEL LOG_WARN

const uint32_t OUTPUT_BINARY_VERSION = 0x00;

typedef struct
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
    size_t numreplies;
    size_t fakereplies; // used for resolver plausibility checks (wrong records)
} resolver_stats_t;

typedef struct {
    size_t fork_index;
    size_t numdomains;
    size_t numreplies;
    size_t finished;
    size_t finished_success;
    size_t mismatch_domain;
    size_t mismatch_id;
    size_t timeouts[0x100];
    size_t all_rcodes[5];
    size_t final_rcodes[5];
    size_t current_rate;
    size_t success_rate;
    size_t numparsed;
    bool done;
} stats_exchange_t;

typedef struct
{
    struct sockaddr_storage address;
    resolver_stats_t stats; // To be used to track resolver bans or non-replying resolvers
    struct sockaddr_storage source_addr; // The source address to be used by raw sockets
    uint16_t next_src_port;
} resolver_t;

typedef struct {
    size_t len;
    size_t ref_count;
    resolver_t resolvers[];
} dedicated_resolvers_t;

typedef struct
{
    dns_name_t name;
    dns_record_type type;
} lookup_key_t;

typedef struct
{
    unsigned char tries;
    uint16_t transaction;
    void **ring_entry; // pointer to the entry within the timed ring for entry invalidation
    resolver_t *resolver;
    dedicated_resolvers_t *dedicated_resolvers;
    size_t dedicated_resolver_index;
    lookup_key_t key;
    socket_info_t *socket;
    bool use_tcp;
    socket_info_t tcp_socket;
    struct {
        uint8_t *buffer;
        size_t received;
        struct sockaddr_storage src_addr;
        uint32_t ack;
        tcp_data_tracker_t *window_tracker;
        bool terminated;
    } tcp_state;
    size_t count;
} lookup_t;

typedef enum
{
    STATE_WARMUP, // Before the hash map size has been reached
    STATE_QUERYING,
    STATE_COOLDOWN,
    STATE_WAIT_CHILDREN,
    STATE_DONE
} state_t;

typedef enum
{
    OUTPUT_TEXT_FULL,
    OUTPUT_TEXT_SIMPLE,
    OUTPUT_BINARY,
    OUTPUT_LIST,
    OUTPUT_NDJSON
} output_t;

typedef enum
{
    LOOKUP_FAILURE_TIMEOUT,
    LOOKUP_FAILURE_MAXRETRIES,
    LOOKUP_FAILURE_NOFAILURE
} lookup_failure_reason_t;

const char *lookup_failure_text[] = {
        "TIMEOUT",
        "MAXRETRIES",
        "IF YOU SEE THIS IN MASSDNS OUTPUT, FILE A BUG REPORT"
};

typedef enum {
    FILTER_DISABLED = 0,
    FILTER_POSITIVE,
    FILTER_NEGATIVE
} filter_mode_t;

typedef struct {
    const char *name;
    const char *status_fmt;
} status_format_map_t;

const char *default_interfaces[] = {""};

typedef struct
{
    buffer_t resolvers;
    lookup_t *lookup_space;
    buffer_t lookup_pool;
    Hashmap *resolver_map;

    struct
    {
        bool sections[4];
        bool match_name;
        bool ttl;
        bool separate_queries;
        bool separate_sections;
        bool include_meta;
        bool indent_sections;
        bool print_question;
        bool write_exhausted_tries;
        bool list_write_zero_answers;
        bool only_with_answers_or_referrals;
        bool sections_explicit;
    } format;

    struct cmd_args
    {
        bool root;
        bool verify_ip;
        char *resolvers;
        char *domains;
        char *outfile_name;
        uint8_t resolve_count;
        size_t hashmap_size;
        unsigned int interval_ms;
        bool norecurse;
        bool quiet;
        int sndbuf;
        int rcvbuf;
        char *drop_user;
        char *drop_group;
        dns_record_type *record_types;
        size_t record_type_count;
        size_t record_type_index;
        size_t timed_ring_buckets;
        output_t output;
        bool retry_codes[0xFFFF]; // Fast lookup map for DNS reply codes that are unacceptable and require a retry
        bool retry_codes_set;
        bool filter_codes[0xFFFF];
        filter_mode_t filter_mode;
        single_list_t bind_addrs4;
        single_list_t bind_addrs6;
        bool sticky;
        int argc;
        char **argv;
        void (*help_function)();
        bool flush;
        bool predictable_resolver;
        size_t num_processes;
        size_t socket_count;
        bool busypoll;
        bool extended_input;
        bool auto_concurrency;
        bool tcp_enabled;
        bool tcp_only;
        bool tcp_raw;
    } cmd_args;

    struct
    {
        buffer_t interfaces4; // Sockets used for receiving queries
        buffer_t interfaces6; // Sockets used for receiving queries
        buffer_t raw_send4;
        buffer_t raw_send6;
        buffer_t raw_receive;
        int *pipes;
        socket_info_t write_pipe;
        socket_info_t *master_pipes_read;
    } sockets;

    // Processes
    size_t finished;
    pid_t *pids;
    bool *done;
    const char *status_fmt;
    FILE* outfile;
    FILE* logfile;
    FILE* domainfile;
    ssize_t domainfile_size;
    int epollfd;
    Hashmap *map;
    state_t state;
    timed_ring_t ring; // handles timeouts
    size_t lookup_index;
    size_t fork_index;
    struct {
        bool enabled;
        struct sockaddr_storage src_range;
    } srcrand;
    struct
    {
        struct timespec start_time;
        size_t mismatch;
        size_t other;
        size_t qsent;
        size_t numreplies;
        size_t numparsed;
        size_t numdomains;
        size_t numtimeouts;
        struct timespec last_print;
        size_t current_rate;
        size_t success_rate;
        size_t timeouts[0x100];
        size_t final_rcodes[0x10000];
        size_t all_rcodes[0x10000];
        size_t finished;
        size_t finished_success;
        size_t mismatch_id;
        size_t mismatch_domain;
    } stats;

    stats_exchange_t *stat_messages;
#ifdef PCAP_SUPPORT
    pcap_t *pcap;
    char pcap_error[PCAP_ERRBUF_SIZE];
    char *pcap_dev;
    socket_info_t pcap_info;
    uint16_t ether_type_ip;
    uint16_t ether_type_ip6;
    struct bpf_program pcap_filter;
#endif
} massdns_context_t;

massdns_context_t context;

#endif //MASSDNS_MASSDNS_H
