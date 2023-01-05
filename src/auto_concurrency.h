// SPDX-License-Identifier: GPL-3.0-only

#ifndef MASSDNS_AUTO_CONCURRENCY_H
#define MASSDNS_AUTO_CONCURRENCY_H

#include "massdns.h"

typedef struct
{
    size_t current_concurrency;
    struct timespec last_update;
    size_t iteration;
    size_t last_numtimeouts;
    size_t last_domains;
} auto_concurrency_state_t;

auto_concurrency_state_t concurrency_state;

void init_concurrency_controller()
{
    bzero(&concurrency_state, sizeof(concurrency_state));
    concurrency_state.current_concurrency = context.cmd_args.auto_concurrency ? 32 : context.cmd_args.hashmap_size;
    clock_gettime(CLOCK_REALTIME, &concurrency_state.last_update);
}

/* Return 1 if a > b, -1 if a < b and 0 if a == b */
int timespec_compare(const struct timespec *a, const struct timespec *b)
{
    if (a->tv_sec == b->tv_sec && a->tv_nsec == b->tv_nsec)
    {
        return 0;
    }
    if (a->tv_sec != b->tv_sec)
    {
        return 2 * (a->tv_sec > b->tv_sec) - 1;
    }
    return 2 * (a->tv_nsec > b->tv_nsec) - 1;
}

void timespec_diff(const struct timespec *old, const struct timespec *now, struct timespec *result)
{
    result->tv_sec = now->tv_sec - old->tv_sec;
    if(result->tv_sec > 0 && now->tv_nsec >= old->tv_nsec)
    {
        result->tv_sec--;
    }
    result->tv_nsec = now->tv_nsec >= old->tv_nsec ?
                      now->tv_nsec - old->tv_nsec : (1000000000L - now->tv_nsec) + (1000000000L - old->tv_nsec);
}

bool elapsed_ms(const struct timespec *old, const struct timespec *now, size_t ms)
{
    struct timespec diff;
    timespec_diff(old, now, &diff);

    struct timespec ms_timespec = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000};
    if(timespec_compare(&diff, &ms_timespec) >= 0)
    {
        return true;
    }
    return false;
}

void auto_concurrency_handle(const struct timespec *now)
{
    if (!context.cmd_args.auto_concurrency)
    {
        return;
    }
    struct timespec new_now;
    if (now == NULL)
    {
        now = &new_now;
        clock_gettime(CLOCK_REALTIME, &new_now);
    }
    if (!elapsed_ms(&concurrency_state.last_update, now, context.cmd_args.interval_ms))
    {
        return;
    }
    concurrency_state.last_update = *now;

    size_t resolved_domains = context.stats.numdomains - concurrency_state.last_domains;

    if (resolved_domains > 0 && 100 * (context.stats.numtimeouts - concurrency_state.last_numtimeouts) / resolved_domains < 3)
    {
        concurrency_state.current_concurrency *= 2;
    }

    concurrency_state.last_domains = context.stats.numdomains;
    concurrency_state.last_numtimeouts = context.stats.numtimeouts;
}

#endif //MASSDNS_AUTO_CONCURRENCY_H
