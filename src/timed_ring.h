#ifndef MASSRESOLVER_TIMED_RING_H
#define MASSRESOLVER_TIMED_RING_H

#include <time.h>
#include <stdint.h>

#include "hashmap.h"
#include "security.h"
#include "list.h"

// The timed ring is a circular buffer allowing to efficiently process time-based events with a certain precision.

#define TIMED_RING_S 1000000000
#define TIMED_RING_MS 1000000
#define TIMED_RING_US 1000
#define TIMED_RING_NS 1

typedef struct
{
    void **data;
    size_t count;
    single_list_t following; // entries exceeding the bucket capacity
} timed_ring_bucket_t;

typedef struct {
    size_t bucket_count; // number of buckets
    size_t precision; // number of nanoseconds per bucket
    struct timespec last_time;
    size_t bucket_capacity;
    size_t next_bucket; // The index of the bucket that is supposed to be executed next.
    timed_ring_bucket_t *buckets;
    bool efficient;
} timed_ring_t;


// Initialize a timed ring with a time span of bucket_count * precision
void timed_ring_init(timed_ring_t* ring, size_t bucket_count, size_t precision, size_t bucket_capacity)
{
    assert(bucket_capacity != 0);
    assert(1000000000 % precision == 0);
    ring->bucket_count = bucket_count;
    ring->precision = precision;
    ring->bucket_capacity = bucket_capacity;
    ring->buckets = safe_malloc(sizeof(*ring->buckets) * ring->bucket_count);
    ring->next_bucket = 0;
    ring->efficient = false;
    for(size_t i = 0; i < ring->bucket_count; i++)
    {
        ring->buckets[i].count = 0;
        single_list_init(&ring->buckets[i].following);
        ring->buckets[i].data = safe_malloc(sizeof(void*) * bucket_capacity);
    }
    clock_gettime(CLOCK_MONOTONIC, &ring->last_time);
    ring->last_time.tv_nsec = (ring->last_time.tv_nsec / precision) * precision;
}

void timed_ring_clear(timed_ring_t* ring)
{
    for(size_t i = 0; i < ring->bucket_count; i++)
    {
        ring->buckets[i].count = 0;
        single_list_clear(&ring->buckets[i].following);
    }
}

void timed_ring_destroy(timed_ring_t* ring)
{
    if(!ring || !ring->buckets)
    {
        return;
    }
    for(size_t i = 0; i < ring->bucket_count; i++)
    {
        single_list_clear(&ring->buckets[i].following);
        free(ring->buckets[i].data);
    }
    free(ring->buckets);
}

void timed_ring_remove(timed_ring_t *ring, void **add_ptr)
{
    *add_ptr = NULL;
}

void **timed_ring_add(timed_ring_t *ring, time_t in, void *ptr)
{
    struct timespec expiry;
    clock_gettime(CLOCK_MONOTONIC, &expiry);
    expiry.tv_nsec += in;
    expiry.tv_sec += expiry.tv_nsec / 1000000000;
    expiry.tv_nsec %= 1000000000;
    expiry.tv_nsec = (expiry.tv_nsec / ring->precision) * ring->precision;
    time_t elapsed_ns = (expiry.tv_sec - ring->last_time.tv_sec) * 1000000000 + (expiry.tv_nsec - ring->last_time.tv_nsec);
    size_t elapsed_buckets = elapsed_ns / ring->precision;
    elapsed_buckets = min(ring->bucket_count - 1, elapsed_buckets);
    size_t bucket = (ring->next_bucket + elapsed_buckets) % ring->bucket_count;
    if(ring->buckets[bucket].count < ring->bucket_capacity)
    {
        ring->buckets[bucket].data[ring->buckets[bucket].count] = ptr;
        return &ring->buckets[bucket].data[ring->buckets[bucket].count++];
    }
    else
    {
        ring->buckets[bucket].count++;
        return &single_list_push_back(&ring->buckets[bucket].following, ptr)->data;
    }
}

static inline void timed_ring_handle_helper(timed_ring_t *ring, timed_ring_bucket_t *bucket, void (*callback)(void*))
{
    // Copy everything because the callback function might add another entry to the same bucket
    // This is an important limitation that needs to be considered:
    // Re-adding more than one event to the ring per callback call might result in an endless loop.
    single_list_t iter_list = bucket->following;
    single_list_init(&bucket->following);
    size_t count = min(bucket->count, ring->bucket_capacity);
    bucket->count = 0;

    for(size_t j = 0; j < count; j++)
    {
        if(bucket->data[j] != NULL)
        {
            callback(bucket->data[j]);
        }
    }
    single_list_foreach_free(iter_list, elm)
    {
        if(elm->data != NULL)
        {
            callback(elm->data);
        }
    }
}

void timed_ring_handle(timed_ring_t *ring, void (*callback)(void*))
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    now.tv_nsec = (now.tv_nsec / ring->precision) * ring->precision;
    time_t elapsed_ns = (now.tv_sec - ring->last_time.tv_sec) * 1000000000 + (now.tv_nsec - ring->last_time.tv_nsec);
    size_t elapsed_buckets = elapsed_ns / ring->precision;
    elapsed_buckets = min(ring->bucket_count, elapsed_buckets);

    for(size_t i = 0; i < elapsed_buckets; i++)
    {
        timed_ring_handle_helper(ring, &ring->buckets[(ring->next_bucket + i) % ring->bucket_count], callback);
    }
    ring->next_bucket = (ring->next_bucket + elapsed_buckets) % ring->bucket_count;
    ring->last_time = now;
}


#endif //MASSRESOLVER_TIMED_RING_H
