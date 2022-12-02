// SPDX-License-Identifier: GPL-3.0-only

#ifndef MASSRESOLVER_RANDOM_H
#define MASSRESOLVER_RANDOM_H

#include <stdio.h>
#include <stdbool.h>

static FILE *randomness;

uint64_t wyhash64_x; /* The state can be seeded with any value. */

// call wyhash64_seed before calling wyhash64
static inline void wyhash64_seed(uint64_t seed) { wyhash64_x = seed; }

static inline uint64_t wyhash64_stateless(uint64_t *seed) {
    *seed += UINT64_C(0x60bee2bee120fc15);
    __uint128_t tmp;
    tmp = (__uint128_t)*seed * UINT64_C(0xa3b195354a39b70d);
    uint64_t m1 = (tmp >> 64) ^ tmp;
    tmp = (__uint128_t)m1 * UINT64_C(0x1b03738712fad5c9);
    uint64_t m2 = (tmp >> 64) ^ tmp;
    return m2;
}

// returns random number, modifies wyhash64_x
static inline uint64_t wyhash64(void) { return wyhash64_stateless(&wyhash64_x); }

bool urandom_init()
{
    wyhash64_seed(time(NULL) ^ ((uint64_t)getpid() << 32));
    return true;
}

void urandom_get(void *dst, size_t len)
{
    size_t written = 0;
    while(written + sizeof(uint64_t) <= len)
    {
        uint64_t num = wyhash64();
        *((uint64_t*)(((uint8_t*)dst) + written)) = num;
        written += sizeof(num);
    }
    uint64_t num = wyhash64();
    memcpy(((uint8_t*)dst) + written, &num, len - written);
}

size_t urandom_size_t()
{
    size_t result;
    urandom_get(&result, sizeof(result));
    return result;
}

int urandom_close()
{
    if(!randomness)
    {
        return 0;
    }
    return fclose(randomness);
}

#endif //MASSRESOLVER_RANDOM_H
