#ifndef MASSRESOLVER_RANDOM_H
#define MASSRESOLVER_RANDOM_H

#include <stdio.h>
#include <stdbool.h>

static FILE *randomness;

bool urandom_init()
{
    randomness = fopen("/dev/urandom", "r");
    return randomness != NULL;
}

void urandom_get(void *dst, size_t len)
{
    size_t read = 0;
    while(read < len)
    {
        read += fread(dst, len - read, 1, randomness);
    }
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
