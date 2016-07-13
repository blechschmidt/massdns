#ifndef INC_SECURITY
#define INC_SECURITY

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

void *safe_malloc(size_t n)
{
    void *ptr = malloc(n);
    // Check for successful allocation, ensure that UDP packet and DNS
    // pointers (which are at max 0xFFFF bytes long) will not overflow
    if(ptr == NULL && n != 0)
    {
        fprintf(stderr, "Out of memory.\n");
        abort();
    }
    return ptr;
}
#endif

