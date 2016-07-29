#ifndef INC_SECURITY
#define INC_SECURITY

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

void *safe_malloc(size_t n)
{
    void *ptr = malloc(n);
    // Check for successful allocation
    if(n != 0 && ptr == NULL)
    {
        fprintf(stderr, "Out of memory.\n");
        abort();
    }
    return ptr;
}

void *safe_calloc(size_t n)
{
    void *ptr = calloc(n, 1);
    // Check for successful allocation
    if(n != 0 && ptr == NULL)
    {
        fprintf(stderr, "Out of memory.\n");
        abort();
    }
    return ptr;
}
#endif
