#ifndef INC_SECURITY
#define INC_SECURITY

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

/**
 * Safely allocate memory on the heap by aborting on failure.
 *
 * @param n The size of the memory block.
 * @return A pointer that points to the allocated block, NULL when requesting a block of zero bytes.
 */
void *safe_malloc(size_t n)
{
    if(n == 0)
    {
        return NULL;
    }
    void *ptr = malloc(n);
    // Check for successful allocation
    if(ptr == NULL)
    {
        perror("Memory allocation failed");
        abort();
    }
    return ptr;
}

void *safe_realloc(void *orig, size_t n)
{
    void *ptr = realloc(orig, n);
    // Check for successful allocation
    if(ptr == NULL)
    {
        perror("Memory allocation failed");
        abort();
    }
    return ptr;
}

/**
 * Safely allocate memory on the heap and initialize it with zeroes by aborting on failure.
 *
 * @param n The size of the memory block.
 * @return A pointer that points to the allocated block, NULL when requesting a block of zero bytes.
 */
void *safe_calloc(size_t n)
{
    if(n == 0)
    {
        return NULL;
    }
    void *ptr = calloc(n, 1);
    // Check for successful allocation
    if(ptr == NULL)
    {
        perror("Memory allocation failed");
        abort();
    }
    return ptr;
}

/**
 * Safely free a memory allocation on the heap at the cost of a NULL assignment. Aims to prevent double free attacks.
 *
 * Example:
 * char *x = malloc(10);
 * safe_free(&x); // x == NULL
 *
 * @param ptr A pointer to a pointer that has been obtained using (safe_)malloc.
 */
void safe_free(void **ptr)
{
    free(*ptr);
    *ptr = NULL;
}


#endif
