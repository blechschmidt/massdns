#ifndef INC_BUFFERS
#define INC_BUFFERS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct buffer
{
    void *data;
    size_t len;
} buffer_t;

#endif
