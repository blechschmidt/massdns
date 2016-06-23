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

typedef struct stream_buffer
{
    void *data;
    size_t offset;
    size_t len;
    size_t capacity;
} stream_buffer_t;

void stream_buffer_free(stream_buffer_t *buf);

size_t stream_buffer_get_bytes_available(stream_buffer_t *buf);

void stream_buffer_print_ascii(stream_buffer_t *buf);

void stream_buffer_print(stream_buffer_t *buf);

void stream_buffer_has_read(stream_buffer_t *buf, size_t len);

void stream_buffer_has_appended(stream_buffer_t *buf, size_t len);

int stream_buffer_ensure_increase(stream_buffer_t *buf, size_t len);

void *stream_buffer_get_ptr(stream_buffer_t *buf);

void stream_buffer_init(stream_buffer_t *buf, size_t capacity);

#endif
