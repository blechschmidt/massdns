#ifndef INC_FAST_BUFFER
  #define INC_FAST_BUFFER

  // SECURITY IMPROVEMENTS REQUIRED. VULNERABLE TO INTEGER AND BUFFER OVERFLOWS.

  #include <string.h>
  #include <stdlib.h>
  #include <stdio.h>
  #include "buffers.h"

  void stream_buffer_init(stream_buffer_t* buf, size_t capacity)
  {
    buf->data = malloc(capacity);
    if(buf->data == NULL)
    {
      //security_exit(SECURITY_FAILURE_MALLOC);
    }
    buf->len = 0;
    buf->capacity = capacity;
    buf->offset = 0;
  }

  void* stream_buffer_get_ptr(stream_buffer_t* buf)
  {
    return ((char*)buf->data) + buf->offset;
  }

  int stream_buffer_ensure_increase(stream_buffer_t* buf, size_t len)
  {
    /*if(buf->len + len > buf->capacity)
    {
      buf->capacity *= 2;
      if(buf->len + len > buf->capacity)
      {
        buf->capacity = (buf->len + len) * 2;
      }
      if(buf->capacity == 0)
      {
        buf->capacity = 1;
      }
      */
      if(buf->len + len > buf->capacity)
      {
        buf->capacity = buf->len + len;
        buf->data = realloc(buf->data, buf->len + len);
        if(buf->data == NULL)
        {
          //security_exit(SECURITY_FAILURE_MALLOC);
        }
      }

  }

  /*void stream_buffer_append(stream_buffer_t* buf, void* data, size_t len)
  {
    stream_buffer_ensure_increase(buf, len);
    memcpy(((char*)buf->data) + len, data, len);
    buf->len += len;
  }*/

  void stream_buffer_has_appended(stream_buffer_t* buf, size_t len)
  {
    //stream_buffer_append(buf, NULL, len);
    buf->len += len;
  }

  void stream_buffer_has_read(stream_buffer_t* buf, size_t len)
  {
    buf->offset += len;
    if(buf->offset >= buf->len)
    {
      buf->offset = 0;
      buf->len = 0;
    }
  }

  void stream_buffer_print(stream_buffer_t* buf)
  {
    for(size_t i = buf->offset; i < buf->len; i++)
    {
      printf("0x%x ", ((char*)buf->data)[i]);
    }
    printf("\n");
  }

  void stream_buffer_print_ascii(stream_buffer_t* buf)
  {
    if(buf->offset < buf->len && buf->len > 0)
    {
      fwrite(((char*)buf->data) + buf->offset, buf->len - buf->offset, 1, stdout);
      printf("\n");
    }
  }

  /*void* stream_buffer_read(stream_buffer_t* buf, size_t len)
  {
    char* ptr = (char*)buf->data;
    ptr += len;
    if(len - buf->offset < buf->capacity / 3)
    {
      buf->capacity = 2 * (buf.>len - buf->offset);


      //buf->data = realloc(buf->data, buf->capacity);
      if(buf->data == NULL)
      {
        security_exit(SECURITY_FAILURE_MALLOC);
      }
    }
    return ptr;
  }*/

  size_t stream_buffer_get_bytes_available(stream_buffer_t* buf)
  {
    return buf->len - buf->offset;
  }

  void stream_buffer_free(stream_buffer_t* buf)
  {
    free(buf->data);
    buf->len = 0;
    buf->capacity = 0;
    buf->data = NULL;
    buf->offset = 0;
  }
#endif
