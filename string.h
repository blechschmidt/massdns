#ifndef INC_STRING
#define INC_STRING

#include "security.h"

#include <stdbool.h>
#include <strings.h>
#include <string.h>
#include <ctype.h>

char *strmcpy(const char *str)
{
    size_t len = strlen(str);
    char *result = safe_malloc(len + 1);
    memcpy(result, str, len);
    result[len] = 0;
    return result;
}

size_t string_copy(char *dest, const char *src, size_t n)
{
    size_t i;

    for (i = 0; i < n - 1 && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    dest[i] = 0;
    return i;
}

void *flatcopy(void *src, size_t len)
{
    void *dst = safe_malloc(len);
    memcpy(dst, src, len);
    return dst;
}

void strtolower(char *str)
{
    while (*str != '\0')
    {
        if (*str >= 'A' && *str <= 'Z')
        {
            *str = (char) (*str | (1 << 5));
        }
        str++;
    }
}

char *trim_start(char *str)
{
    while (0 != *str)
    {
        if(!isspace(*str))
        {
            return str;
        }
        str++;
    }
    return str;
}

void trim_end(char* str)
{
    char *last = str + strlen(str) - 1;
    while (last >= str)
    {
        if(!isspace(*last))
        {
            return;
        }
        *last = 0;
        last--;
    }
}

bool endswith(char* haystack, char* needle, bool case_sensitive)
{
    int (*cmp)(const char*, const char*) = strcmp;
    if(!case_sensitive)
    {
        cmp = strcasecmp;
    }
    size_t haystack_len = strlen(haystack);
    size_t needle_len = strlen(needle);
    return needle_len <= haystack_len && cmp(haystack + haystack_len - needle_len, needle) == 0;
}

bool startswith(char* haystack, char* needle, bool case_sensitive) // Supports ASCII only
{
    while(true)
    {
        char nchar = *needle++;
        char hchar = *haystack++;
        if(nchar == 0)
        {
            return true;
        }
        else if(hchar == 0)
        {
            return false;
        }
        if(case_sensitive)
        {
            nchar = (char)tolower(nchar);
            hchar = (char)tolower(hchar);
        }
        if(nchar != hchar)
        {
            return false;
        }
    }
}

// Buffer needs to have at least one byte.
size_t json_escape(char *dst, const char *src, size_t dst_len)
{
#define require_space(N) if(dst_idx >= dst_len - (N)) goto json_escape_finalize;
    const char complex_chars[] = "abtnvfr";
    size_t dst_idx = 0;

    for(size_t i = 0; src[i] != 0; i++)
    {
        size_t complex_idx = 0;
        switch(src[i])
        {
            case '\\':
            case '\"':
                require_space(2);
                dst[dst_idx++] = '\\';
                dst[dst_idx++] = src[i];
                break;
            case '\r': complex_idx++;
            case '\f': complex_idx++;
            case '\v': complex_idx++;
            case '\n': complex_idx++;
            case '\t': complex_idx++;
            case '\b': complex_idx++;
            case '\a':
                require_space(2);
                dst[dst_idx++] = '\\';
                dst[dst_idx++] = complex_chars[complex_idx];
                break;
            default:
                if(isprint(src[i]))
                {
                    require_space(1);
                    dst[dst_idx++] = src[i];
                }
                else
                {
                    require_space(4);
                    dst[dst_idx++] = '\\';
                    dst[dst_idx++] = ((src[i] & 0300) >> 6) + '0';
                    dst[dst_idx++] = ((src[i] & 0070) >> 3) + '0';
                    dst[dst_idx++] = ((src[i] & 0007) >> 0) + '0';
                }
                break;
        }
    }
#undef require_space
json_escape_finalize:
    dst[dst_idx++] = 0;
    return dst_idx;
}

#endif
