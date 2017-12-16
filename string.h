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
    while (0 != *str)
    {
        if(isspace(*str))
        {
            *str = 0;
            return;
        }
        str++;
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

#endif
