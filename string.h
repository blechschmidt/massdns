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

// JSON requires some escaping
// https://stackoverflow.com/users/10320/dreamlax
size_t string_escape(char *dst, const char *src, size_t dstLen)
{
    const char complexCharMap[] = "abtnvfr";

    size_t i;
    size_t srcLen = strlen(src);    
    size_t dstIdx = 0;

    if (dst == NULL || dstLen == 0) dstLen = SIZE_MAX;

    for (i = 0; i < srcLen && dstIdx < dstLen; i++)
    {
        size_t complexIdx = 0;

        switch (src[i])
        {
            case '\'':
            case '\"':
            case '\\':
                if (dst && dstIdx <= dstLen - 2)
                {
                    dst[dstIdx++] = '\\';
                    dst[dstIdx++] = src[i];
                }
                else dstIdx += 2;
                break;

            case '\r': complexIdx++;
            case '\f': complexIdx++;
            case '\v': complexIdx++;
            case '\n': complexIdx++;
            case '\t': complexIdx++;
            case '\b': complexIdx++;
            case '\a':
                if (dst && dstIdx <= dstLen - 2)
                {
                    dst[dstIdx++] = '\\';
                    dst[dstIdx++] = complexCharMap[complexIdx];
                }
                else dstIdx += 2;
                break;

            default:
                if (isprint(src[i]))
                {
                    // simply copy the character
                    if (dst)
                        dst[dstIdx++] = src[i];
                    else
                        dstIdx++;
                }
                else
                {
                    // produce octal escape sequence
                    if (dst && dstIdx <= dstLen - 4)
                    {
                        dst[dstIdx++] = '\\';
                        dst[dstIdx++] = ((src[i] & 0300) >> 6) + '0';
                        dst[dstIdx++] = ((src[i] & 0070) >> 3) + '0';
                        dst[dstIdx++] = ((src[i] & 0007) >> 0) + '0';
                    }
                    else
                    {
                        dstIdx += 4;
                    }
                }
        }
    }

    if (dst && dstIdx <= dstLen)
        dst[dstIdx] = '\0';

    return dstIdx;
}

#endif
