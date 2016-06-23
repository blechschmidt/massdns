#ifndef INC_STRING
#define INC_STRING

#include <stdbool.h>
#include <strings.h>

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

void trim_end(char* str)
{
    while (0 != *str)
    {
        if(*str == ' ' || *str == '\n' || *str == '\t' || *str == '\r')
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
#endif
