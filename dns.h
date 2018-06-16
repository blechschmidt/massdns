#ifndef MASSRESOLVER_DNS_H
#define MASSRESOLVER_DNS_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <strings.h>
#include <string.h>
#include <inttypes.h>
#include <ctype.h>

#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))
#define elements(a) (sizeof(a) / sizeof((a)[0]))

typedef enum
{
    DNS_REC_INVALID = -1, // Error code

    DNS_REC_A = 1,
    DNS_REC_AAAA = 28,
    DNS_REC_AFSDB = 18,
    DNS_REC_ANY = 255,
    DNS_REC_APL = 42,
    DNS_REC_CAA = 257,
    DNS_REC_CDNSKEY = 60,
    DNS_REC_CDS = 59,
    DNS_REC_CERT = 37,
    DNS_REC_CNAME = 5,
    DNS_REC_DHCID = 49,
    DNS_REC_DLV = 32769,
    DNS_REC_DNAME = 39,
    DNS_REC_DNSKEY = 48,
    DNS_REC_DS = 43,
    DNS_REC_HIP = 55,
    DNS_REC_IPSECKEY = 45,
    DNS_REC_KEY = 25,
    DNS_REC_KX = 36,
    DNS_REC_LOC = 29,
    DNS_REC_MX = 15,
    DNS_REC_NAPTR = 35,
    DNS_REC_NS = 2,
    DNS_REC_NSEC = 47,
    DNS_REC_NSEC3 = 50,
    DNS_REC_NSEC3PARAM = 51,
    DNS_REC_OPENPGPKEY = 61,
    DNS_REC_PTR = 12,
    DNS_REC_RP = 17,
    DNS_REC_RRSIG = 46,
    DNS_REC_SIG = 24,
    DNS_REC_SOA = 6,
    DNS_REC_SRV = 33,
    DNS_REC_SSHFP = 44,
    DNS_REC_TA = 32768,
    DNS_REC_TKEY = 249,
    DNS_REC_TLSA = 52,
    DNS_REC_TSIG = 250,
    DNS_REC_TXT = 16,
    DNS_REC_URI = 256
} dns_record_type;

typedef enum
{
    DNS_SECTION_QUESTION = 0,
    DNS_SECTION_ANSWER = 1,
    DNS_SECTION_AUTHORITY = 2,
    DNS_SECTION_ADDITIONAL = 3
} dns_section_t;

dns_record_type dns_str_to_record_type(const char *str)
{
    // Performance is important here because we may want to use this when reading
    // large numbers of DNS queries from a file.

    switch (tolower(str[0]))
    {
        case 'a':
            switch (tolower(str[1]))
            {
                case 0:
                    return DNS_REC_A;
                case 'a':
                    if (tolower(str[2]) == 'a' && tolower(str[3]) == 'a' && str[4] == 0)
                    {
                        return DNS_REC_AAAA;
                    }
                    return DNS_REC_INVALID;
                case 'f':
                    if (tolower(str[2]) == 's' && tolower(str[3]) == 'd' && tolower(str[4]) == 'b' && str[5] == 0)
                    {
                        return DNS_REC_AFSDB;
                    }
                    return DNS_REC_INVALID;
                case 'n':
                    if (tolower(str[2]) == 'y' && str[3] == 0)
                    {
                        return DNS_REC_ANY;
                    }
                    return DNS_REC_INVALID;
                case 'p':
                    if (tolower(str[2]) == 'l' && str[3] == 0)
                    {
                        return DNS_REC_APL;
                    }
                    return DNS_REC_INVALID;
                default:
                    return DNS_REC_INVALID;
            }
        case 'c':
            switch (tolower(str[1]))
            {
                case 'a':
                    if (tolower(str[2]) == 'a' && str[3] == 0)
                    {
                        return DNS_REC_CAA;
                    }
                    return DNS_REC_INVALID;
                case 'd':
                    switch(tolower(str[2]))
                    {
                        case 's':
                            if(str[3] == 0)
                            {
                                return DNS_REC_CDS;
                            }
                            return DNS_REC_INVALID;
                        case 'n':
                            if(tolower(str[3]) == 's' && tolower(str[4]) == 'k' && tolower(str[5]) == 'e'
                                && tolower(str[6]) == 'y' && str[7] == 0)
                            {
                                return DNS_REC_CDNSKEY;
                            }
                        default:
                            return DNS_REC_INVALID;
                    }
                case 'e':
                    if(tolower(str[2]) == 'r' && tolower(str[3]) == 't' && str[4] == 0)
                    {
                        return DNS_REC_CERT;
                    }
                    return DNS_REC_INVALID;
                case 'n':
                    if(tolower(str[2]) == 'a' && tolower(str[3]) == 'm' && tolower(str[4]) == 'e' && str[5] == 0)
                    {
                        return DNS_REC_CNAME;
                    }
                    return DNS_REC_INVALID;
                default:
                    return DNS_REC_INVALID;
            }
        case 'd':
            switch (tolower(str[1]))
            {
                case 'h':
                    if(tolower(str[2]) == 'c' && tolower(str[3]) == 'i' && tolower(str[4]) == 'd' && str[5] == 0)
                    {
                        return DNS_REC_DHCID;
                    }
                    return DNS_REC_INVALID;
                case 'l':
                    if(tolower(str[2]) == 'v' && str[3] == 0)
                    {
                        return DNS_REC_DLV;
                    }
                    return DNS_REC_INVALID;
                case 'n':
                    switch(tolower(str[2]))
                    {
                        case 'a':
                            if(tolower(str[3]) == 'm' && tolower(str[4]) == 'e' && str[5] == 0)
                            {
                                return DNS_REC_DNAME;
                            }
                            return DNS_REC_INVALID;
                        case 's':
                            if(tolower(str[3]) == 'k' && tolower(str[4]) == 'e' && tolower(str[5]) == 'y' && str[6] == 0)
                            {
                                return DNS_REC_DNSKEY;
                            }
                            return DNS_REC_INVALID;
                        default:
                            return DNS_REC_INVALID;
                    }
                case 's':
                    if(str[2] == 0)
                    {
                        return DNS_REC_DS;
                    }
                    return DNS_REC_INVALID;
                default:
                    return DNS_REC_INVALID;
            }
        case 'h':
            if (tolower(str[1]) == 'i' && tolower(str[2]) == 'p' && str[3] == 0)
            {
                return DNS_REC_HIP;
            }
            return DNS_REC_INVALID;
        case 'i':
            if (tolower(str[1]) == 'p' && tolower(str[2]) == 's' && tolower(str[3]) == 'e' && tolower(str[4]) == 'c'
                && tolower(str[5]) == 'k' && tolower(str[6]) == 'e' && tolower(str[7]) == 'y' && str[8] == 0)
            {
                return DNS_REC_IPSECKEY;
            }
            return DNS_REC_INVALID;
        case 'k':
            switch(tolower(str[1]))
            {
                case 'e':
                    if (tolower(str[2]) == 'y' && str[3] == 0)
                    {
                        return DNS_REC_KEY;
                    }
                    return DNS_REC_INVALID;
                case 'x':
                    if (str[2] == 0)
                    {
                        return DNS_REC_KX;
                    }
                    return DNS_REC_INVALID;
                default:
                    return DNS_REC_INVALID;
            }
        case 'l':
            if (tolower(str[1]) == 'o' && tolower(str[2]) == 'c' && str[3] == 0)
            {
                return DNS_REC_LOC;
            }
            return DNS_REC_INVALID;
        case 'm':
            if (tolower(str[1]) == 'x' && str[2] == 0)
            {
                return DNS_REC_MX;
            }
            return DNS_REC_INVALID;
        case 'n':
            switch(tolower(str[1]))
            {
                case 'a':
                    if (tolower(str[2]) == 'p' && tolower(str[3]) == 't' && tolower(str[4]) == 'r' && str[5] == 0)
                    {
                        return DNS_REC_NAPTR;
                    }
                    return DNS_REC_INVALID;
                case 's':
                    switch(tolower(str[2]))
                    {
                        case 0:
                            return DNS_REC_NS;
                        case 'e':
                            if(tolower(str[3]) == 'c')
                            {
                                switch(tolower(str[4]))
                                {
                                    case 0:
                                        return DNS_REC_NSEC;
                                    case '3':
                                        if(str[5] == 0)
                                        {
                                            return DNS_REC_NSEC3;
                                        }
                                        if(tolower(str[5]) == 'p' && tolower(str[6]) == 'a' && tolower(str[7]) == 'r'
                                            && tolower(str[8]) == 'a' && tolower(str[9]) == 'm' && str[10] == 0)
                                        {
                                            return DNS_REC_NSEC3PARAM;
                                        }
                                        return DNS_REC_INVALID;
                                    default:
                                        return DNS_REC_INVALID;
                                }
                            }
                            return DNS_REC_INVALID;
                        default:
                            return DNS_REC_INVALID;
                    }
                default:
                    return DNS_REC_INVALID;
            }
        case 'o':
            if (tolower(str[1]) == 'p' && tolower(str[2]) == 'e' && tolower(str[3]) == 'n' && tolower(str[4]) == 'p'
                && tolower(str[5]) == 'g' && tolower(str[6]) == 'p' && tolower(str[7]) == 'k' && tolower(str[8]) == 'e'
                && tolower(str[9]) == 'y' && str[10] == 0)
            {
                return DNS_REC_OPENPGPKEY;
            }
            return DNS_REC_INVALID;
        case 'p':
            if (tolower(str[1]) == 't' && tolower(str[2]) == 'r' && str[3] == 0)
            {
                return DNS_REC_PTR;
            }
            return DNS_REC_INVALID;
        case 'r':
            switch(tolower(str[1]))
            {
                case 'p':
                    if(str[2] == 0)
                    {
                        return DNS_REC_RP;
                    }
                    return DNS_REC_INVALID;
                case 'r':
                    if (tolower(str[2]) == 's' && tolower(str[3]) == 'i' && tolower(str[4]) == 'g' && str[5] == 0)
                    {
                        return DNS_REC_RRSIG;
                    }
                    return DNS_REC_INVALID;
                default:
                    return DNS_REC_INVALID;
            }
        case 's':
            switch (tolower(str[1]))
            {
                case 'i':
                    if (tolower(str[2]) == 'g' && tolower(str[3]) == 0)
                    {
                        return DNS_REC_SIG;
                    }
                    return DNS_REC_INVALID;
                case 'o':
                    if (tolower(str[2]) == 'a' && tolower(str[3]) == 0)
                    {
                        return DNS_REC_SOA;
                    }
                    return DNS_REC_INVALID;
                case 'r':
                    if (tolower(str[2]) == 'v' && tolower(str[3]) == 0)
                    {
                        return DNS_REC_SRV;
                    }
                    return DNS_REC_INVALID;
                case 's':
                    if (tolower(str[2]) == 'h' && tolower(str[3]) == 'f' && tolower(str[4]) == 'p' && str[5] == 0)
                    {
                        return DNS_REC_SSHFP;
                    }
                    return DNS_REC_INVALID;
                default:
                    return DNS_REC_INVALID;
            }
        case 't':
            switch (tolower(str[1]))
            {
                case 'a':
                    if(str[2] == 0)
                    {
                        return DNS_REC_TA;
                    }
                    return DNS_REC_INVALID;
                case 'k':
                    if (tolower(str[2]) == 'e' && tolower(str[3]) == 'y' && str[4] == 0)
                    {
                        return DNS_REC_TKEY;
                    }
                    return DNS_REC_INVALID;
                case 'l':
                    if (tolower(str[2]) == 's' && tolower(str[3]) == 'a' && str[4] == 0)
                    {
                        return DNS_REC_TLSA;
                    }
                    return DNS_REC_INVALID;
                case 's':
                    if (tolower(str[2]) == 'i' && tolower(str[3]) == 'g' && str[4] == 0)
                    {
                        return DNS_REC_TSIG;
                    }
                    return DNS_REC_INVALID;
                case 'x':
                    if (tolower(str[2]) == 't' && str[3] == 0)
                    {
                        return DNS_REC_TXT;
                    }
                    return DNS_REC_INVALID;
                default:
                    return DNS_REC_INVALID;
            }
        case 'u':
            switch (tolower(str[1]))
            {
                case 'r':
                    if (tolower(str[2]) == 'i' && str[3] == 0)
                    {
                        return DNS_REC_URI;
                    }
                    return DNS_REC_INVALID;
                default:
                    return DNS_REC_INVALID;
            }
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            return (dns_record_type)atoi(str);
        default:
            return DNS_REC_INVALID;
    }
}

typedef enum
{
    DNS_CLS_IN = 1,
    DNS_CLS_CH = 3,
    DNS_CLS_HS = 4,
    DNS_CLS_QCLASS_NONE = 254,
    DNS_CLS_QCLASS_ANY = 255
} dns_class;

#define DNS_RCODE_BADSIG DNS_RCODE_BADVERS

typedef enum
{
    DNS_RCODE_OK = 0,
    DNS_RCODE_FORMERR = 1,
    DNS_RCODE_SERVFAIL = 2,
    DNS_RCODE_NXDOMAIN = 3,
    DNS_RCODE_NOTIMP = 4,
    DNS_RCODE_REFUSED = 5,
    DNS_RCODE_YXDOMAIN = 6,
    DNS_RCODE_YXRRSET = 7,
    DNS_RCODE_NOTAUTH = 9,
    DNS_RCODE_NOTZONE = 10,
    DNS_RCODE_BADVERS = 16,
    DNS_RCODE_BADKEY = 17,
    DNS_RCODE_BADTIME = 18,
    DNS_RCODE_BADMODE = 19,
    DNS_RCODE_BADNAME = 20,
    DNS_RCODE_BADALG = 21,
    DNS_RCODE_BADTRUNC = 22,
    DNS_RCODE_BADCOOKIE = 23
} dns_rcode;

bool dns_str2rcode(char *str, dns_rcode *code)
{
    if(strcasecmp(str, "ok") == 0 || strcasecmp(str, "noerror") == 0)
    {
        *code = DNS_RCODE_OK;
        return true;
    }
    else if(strcasecmp(str, "formerr") == 0)
    {
        *code = DNS_RCODE_FORMERR;
        return true;
    }
    else if(strcasecmp(str, "servfail") == 0)
    {
        *code = DNS_RCODE_SERVFAIL;
        return true;
    }
    else if(strcasecmp(str, "nxdomain") == 0)
    {
        *code = DNS_RCODE_NXDOMAIN;
        return true;
    }
    else if(strcasecmp(str, "notimp") == 0)
    {
        *code = DNS_RCODE_NOTIMP;
        return true;
    }
    else if(strcasecmp(str, "refused") == 0)
    {
        *code = DNS_RCODE_REFUSED;
        return true;
    }
    else if(strcasecmp(str, "yxdomain") == 0)
    {
        *code = DNS_RCODE_YXDOMAIN;
        return true;
    }
    else if(strcasecmp(str, "yxrrset") == 0)
    {
        *code = DNS_RCODE_YXRRSET;
        return true;
    }
    else if(strcasecmp(str, "notauth") == 0)
    {
        *code = DNS_RCODE_NOTAUTH;
        return true;
    }
    else if(strcasecmp(str, "notzone") == 0)
    {
        *code = DNS_RCODE_NOTZONE;
        return true;
    }
    else if(strcasecmp(str, "badvers") == 0 || strcasecmp(str, "badsig") == 0)
    {
        *code = DNS_RCODE_BADVERS;
        return true;
    }
    else if(strcasecmp(str, "badkey") == 0)
    {
        *code = DNS_RCODE_BADKEY;
        return true;
    }
    else if(strcasecmp(str, "badtime") == 0)
    {
        *code = DNS_RCODE_BADTIME;
        return true;
    }
    else if(strcasecmp(str, "badmode") == 0)
    {
        *code = DNS_RCODE_BADMODE;
        return true;
    }
    else if(strcasecmp(str, "badname") == 0)
    {
        *code = DNS_RCODE_BADNAME;
        return true;
    }
    else if(strcasecmp(str, "badalg") == 0)
    {
        *code = DNS_RCODE_BADALG;
        return true;
    }
    else if(strcasecmp(str, "badtrunc") == 0)
    {
        *code = DNS_RCODE_BADTRUNC;
        return true;
    }
    else if(strcasecmp(str, "badcookie") == 0)
    {
        *code = DNS_RCODE_BADCOOKIE;
        return true;
    }
    else
    {
        char *endptr;
        unsigned long result = strtoul(str, &endptr, 10);
        if(*endptr != 0 || result > UINT16_MAX)
        {
            return false;
        }
        *code = (dns_rcode)result;
    }
    return false;
}

typedef enum
{
    DNS_OPCODE_QUERY = 0,
    DNS_OPCODE_IQUERY = 1,
    DNS_OPCODE_STATUS = 2,
    DNS_OPCODE_NOTIFY = 4,
    DNS_OPCODE_UPDATE = 5
} dns_opcode;

const size_t DNS_PACKET_MINIMUM_SIZE = 17; // as we handle them
// 12 bytes header + 1 byte question name + 2 bytes question class + 2 bytes question type

typedef struct
{
    uint16_t id;
    bool rd;
    bool tc;
    bool aa;
    uint8_t opcode;
    bool qr;
    uint8_t rcode;
    bool ad;
    bool z;
    bool cd;
    bool ra;

    uint16_t q_count;
    uint16_t ans_count;
    uint16_t auth_count;
    uint16_t add_count;

} dns_header_t;

typedef struct
{
    uint8_t name[0xFF];
    uint8_t length;
} dns_name_t;

typedef struct
{
    dns_name_t name;
    dns_record_type type;
    unsigned int class;
} dns_question_t;

typedef struct
{
    dns_header_t header;
    dns_question_t question;
} dns_head_t;

typedef struct
{
    dns_name_t name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t length;
    union
    {
        uint8_t *raw;
        dns_name_t name;
        struct in_addr in_addr;
        struct in6_addr in6_addr;
    } data;
} dns_record_t;

typedef struct
{
    dns_record_t ans[0x100];
    dns_record_t auth[0x100];
    dns_record_t add[0x100];
} dns_filtered_body_t;

typedef struct
{
    dns_head_t head;
    dns_filtered_body_t body;
} dns_pkt_t;

typedef struct
{
    uint8_t length;
    uint8_t *data;
} dns_character_string_ptr_t;

typedef struct
{
    uint16_t preference;
    dns_name_t name;
} dns_mx_t;

typedef struct
{
    uint8_t flags;
    uint8_t taglen;
    uint8_t *tag;
    uint8_t *value;
} dns_caa_t;

static inline bool is_valid_label_char(int c)
{
    return isalnum(c) || c == '-' || c == '_';
}

static bool parse_name(uint8_t *begin, uint8_t *buf, const uint8_t *end, uint8_t *name, uint8_t *len, uint8_t **next)
{
    static uint8_t first;
    static int label_type;
    static int label_len;
    static int name_len;
    static uint8_t *pointer;

    label_len = 0;
    pointer = NULL;
    name_len = 0;
    while (true)
    {
        if (buf >= end)
        {
            return false;
        }
        first = *buf;
        label_type = (first & 0xC0);
        if (label_type == 0xC0) // Compressed
        {
            if (next && !pointer)
            {
                *next = buf + 2;
            }
            pointer = begin + (htons(*((uint16_t *) buf)) & 0x3FFF);
            if (pointer >= buf)
            {
                return false;
            }
            buf = pointer;
        }
        else if (label_type == 0x00) // Uncompressed
        {
            label_len = (first & 0x3F);
            name_len += label_len + 1;
            if (name_len >= 0xFF)
            {
                return false;
            }
            if (label_len == 0)
            {
                if (name_len == 1)
                {
                    *(name++) = '.';
                }
                *name = 0;
                if (next && !pointer)
                {
                    *next = buf + label_len + 1;
                }
                if (name_len <= 1)
                {
                    *len = (uint8_t) name_len;
                }
                else
                {
                    *len = (uint8_t) (name_len - 1);
                }
                return true;
            }
            else
            {
                if (buf + label_len + 1 > end)
                {
                    return false;
                }
                memcpy(name, buf + 1, (size_t)label_len);
                *(name + label_len) = '.';
                name += label_len + 1;
                buf += label_len + 1;
            }
        }
        else
        {
            return false;
        }
    }
}

static inline void dns_buffer_set_id(uint8_t *buf, uint16_t id)
{
    *((uint16_t *) buf) = htons(id);
}

char *dns_class2str(dns_class cls)
{
    static char numbuf[16];

    switch(cls)
    {
        case DNS_CLS_IN:
            return "IN";
        case DNS_CLS_CH:
            return "H";
        case DNS_CLS_HS:
            return "HS";
        case DNS_CLS_QCLASS_NONE:
            return "QNONE";
        case DNS_CLS_QCLASS_ANY:
            return "QANY";
        default:
            snprintf(numbuf, sizeof(numbuf), "%" PRIu16, (uint16_t)cls);
            return numbuf;
    }
}

char *dns_opcode2str(dns_opcode opcode)
{
    static char numbuf[16];

    switch(opcode)
    {
        case DNS_OPCODE_QUERY:
            return "QUERY";
        case DNS_OPCODE_IQUERY:
            return "IQUERY";
        case DNS_OPCODE_STATUS:
            return "STATUS";
        case DNS_OPCODE_NOTIFY:
            return "NOTIFY";
        case DNS_OPCODE_UPDATE:
            return "UPDATE";
        default:
            snprintf(numbuf, sizeof(numbuf), "%" PRIu16, (uint16_t)opcode);
            return numbuf;
    }
}

char *dns_rcode2str(dns_rcode rcode)
{
    static char numbuf[16];

    switch (rcode)
    {
        case DNS_RCODE_OK:
            return "NOERROR";
        case DNS_RCODE_FORMERR:
            return "FORMERR";
        case DNS_RCODE_SERVFAIL:
            return "SERVFAIL";
        case DNS_RCODE_NXDOMAIN:
            return "NXDOMAIN";
        case DNS_RCODE_NOTIMP:
            return "NOTIMP";
        case DNS_RCODE_REFUSED:
            return "REFUSED";
        case DNS_RCODE_YXDOMAIN:
            return "YXDOMAIN";
        case DNS_RCODE_YXRRSET:
            return "YXRRSET";
        case DNS_RCODE_NOTAUTH:
            return "NOTAUTH";
        case DNS_RCODE_NOTZONE:
            return "NOTZONE";
        case DNS_RCODE_BADVERS:
            return "BADVERS";
        case DNS_RCODE_BADKEY:
            return "BADKEY";
        case DNS_RCODE_BADTIME:
            return "BADTIME";
        case DNS_RCODE_BADMODE:
            return "BADMODE";
        case DNS_RCODE_BADNAME:
            return "BADNAME";
        case DNS_RCODE_BADALG:
            return "BADALG";
        case DNS_RCODE_BADTRUNC:
            return "BADTRUNC";
        case DNS_RCODE_BADCOOKIE:
            return "BADCOOKIE";
        default:
            snprintf(numbuf, sizeof(numbuf), "%" PRIu16, (uint16_t)rcode);
            return numbuf;
    }
}

char *dns_record_type2str(dns_record_type type)
{
    static char numbuf[16];

    switch (type)
    {
        case DNS_REC_A:
            return "A";
        case DNS_REC_AAAA:
            return "AAAA";
        case DNS_REC_AFSDB:
            return "AFSDB";
        case DNS_REC_ANY:
            return "ANY";
        case DNS_REC_APL:
            return "APL";
        case DNS_REC_CAA:
            return "CAA";
        case DNS_REC_CDNSKEY:
            return "CDNSKEY";
        case DNS_REC_CDS:
            return "CDS";
        case DNS_REC_CERT:
            return "CERT";
        case DNS_REC_CNAME:
            return "CNAME";
        case DNS_REC_DHCID:
            return "DHCID";
        case DNS_REC_DLV:
            return "DLV";
        case DNS_REC_DNAME:
            return "DNAME";
        case DNS_REC_DNSKEY:
            return "DNSKEY";
        case DNS_REC_DS:
            return "DS";
        case DNS_REC_HIP:
            return "HIP";
        case DNS_REC_IPSECKEY:
            return "IPSECKEY";
        case DNS_REC_KEY:
            return "KEY";
        case DNS_REC_KX:
            return "KX";
        case DNS_REC_LOC:
            return "LOC";
        case DNS_REC_MX:
            return "MX";
        case DNS_REC_NAPTR:
            return "NAPTR";
        case DNS_REC_NS:
            return "NS";
        case DNS_REC_NSEC:
            return "NSEC";
        case DNS_REC_NSEC3:
            return "NSEC3";
        case DNS_REC_NSEC3PARAM:
            return "NSEC3PARAM";
        case DNS_REC_OPENPGPKEY:
            return "OPENPGPKEY";
        case DNS_REC_PTR:
            return "PTR";
        case DNS_REC_RRSIG:
            return "RRSIG";
        case DNS_REC_RP:
            return "RP";
        case DNS_REC_SIG:
            return "SIG";
        case DNS_REC_SOA:
            return "SOA";
        case DNS_REC_SRV:
            return "SRV";
        case DNS_REC_SSHFP:
            return "SSHFP";
        case DNS_REC_TA:
            return "TA";
        case DNS_REC_TKEY:
            return "TKEY";
        case DNS_REC_TLSA:
            return "TLSA";
        case DNS_REC_TSIG:
            return "TSIG";
        case DNS_REC_TXT:
            return "TXT";
        case DNS_REC_URI:
            return "URI";
        default:
            snprintf(numbuf, sizeof(numbuf), "%" PRIu16, (uint16_t)type);
            return numbuf;
    }
}

ssize_t dns_str2namebuf(const char *name, uint8_t *buffer)
{
    static uint8_t *bufname;
    static uint8_t *lenptr;
    static uint8_t total_len;
    static uint8_t label_len;

    lenptr = buffer; // points to the byte containing the label length
    bufname = buffer + 1; // points to the first byte of the actual name
    total_len = 0;
    label_len = 0;

    while (true)
    {
        char c = *(name++);
        total_len++;
        if (total_len > 254)
        {
            return -1;
        }
        if (c == '.')
        {
            *lenptr = label_len;
            if (total_len == 1)
            {
                break;
            }
            if (*name == 0)
            {
                *(bufname++) = 0;
                break;
            }
            lenptr = bufname++;
            label_len = 0;
        }
        else if (c == 0)
        {
            *lenptr = label_len;
            *(bufname++) = 0;
            break;
        }
        else
        {
            *(bufname++) = (uint8_t) c;
            label_len++;
            if (label_len >= 64)
            {
                return -1;
            }
        }
    }
    return total_len + 1;
}

ssize_t dns_question_create_from_name(uint8_t *buffer, dns_name_t *name, dns_record_type type, uint16_t id)
{
    static uint8_t *aftername;

    memcpy(buffer + 12, name->name, name->length);
    aftername = buffer + 12 + name->length;
    dns_buffer_set_id(buffer, id);
    *((uint16_t *) (buffer + 2)) = 0;
    *((uint16_t *) aftername) = htons(type);
    *((uint16_t *) (aftername + 2)) = htons(DNS_CLS_IN);
    *((uint16_t *) (buffer + 4)) = htons(0x0001);
    return aftername + 4 - buffer;
}

// Requires a buffer of at least 272 bytes to be supplied
static ssize_t dns_question_create(uint8_t *buffer, char *name, dns_record_type type, uint16_t id)
{
    static uint8_t *aftername;

    ssize_t name_len = dns_str2namebuf(name, buffer + 12);
    if(name_len < 0)
    {
        return -1;
    }
    aftername = buffer + 12 + name_len;

    dns_buffer_set_id(buffer, id);
    *((uint16_t *) (buffer + 2)) = 0;
    *((uint16_t *) aftername) = htons(type);
    *((uint16_t *) (aftername + 2)) = htons(DNS_CLS_IN);
    *((uint16_t *) (buffer + 4)) = htons(0x0001);
    return aftername + 4 - buffer;
}

bool dns_send_question(uint8_t *buffer, char *name, dns_record_type type, uint16_t id, int fd, struct sockaddr_storage *addr)
{
    ssize_t result = dns_question_create(buffer, name, type, id);
    if (result < DNS_PACKET_MINIMUM_SIZE)
    {
        return false;
    }
    sendto(fd,
           buffer,
           (size_t) result,
           0,
           (struct sockaddr *) addr,
           addr->ss_family == PF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
    return true;
}

bool dns_parse_question(uint8_t *buf, size_t len, dns_head_t *head, uint8_t **body_begin)
{
    static uint8_t *end; // exclusive
    static bool name_parsed;
    static uint8_t *qname_end;

    end = buf + len;
    if (len < DNS_PACKET_MINIMUM_SIZE)
    {
        return false;
    }

    head->header.id = ntohs((*(uint16_t *) buf));
    head->header.qr = (bool) (buf[2] & 0x80);
    head->header.opcode = (uint8_t) ((buf[2] & (0x78)) >> 3);
    head->header.aa = (bool) (buf[2] & 0x04);
    head->header.tc = (bool) (buf[2] & 0x02);
    head->header.rd = (bool) (buf[2] & 0x01);
    head->header.ra = (bool) (buf[3] & 0x80);
    head->header.z = (bool) (buf[4] & 0x40);
    head->header.ad = (bool) (buf[3] & 0x20);
    head->header.cd = (bool) (buf[3] & 0x10);
    head->header.rcode = (uint8_t) (buf[3] & 0x0F);

    head->header.ans_count = ntohs((*(uint16_t *) (buf + 6)));
    head->header.auth_count = ntohs((*(uint16_t *) (buf + 8)));
    head->header.add_count = ntohs((*(uint16_t *) (buf + 10)));
    head->header.q_count = ntohs((*(uint16_t *) (buf + 4)));
    if (head->header.q_count != 1)
    {
        return false;
    }
    name_parsed = parse_name(buf, buf + 12, end, head->question.name.name, &head->question.name.length, &qname_end);
    if (qname_end + 2 > end)
    {
        return false;
    }
    if (!name_parsed)
    {
        return false;
    }
    head->question.type = (dns_record_type) ntohs((*(uint16_t *) qname_end));
    head->question.class = ntohs((*(uint16_t *) (qname_end + 2)));
    if (body_begin)
    {
        *body_begin = qname_end + 4;
    }
    return true;
}

bool dns_names_eq(dns_name_t *name1, dns_name_t *name2)
{
    if(name1->length != name2->length)
    {
        return false;
    }
    for(uint8_t i = 0; i < name1->length; i++)
    {
        if(tolower(name1->name[i]) != tolower(name2->name[i]))
        {
            return false;
        }
    }
    return true;
}

bool dns_raw_names_eq(dns_name_t *name1, dns_name_t *name2)
{
    return name1->length == name2->length && memcmp(name1->name, name2->name, name1->length) == 0;
}

bool dns_parse_record_raw(uint8_t *begin, uint8_t *buf, const uint8_t *end, uint8_t **next, dns_record_t *record)
{
    if (!parse_name(begin, buf, end, record->name.name, &record->name.length, next))
    {
        return false;
    }
    if (*next + 10 > end)
    {
        return false;
    }

    record->type = ntohs((*(uint16_t *) (*next)));
    record->class = ntohs((*(uint16_t *) (*next + 2)));
    record->ttl = ntohl((*(uint32_t *) (*next + 4)));
    record->length = ntohs((*(uint16_t *) (*next + 8)));
    *next = *next + 10;

    record->data.raw = *next;

    *next = *next + record->length;
    if (*next > end)
    {
        return false;
    }
    return true;
}

bool dns_parse_record(uint8_t *begin, uint8_t *buf, const uint8_t *end, uint8_t **next, dns_record_t *record)
{
    if(!dns_parse_record_raw(begin, buf, end, next, record))
    {
        return false;
    }

    if (record->type == DNS_REC_A)
    {
        if (record->length != 4)
        {
            return false;
        }
        memcpy(&record->data.in_addr, record->data.raw, 4);
    }
    else if (record->type == DNS_REC_AAAA)
    {
        if (record->length != 16)
        {
            return false;
        }
        memcpy(&record->data.in6_addr, record->data.raw, 16);
    }
    else if (record->type == DNS_REC_NS)
    {
        if (record->length > 0xFF)
        {
            return false;
        }
        if (!parse_name(begin, record->data.raw, end, record->data.name.name, &record->data.name.length, NULL))
        {
            return false;
        }
    }

    // We don't care about any other records.

    return true;
}

bool dns_parse_body(uint8_t *buf, uint8_t *begin, const uint8_t *end, dns_pkt_t *packet)
{
    static uint8_t *next;
    static uint16_t i;

    next = buf;
    for (i = 0; i < min(packet->head.header.ans_count, elements(packet->body.ans) - 1); i++)
    {
        if (!dns_parse_record(begin, next, end, &next, &packet->body.ans[i]))
        {
            return false;
        }
    }
    packet->body.ans[i].type = 0;

    for (i = 0; i < min(packet->head.header.auth_count, elements(packet->body.auth) - 1); i++)
    {
        if (!dns_parse_record(begin, next, end, &next, &packet->body.auth[i]))
        {
            return false;
        }
    }
    packet->body.auth[i].type = 0;

    for (i = 0; i < min(packet->head.header.add_count, elements(packet->body.add) - 1); i++)
    {
        if (!dns_parse_record(begin, next, end, &next, &packet->body.add[i]))
        {
            return false;
        }
    }
    packet->body.add[i].type = 0;

    // TODO: Check whether overly long packets are valid. If not, discard them here.

    return true;
}

bool dns_parse_reply(uint8_t *buf, size_t len, dns_pkt_t *packet)
{
    uint8_t *body_begin;
    if (!dns_parse_question(buf, len, &packet->head, &body_begin))
    {
        return false;
    }
    return dns_parse_body(body_begin, buf, buf + len, packet);
}

void dns_buf_set_qr(uint8_t *buf, bool value)
{
    buf[2] &= 0x7F;
    buf[2] |= value << 7;
}

void dns_buf_set_rd(uint8_t *buf, bool value)
{
    buf[2] &= 0xFE;
    buf[2] |= value;
}

void dns_buf_set_rcode(uint8_t *buf, uint8_t code)
{
    buf[3] &= 0xF0;
    buf[3] |= code;
}

void dns_send_reply(uint8_t *buffer, size_t len, int fd, struct sockaddr_storage *addr)
{
    sendto(fd,
           buffer,
           len,
           0,
           (struct sockaddr *) addr,
           addr->ss_family == PF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
}

bool dns_create_reply(uint8_t *buffer, size_t *len, char *name, dns_record_type type, uint16_t id, dns_rcode code)
{
    ssize_t result = dns_question_create(buffer, name, type, id);
    if (result < DNS_PACKET_MINIMUM_SIZE)
    {
        return false;
    }
    *len = (size_t) result;
    dns_buf_set_qr(buffer, true);
    dns_buf_set_rcode(buffer, code);
    return true;
}

bool dns_print_readable(char **buf, size_t buflen, const uint8_t *source, size_t len)
{
    char *endbuf = *buf + buflen;
    for(size_t i = 0; i < len; i++)
    {
        if(source[i] >= ' ' && source[i] <= '~' && source[i] != '\\')
        {
            if(*buf >= endbuf - 1)
            {
                **buf = 0;
                return false;
            }
            *((*buf)++) = source[i];
        }
        else
        {
            if(*buf >= endbuf - 4)
            {
                **buf = 0;
                return false;
            }
            *((*buf)++) = '\\';
            *((*buf)++) = 'x';
            char hex1 = (char)((source[i] >> 8) & 0xF);
            char hex2 = (char)(source[i] & 0xF);
            *((*buf)++) = (char)(hex1 + (hex1 < 10 ? '0' : ('a' - 10)));
            *((*buf)++) = (char)(hex2 + (hex2 < 10 ? '0' : ('a' - 10)));
        }
    }
    **buf = 0;
    return true;
}

char* dns_name2str(dns_name_t *name)
{
    static char buf[0xFF * 4];

    char *ptr = buf;
    dns_print_readable(&ptr, sizeof(buf), name->name, name->length);
    return buf;
}

void dns_question2str(dns_question_t *question, char *buf, size_t len)
{
    snprintf(buf, len, "%s %s %s",
             dns_name2str(&question->name),
             dns_class2str((dns_class)question->class),
             dns_record_type2str(question->type));
}

char* dns_raw_record_data2str(dns_record_t *record, uint8_t *begin, uint8_t *end)
{
    static char buf[0xFFFF0];
    static dns_name_t name;

    char *ptr = buf;

    switch(record->type)
    {
        case DNS_REC_NS:
        case DNS_REC_CNAME:
        case DNS_REC_DNAME:
        case DNS_REC_PTR:
            parse_name(begin, record->data.raw, end, name.name, &name.length, NULL);
            dns_print_readable(&ptr, sizeof(buf), name.name, name.length);
            break;
        case DNS_REC_MX:
            if(record->length < 3)
            {
                goto raw;
            }
            parse_name(begin, record->data.raw + 2, end, name.name, &name.length, NULL);
            int no = sprintf(buf, "%" PRIu16 " ", ntohs(*((uint16_t*)record->data.raw)));
            ptr += no;
            dns_print_readable(&ptr, sizeof(buf), name.name, name.length);
            break;
        case DNS_REC_TXT:
        {
            uint8_t *record_end = record->data.raw + record->length;
            uint8_t *data_ptr = record->data.raw;
            while(data_ptr < record_end)
            {
                uint8_t length = *(data_ptr++);
                if (data_ptr + length <= record_end)
                {
                    *(ptr++) = '"';
                    dns_print_readable(&ptr, sizeof(buf), data_ptr, length);
                    data_ptr += length;
                    *(ptr++) = '"';
                    *(ptr++) = ' ';
                }
                else
                {
                    break;
                }
            }
            *ptr = 0;
            break;
        }
        case DNS_REC_SOA:
        {
            uint8_t *next;
            // We have 5 32-bit values plus two names.
            if (record->length < 22)
            {
                goto raw;
            }

            parse_name(begin, record->data.raw, end, name.name, &name.length, &next);
            dns_print_readable(&ptr, sizeof(buf), name.name, name.length);
            *(ptr++) = ' ';

            if(next + 20 >= record->data.raw + record->length)
            {
                goto raw;
            }
            parse_name(begin, next, end, name.name, &name.length, &next);
            dns_print_readable(&ptr, sizeof(buf), name.name, name.length);
            *(ptr++) = ' ';
            if(next + 20 > record->data.raw + record->length)
            {
                goto raw;
            }

            sprintf(ptr, "%" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32,
                    ntohl(*((uint32_t*)next)),
                    ntohl(*(((uint32_t*)next) + 1)),
                    ntohl(*(((uint32_t*)next) + 2)),
                    ntohl(*(((uint32_t*)next) + 3)),
                    ntohl(*(((uint32_t*)next) + 4)));
            break;
        }
        case DNS_REC_A:
            if(record->length != 4)
            {
                goto raw;
            }
            inet_ntop(AF_INET, record->data.raw, buf, sizeof(buf));
            break;
        case DNS_REC_AAAA:
            if(record->length != 16)
            {
                goto raw;
            }
            inet_ntop(AF_INET6, record->data.raw, buf, sizeof(buf));
            break;
        case DNS_REC_CAA:
            if(record->length < 2 || record->data.raw[1] < 1 || record->data.raw[1] > 15
               || record->data.raw[1] + 2 > record->length)
            {
                goto raw;
            }
            int written = sprintf(ptr, "%" PRIu8 " ", (uint8_t)(record->data.raw[0] >> 7));
            if(written < 0)
            {
                return buf;
            }
            ptr += written;
            dns_print_readable(&ptr, sizeof(buf), record->data.raw + 2, record->data.raw[1]);
            *(ptr++) = ' ';
            *(ptr++) = '"';
            dns_print_readable(&ptr, sizeof(buf), record->data.raw + 2 + record->data.raw[1],
                               (size_t)(record->length - record->data.raw[1] - 2));
            *(ptr++) = '"';
            *ptr = 0;
            break;
        raw:
        default:
            dns_print_readable(&ptr, sizeof(buf), record->data.raw, record->length);
            *ptr = 0;
    }
    return buf;
}

dns_section_t dns_get_section(uint16_t index, dns_header_t *header)
{
    if(index < header->ans_count)
    {
        return DNS_SECTION_ANSWER;
    }
    else if(index < header->ans_count + header->auth_count)
    {
        return DNS_SECTION_AUTHORITY;
    }
    else
    {
        return DNS_SECTION_ADDITIONAL;
    }
}

char *dns_section2str(dns_section_t section)
{
    switch(section)
    {
        case DNS_SECTION_ANSWER:
            return "ANSWER";
        case DNS_SECTION_ADDITIONAL:
            return "ADDITIONAL";
        case DNS_SECTION_AUTHORITY:
            return "AUTHORITY";
        case DNS_SECTION_QUESTION:
            return "QUESTION";
    }
    return "UNKNOWN";
}

bool dns_in_zone(dns_name_t *name, dns_name_t *zone)
{
    return zone->length == 1 // Provided that the label is a FQDN, this is the root zone containing everything else
           || (zone->length == name->length
               && strcasecmp((char*)name->name + name->length - zone->length, (char*)zone->name) == 0)
           || (zone->length < name->length
               && strcasecmp((char*)name->name + name->length - zone->length, (char*)zone->name) == 0
               && *(name->name + name->length - zone->length - 1) == '.');

}

void dns_print_packet(FILE *f, dns_pkt_t *packet, uint8_t *begin, size_t len, uint8_t *next)
{
    static char buf[0xFFFF];
    static dns_record_t rec;

    fprintf(f,
             ";; ->>HEADER<<- opcode: %s, status: %s, id: %"PRIu16"\n"
             ";; flags: %s%s%s%s%s; QUERY: %" PRIu16 ", ANSWER: %" PRIu16 ", AUTHORITY: %" PRIu16 ", ADDITIONAL: %" PRIu16 "\n\n"
             ";; QUESTION SECTION:\n",
             dns_opcode2str((dns_opcode)packet->head.header.opcode),
             dns_rcode2str((dns_rcode)packet->head.header.rcode),
             packet->head.header.id,
             packet->head.header.qr ? "qr " : "",
             packet->head.header.ad ? "ad " : "",
             packet->head.header.aa ? "aa " : "",
             packet->head.header.rd ? "rd " : "",
             packet->head.header.ra ? "ra " : "",
             packet->head.header.q_count,
             packet->head.header.ans_count,
             packet->head.header.auth_count,
             packet->head.header.add_count
    );

    dns_question2str(&packet->head.question, buf, sizeof(buf));
    fprintf(f, "%s\n", buf);

    uint16_t i = 0;
    dns_section_t section = DNS_SECTION_QUESTION;
    while(dns_parse_record_raw(begin, next, begin + len, &next, &rec))
    {
        dns_section_t new_section = dns_get_section(i++, &packet->head.header);
        if(new_section != section)
        {
            fprintf(f, "\n;; %s SECTION:\n", dns_section2str(new_section));
            section = new_section;
        }
        fprintf(f,
                "%s %" PRIu32 " %s %s %s\n",
                dns_name2str(&rec.name),
                rec.ttl,
                dns_class2str((dns_class)rec.class),
                dns_record_type2str((dns_record_type) rec.type),
                dns_raw_record_data2str(&rec, begin, begin + len));
    }
    fprintf(f, "\n\n");
}

#endif //MASSRESOLVER_DNS_H
