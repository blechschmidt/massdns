/*
	B. Blechschmidt
	https://cysec.biz/
*/

#ifndef INC_DNS
#define INC_DNS

#include <inttypes.h>
#include <assert.h>
#include "buffers.h"


// Record bit fields (for specification of multiple records, e. g. through the command line)
#define RECORD_A 0x01
#define RECORD_AAAA 0x02
#define RECORD_CNAME 0x04
#define RECORD_MX 0x08
#define RECORD_NS 0x10
#define RECORD_PTR 0x20
#define RECORD_TXT 0x40
#define RECORD_SOA 0x80
#define RECORD_DNAME 0xA0
#define RECORD_ANY 0x140

// Record identifiers as defined by the DNS standard
#define DNS_RECORD_UNKNOWN 0
#define DNS_RECORD_A 1
#define DNS_RECORD_AAAA 28
#define DNS_RECORD_CNAME 5
#define DNS_RECORD_MX 15
#define DNS_RECORD_NS 2
#define DNS_RECORD_PTR 12
#define DNS_RECORD_TXT 16
#define DNS_RECORD_SOA 6
#define DNS_RECORD_SRV 33
#define DNS_RECORD_LOC 29
#define DNS_RECORD_DNAME 39
#define DNS_RECORD_ANY 255

const char* const DNS_RECORD_STRING_A = "A";
const char* const DNS_RECORD_STRING_AAAA = "AAAA";
const char* const DNS_RECORD_STRING_CNAME = "CNAME";
const char* const DNS_RECORD_STRING_MX = "MX";
const char* const DNS_RECORD_STRING_NS = "NS";
const char* const DNS_RECORD_STRING_PTR = "PTR";
const char* const DNS_RECORD_STRING_TXT = "TXT";
const char* const DNS_RECORD_STRING_SOA = "SOA";
const char* const DNS_RECORD_STRING_SRV = "SRV";
const char* const DNS_RECORD_STRING_LOC = "LOC";
const char* const DNS_RECORD_STRING_DNAME = "DNAME";
const char* const DNS_RECORD_STRING_ANY = "ANY";
const char* const EMPTY = "";
const char* const ROOT = ".";

#define DNS_CLASS_IN 0x01
const char* const DNS_CLASS_IN_STRING = "IN";

#define DNS_REPLY_NOERR 0
#define DNS_REPLY_FORMERR 1
#define DNS_REPLY_SERVFAIL 2
#define DNS_REPLY_NXDOMAIN 3
#define DNS_REPLY_NOTIMP 4
#define DNS_REPLY_REFUSED 5


#define DNS_OPCODE_QUERY 1
#define DNS_OPCODE_STATUS 2
#define DNS_OPCODE_NOTIFY 4
#define DNS_OPCODE_UPDATE 5

#define DNS_RESPONSE_FLAG 1 << 15
#define DNS_AUTHORITATIVE_FLAG 1 << 10
#define DNS_TRUNCATED_FLAG 1 << 9
#define DNS_RECURSION_DESIRED_FLAG 1 << 8
#define DNS_RECURSION_AVAILABLE_FLAG 1 << 7
#define DNS_ANSWER_AUTHENTICATED_FLAG 1 << 5
#define DNS_REQUIRE_AUTHENTICATION_FLAG 1 << 4

typedef struct dns_record
{
    char *name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    void *data;
    size_t len;
    struct dns_record *next_record;
} dns_record;

typedef struct
{
    uint16_t transaction;
    uint16_t flags;
    uint16_t questioncount;
    dns_record *question;
    uint16_t answercount;
    dns_record *answer;
    uint16_t authoritycount;
    dns_record *authority;
    uint16_t additionalcount;
    dns_record *additional;
} dns_packet;

typedef struct
{
    uint16_t preference;
    char *name;
} dns_record_mx;

typedef struct
{
    char *name;
} dns_record_name;

typedef struct
{
    char *nameserver;
    char *mailbox;
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expiry;
    uint32_t min_ttl;
} dns_record_soa;

typedef buffer_t dns_record_txt;

uint16_t dns_parse_record(int record)
{
    // https://en.wikipedia.org/wiki/List_of_DNS_record_types
    if (record == RECORD_A)
        return DNS_RECORD_A;
    else if (record == RECORD_AAAA)
        return DNS_RECORD_AAAA;
    else if (record == RECORD_CNAME)
        return DNS_RECORD_CNAME;
    else if (record == RECORD_MX)
        return DNS_RECORD_MX;
    else if (record == RECORD_NS)
        return DNS_RECORD_NS;
    else if (record == RECORD_PTR)
        return DNS_RECORD_PTR;
    else if (record == RECORD_TXT)
        return DNS_RECORD_TXT;
    else if (record == RECORD_SOA)
        return DNS_RECORD_SOA;
    else if (record == RECORD_DNAME)
        return DNS_RECORD_DNAME;
    else if (record == RECORD_ANY)
        return DNS_RECORD_ANY;
    else
        assert(0);
}

char *dns_get_label_len(char *hostname, uint8_t *len)
{
    *len = 0;
    while (*hostname != '\0' && *hostname != '.')
    {
        (*len)++;
        hostname++;
    }
    if (*hostname == '\0')
    {
        return NULL;
    }
    return hostname + 1;
}

dns_record *dns_create_question(char *query, int record)
{
    dns_record *question = safe_malloc(sizeof(dns_record));
    size_t query_len = strlen(query);
    question->name = safe_malloc(query_len + 1);
    strcpy(question->name, query);
    question->class = DNS_CLASS_IN;
    question->type = dns_parse_record(record);
    question->len = query_len + 6;
    question->data = safe_malloc(question->len);
    question->next_record = NULL;
    strcpy((char *) question->data + 1, query);
    char *label = (char *) question->data + 1;
    char *label_pointer = question->data;
    uint8_t label_len;
    while ((label = dns_get_label_len(label, &label_len)) != NULL)
    {
        *label_pointer = label_len;
        label_pointer = label - 1;
    }
    *label_pointer = label_len;
    uint16_t record_type = htons(dns_parse_record(record));
    uint16_t record_class = htons(DNS_CLASS_IN);
    memcpy((char *) question->data + query_len + 2, &record_type, 2);
    memcpy((char *) question->data + query_len + 4, &record_class, 2);

    return question;
}

char *printable_binary(buffer_t *input)
{
    char *result = safe_malloc(input->len * 4 + 1);
    size_t result_index = 0;
    char *data = (char *) input->data;
    for (size_t i = 0; i < input->len; i++)
    {
        if (data[i] >= 0x20 && data[i] <= 0x7E && data[i] != '"')
        {
            result[result_index++] = data[i];
        }
        else
        {
            sprintf(result + result_index, "\\x%02x", data[i] & 0xFF);
            result_index += 4;
        }
    }
    result[result_index] = 0;
    return result;
}

uint16_t dns_create_question_section(dns_packet *packet, char *query, int record_types)
{
    uint16_t record_count = 1;
    packet->question = dns_create_question(query, record_types);
    return record_count;
}

dns_packet *dns_create_packet(char *query, int record_types, uint16_t transaction, uint16_t flags)
{
    dns_packet *packet = safe_malloc(sizeof(*packet));
    packet->transaction = transaction;
    packet->flags = flags;
    packet->questioncount = dns_create_question_section(packet, query, record_types);
    packet->answercount = 0;
    packet->answer = NULL;
    packet->authoritycount = 0;
    packet->authority = NULL;
    packet->additionalcount = 0;
    packet->additional = NULL;
    return packet;
}

const char* const dns_record_type_to_string(int type)
{
    switch(type)
    {
        case DNS_RECORD_A:
            return DNS_RECORD_STRING_A;
        case DNS_RECORD_AAAA:
            return DNS_RECORD_STRING_AAAA;
        case DNS_RECORD_CNAME:
            return DNS_RECORD_STRING_CNAME;
        case DNS_RECORD_DNAME:
            return DNS_RECORD_STRING_DNAME;
        case DNS_RECORD_MX:
            return DNS_RECORD_STRING_MX;
        case DNS_RECORD_NS:
            return DNS_RECORD_STRING_NS;
        case DNS_RECORD_SOA:
            return DNS_RECORD_STRING_SOA;
        case DNS_RECORD_SRV:
            return DNS_RECORD_STRING_SRV;
        case DNS_RECORD_PTR:
            return DNS_RECORD_STRING_PTR;
        case DNS_RECORD_TXT:
            return DNS_RECORD_STRING_TXT;
        case DNS_RECORD_LOC:
            return DNS_RECORD_STRING_LOC;
        case DNS_RECORD_ANY:
            return DNS_RECORD_STRING_ANY;
        default:
            return EMPTY;
    }
}

const char* const dns_record_class_to_string(int class)
{
    if(class == DNS_CLASS_IN)
    {
        return DNS_CLASS_IN_STRING;
    }
    return EMPTY;
}

void dns_destroy_record_list(dns_record *record)
{
    dns_record *next_ptr;
    while (record != NULL)
    {
        next_ptr = record->next_record;
        switch (record->type)
        {
            case DNS_RECORD_TXT:
            {
                dns_record_txt *txt = (dns_record_txt *) record->data;
                if (txt == NULL)
                    break;
                free(txt->data);
                txt->data = NULL;
                break;
            }
            case DNS_RECORD_SOA:
            {
                dns_record_soa *soa = (dns_record_soa *) record->data;
                if (soa == NULL)
                    break;
                free(soa->nameserver);
                soa->nameserver = NULL;
                free(soa->mailbox);
                soa->mailbox = NULL;
                break;
            }
            case DNS_RECORD_MX:
            {
                dns_record_mx *mx = (dns_record_mx *) record->data;
                if (mx == NULL)
                    break;
                free(mx->name);
                mx->name = NULL;
                break;
            }
            case DNS_RECORD_CNAME:
            case DNS_RECORD_NS:
            case DNS_RECORD_DNAME:
            case DNS_RECORD_PTR:
            {
                dns_record_name *ns = (dns_record_name *) record->data;
                if (ns == NULL)
                    break;
                free(ns->name);
                ns->name = NULL;
                break;
            }
            default:
                break;
        }
        free(record->data);
        record->data = NULL;
        free(record->name);
        record->name = NULL;
        free(record);
        record = next_ptr;
    }
}

void dns_destroy_packet(dns_packet *packet)
{
    if (packet->question)
    {
        free(packet->question->data);
        packet->question->data = NULL;
        free(packet->question->name);
        packet->question->name = NULL;
    }
    free(packet->question);
    packet->question = NULL;
    dns_destroy_record_list(packet->answer);
    packet->answer = NULL;
    dns_destroy_record_list(packet->authority);
    packet->authority = NULL;
    dns_destroy_record_list(packet->additional);
    packet->additional = NULL;
    free(packet);
}

void dns_records_to_buf(dns_record *record, char *buf)
{
    size_t record_offset = 0;
    while (record != NULL)
    {
        memcpy(buf + record_offset, record->data, record->len);
        record_offset += record->len;
        record = record->next_record;
    }
}

size_t dns_record_list_size(dns_record *record)
{
    size_t list_size = 0;
    while (record != NULL)
    {
        list_size += record->len;
        record = record->next_record;
    }
    return list_size;
}

size_t dns_packet_to_bytes(dns_packet *packet, char **buf)
{
    size_t len = 12;
    size_t question_list_size = dns_record_list_size(packet->question);
    size_t answer_list_size = dns_record_list_size(packet->answer);
    size_t authority_list_size = dns_record_list_size(packet->authority);
    size_t additional_list_size = dns_record_list_size(packet->additional);
    len += question_list_size;
    len += answer_list_size;
    len += authority_list_size;
    len += additional_list_size;
    *buf = safe_malloc(len);
    memset(*buf, 0, len);
    uint16_t packet_transaction = htons(packet->transaction);
    uint16_t packet_flags = htons(packet->flags);
    uint16_t packet_questioncount = htons(packet->questioncount);
    uint16_t packet_answercount = htons(packet->answercount);
    uint16_t packet_authoritycount = htons(packet->authoritycount);
    uint16_t packet_additionalcount = htons(packet->additionalcount);
    memcpy(*buf, &packet_transaction, 2);
    memcpy(*buf + 2, &packet_flags, 2);
    memcpy(*buf + 4, &packet_questioncount, 2);
    memcpy(*buf + 6, &packet_answercount, 2);
    memcpy(*buf + 8, &packet_authoritycount, 2);
    memcpy(*buf + 10, &packet_additionalcount, 2);
    char *record_ptr = *buf + 12;
    dns_records_to_buf(packet->question, record_ptr);
    record_ptr += question_list_size;
    dns_records_to_buf(packet->answer, record_ptr);
    record_ptr += answer_list_size;
    dns_records_to_buf(packet->authority, record_ptr);
    record_ptr += authority_list_size;
    dns_records_to_buf(packet->additional, record_ptr);
    return len;
}

char *dns_get_name(char **current, char *packet, size_t packetlen)
{
    char *packetend = packet + packetlen;
    size_t memsize = 0;
    char *buf = NULL;
    char *pointer_storage = NULL;
    bool pointers[0xFFFF];
    memset(pointers, 0, sizeof(pointers));
    while (1)
    {
        if (*current < packet || *current >= packetend)
        {
            free(buf);
            return NULL;
        }
        if (pointers[*current - packet])
        {
            free(buf);
            return NULL;
        }
        pointers[*current - packet] = true;
        int is_pointer = (**current & ~0x3F) == ~0x3F;
        if (is_pointer)
        {
            uint16_t offset = (uint16_t) ((**current & 0x3F) << 8 | (*(*current + 1)) & 0xFF);

            if(offset == 0 && !pointer_storage)
            {
                free(buf);
                return NULL;
            }

            if (offset < 0 || offset >= packetlen)
            {
                free(buf);
                return NULL;
            }
            if (pointer_storage == NULL)
            {
                pointer_storage = *current + 2;
            }
            *current = packet + offset;
        }
        else
        {
            uint8_t size = (uint8_t) (**current & 0x3F);
            if (*current + size >= packetend)
            {
                free(buf);
                return NULL;
            }
            if (size == 0)
            {
                *current += 1;
                break;
            }
            buf = realloc(buf, memsize + size + 1);
            memcpy(buf + memsize, *current + 1, size);
            buf[memsize + size] = '.';
            *current += size + 1;
            memsize += size + 1;
        }
    }
    if (memsize > 0)
    {
        buf[memsize - 1] = 0;
    }
    if (pointer_storage != NULL)
    {
        *current = pointer_storage;
    }
    if(buf == NULL)
    {
        buf = safe_malloc(strlen(ROOT) + 1);
        strcpy(buf, ROOT);
        return buf;
    }
    return buf;
}

int dns_parse_question_record(dns_record *record, char **begin, char *packet, size_t packetlen)
{
    char *packetend = packet + packetlen;
    record->name = NULL;
    record->data = NULL;
    record->type = DNS_RECORD_UNKNOWN;
    record->name = dns_get_name(begin, packet, packetlen);
    record->next_record = NULL;
    if (*begin + 4 > packetend || record->name == NULL)
    {
        return DNS_REPLY_FORMERR;
    }
    record->len = strlen(record->name) + 1;
    memcpy(&record->type, *begin, 2);
    memcpy(&record->class, *begin + 2, 2);
    record->type = ntohs(record->type);
    record->class = ntohs(record->class);
    *begin += 4;
    return DNS_REPLY_NOERR;
}

int dns_parse_answer_record(dns_record *record, char **begin, char *packet, size_t packetlen)
{
    char *packetend = packet + packetlen;
    record->name = NULL;
    record->data = NULL;
    if (*begin + 10 > packetend)
    {
        return DNS_REPLY_FORMERR;
    }
    record->name = dns_get_name(begin, packet, packetlen);
    memcpy(&record->type, *begin, 2);
    memcpy(&record->class, *begin + 2, 2);
    memcpy(&record->ttl, *begin + 4, 4);
    memcpy(&record->len, *begin + 8, 2);
    record->type = ntohs(record->type);
    record->class = ntohs(record->class);
    record->ttl = ntohl(record->ttl);
    record->len = ntohs((uint16_t) record->len);
    *begin += 10;
    if (*begin + record->len > packetend || record->type == DNS_RECORD_A && record->len != 4
        || record->type == DNS_RECORD_AAAA && record->len != 16)
    {
        return DNS_REPLY_FORMERR;
    }
    char *data_begin = *begin;
    switch (record->type)
    {
        case DNS_RECORD_A:
        case DNS_RECORD_AAAA:
        {
            record->data = safe_malloc(record->len);
            memcpy(record->data, *begin, record->len);
            *begin = data_begin + record->len;
            return DNS_REPLY_NOERR;
        }
        case DNS_RECORD_MX:
        {
            if (*begin + 2 > packetend)
            {
                return DNS_REPLY_FORMERR;
            }
            dns_record_mx *mx = safe_malloc(sizeof(*mx));
            mx->name = NULL;
            memcpy(&mx->preference, *begin, 2);
            mx->preference = ntohs(mx->preference);
            *begin += 2;
            mx->name = dns_get_name(begin, packet, packetlen);
            record->data = mx;
            return DNS_REPLY_NOERR;
        }
        case DNS_RECORD_NS:
        case DNS_RECORD_CNAME:
        case DNS_RECORD_DNAME:
        case DNS_RECORD_PTR:
        {
            dns_record_name *name = safe_malloc(sizeof(*name));
            name->name = NULL;
            name->name = dns_get_name(begin, packet, packetlen);
            record->data = name;
            return DNS_REPLY_NOERR;
        }
        case DNS_RECORD_SOA:
        {
            dns_record_soa *soa = safe_malloc(sizeof(*soa));
            soa->nameserver = NULL;
            soa->mailbox = NULL;
            soa->nameserver = dns_get_name(begin, packet, packetlen);
            soa->mailbox = dns_get_name(begin, packet, packetlen);
            if (*begin + 20 > packetend)
            {
                free(soa->nameserver);
                free(soa->mailbox);
                free(soa);
                return DNS_REPLY_FORMERR;
            }
            memcpy(&soa->serial, *begin, 4);
            memcpy(&soa->refresh, *begin + 4, 4);
            memcpy(&soa->retry, *begin + 8, 4);
            memcpy(&soa->expiry, *begin + 12, 4);
            memcpy(&soa->min_ttl, *begin + 16, 4);
            soa->serial = ntohl(soa->serial);
            soa->refresh = ntohl(soa->refresh);
            soa->retry = ntohl(soa->retry);
            soa->expiry = ntohl(soa->expiry);
            soa->min_ttl = ntohl(soa->min_ttl);
            record->data = soa;
            *begin += 20;
            return DNS_REPLY_NOERR;
        }
        case DNS_RECORD_TXT:
        {
            if (*begin + 1 > packetend)
            {
                return DNS_REPLY_FORMERR;
            }
            dns_record_txt *txt = safe_malloc(sizeof(*txt));
            txt->data = NULL;
            txt->len = (size_t)**begin & 0xFF;
            if (*begin + txt->len > packetend)
            {
                free(txt);
                return DNS_REPLY_FORMERR;
            }
            txt->data = safe_malloc(txt->len);
            *begin += 1;
            memcpy(txt->data, *begin, txt->len);
            *begin += txt->len;
            record->data = txt;
            return DNS_REPLY_NOERR;
        }
        default:
        {
            if (*begin + record->len > packetend)
            {
                return DNS_REPLY_FORMERR;
            }
            record->data = safe_malloc(record->len);
            memcpy(record->data, *begin, record->len);
            *begin += record->len;
            return DNS_REPLY_NOERR;
        }
    }
}

char *dns_record_to_string(dns_record *record, bool print_unknown)
{
    char *result = NULL;
    const char* const record_type = dns_record_type_to_string(record->type);
    const char* const record_class = dns_record_class_to_string(record->class);
    if(record->class != DNS_CLASS_IN)
        return DNS_REPLY_NOERR;
    switch (record->type)
    {
        case DNS_RECORD_A:
        {
            char buffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, record->data, buffer, INET_ADDRSTRLEN);
            asprintf(&result, "%s %d %s %s %s", record->name, record->ttl, record_class, record_type, buffer);
            break;
        }
        case DNS_RECORD_AAAA:
        {
            char buffer[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, record->data, buffer, INET6_ADDRSTRLEN);
            asprintf(&result, "%s %d %s %s %s", record->name, record->ttl, record_class, record_type, buffer);
            break;
        }
        case DNS_RECORD_MX:
        {
            dns_record_mx *mx = (dns_record_mx *) record->data;
            asprintf(&result, "%s %d %s %s %d %s", record->name, record->ttl, record_class, record_type, mx->preference, mx->name);
            break;
        }
        case DNS_RECORD_CNAME:
        case DNS_RECORD_NS:
        case DNS_RECORD_DNAME:
        case DNS_RECORD_PTR:
        {
            dns_record_name *name = (dns_record_name *) record->data;
            asprintf(&result, "%s %d %s %s %s", record->name, record->ttl, record_class, record_type, name->name);
            break;
        }
        case DNS_RECORD_SOA:
        {
            dns_record_soa *soa = (dns_record_soa *) record->data;
            asprintf(&result, "%s %d %s %s %s %s %d %d %d %d %d", record->name, record->ttl, record_class, record_type, soa->nameserver,
                     soa->mailbox, soa->serial, soa->refresh, soa->retry, soa->expiry, soa->min_ttl);
            break;
        }
        case DNS_RECORD_TXT:
        {
            dns_record_txt *txt = (dns_record_txt *) record->data;
            char *txtbuf = printable_binary(txt);
            asprintf(&result, "%s %d %s %s \"%s\"", record->name, record->ttl, record_class, record_type, txtbuf);
            free(txtbuf);
            break;
        }
        default:
        {
            if(print_unknown)
            {
                buffer_t databuf;
                databuf.len = record->len;
                databuf.data = record->data;
                char* datastr = printable_binary(&databuf);
                asprintf(&result, "%s %d %s %d \"%s\"", record->name, record->ttl, record_class, record->type, datastr);
                free(datastr);
            }
            break;
        }
    }
    return result;
}

int dns_parse_response_list(dns_record **target, uint16_t count, char **ptr, char *buf,
                            size_t buflen)
{
    dns_record *next_record = NULL;
    for (uint16_t i = 0; i < count; i++)
    {
        dns_record *record = safe_malloc(sizeof(*record));
        record->next_record = NULL;
        record->data = NULL;
        record->type = 0;
        int response_code = dns_parse_answer_record(record, ptr, buf, buflen);
        if (response_code != DNS_REPLY_NOERR)
        {
            dns_destroy_record_list(record);
            *target = next_record;
            return response_code;
        }
        record->next_record = next_record;
        next_record = record;
    }
    *target = next_record;
    return DNS_REPLY_NOERR;
}

int dns_parse_raw_packet(dns_packet *packet, char *buf, size_t buflen)
{
    if (buflen < 12)
    {
        return DNS_REPLY_FORMERR;
    }
    uint16_t transaction;
    memcpy(&transaction, buf, 2);
    uint16_t flags;
    memcpy(&flags, buf + 2, 2);
    uint16_t questioncount;
    memcpy(&questioncount, buf + 4, 2);
    uint16_t answercount;
    memcpy(&answercount, buf + 6, 2);
    uint16_t authoritycount;
    memcpy(&authoritycount, buf + 8, 2);
    uint16_t additionalcount;
    memcpy(&additionalcount, buf + 10, 2);
    packet->transaction = ntohs(transaction);
    packet->flags = ntohs(flags);
    packet->questioncount = ntohs(questioncount);
    packet->answercount = ntohs(answercount);
    packet->authoritycount = ntohs(authoritycount);
    packet->additionalcount = ntohs(additionalcount);
    packet->question = NULL;
    packet->answer = NULL;
    packet->authority = NULL;
    packet->additional = NULL;
    if (packet->flags & DNS_RESPONSE_FLAG == 0 || packet->questioncount != 1)
    {
        return DNS_REPLY_FORMERR;
    }
    char *current_ptr = buf + 12;

    packet->question = safe_malloc(sizeof(*packet->question));
    int response_code = dns_parse_question_record(packet->question, &current_ptr, buf, buflen);
    if (response_code != DNS_REPLY_NOERR)
    {
        return response_code;
    }
    response_code = dns_parse_response_list(&packet->answer, packet->answercount, &current_ptr, buf, buflen);
    if (response_code != DNS_REPLY_NOERR)
    {
        return response_code;
    }
    response_code = dns_parse_response_list(&packet->authority, packet->authoritycount, &current_ptr, buf, buflen);
    if (response_code != DNS_REPLY_NOERR)
    {
        return response_code;
    }
    return (char) (packet->flags & 0xF);
}

#endif
