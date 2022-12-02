#ifndef MASSDNS_TCP_H
#define MASSDNS_TCP_H

#include <stddef.h>
#include <stdlib.h>
#include "security.h"

#define TCPIP_HEADER_MAX_SIZE 60

typedef struct tcp_data_tacker {
    struct tcp_data_tacker *next;
    size_t offset;
    size_t end;
} tcp_data_tracker_t;

int tcp_segments_cmp(tcp_data_tracker_t *tracker1, tcp_data_tracker_t *tracker2)
{
    if(tracker1->end + 1 < tracker2->offset)
    {
        return -1;
    }
    if(tracker1->offset > tracker2->end + 1)
    {
        return 1;
    }
    return 0;
}

void tcp_segments_merge(tcp_data_tracker_t *dst, tcp_data_tracker_t *src)
{
    dst->offset = min(dst->offset, src->offset);
    dst->end = max(dst->end, src->end);
}

void tcp_data_tracker_add_data(tcp_data_tracker_t **root, size_t offset, size_t end) {
    if (*root == NULL) {
        *root = safe_malloc(sizeof(**root));
        (*root)->offset = offset;
        (*root)->end = end;
        (*root)->next = NULL;
        return;
    }

    tcp_data_tracker_t new_tracker;
    new_tracker.offset = offset;
    new_tracker.end = end;

    tcp_data_tracker_t *current = *root;
    tcp_data_tracker_t *last = NULL;
    while(current != NULL)
    {
        int cmp = tcp_segments_cmp(&new_tracker, current);
        if(cmp == 0)
        {
            tcp_segments_merge(current, &new_tracker);

            while(current->next && tcp_segments_cmp(current, current->next) == 0)
            {
                tcp_segments_merge(current, current->next);
                tcp_data_tracker_t *skip = current->next->next;
                free(current->next);
                current->next = skip;
            }
            return;
        }
        if(cmp > 0)
        {
            if(last == NULL)
            {
                tcp_data_tracker_t *new_root = safe_malloc(sizeof(*new_root));
                new_root->offset = offset;
                new_root->end = end;
                new_root->next = *root;
                *root = new_root;
                return;
            }

            tcp_data_tracker_t *insert = safe_malloc(sizeof(*insert));
            insert->offset = offset;
            insert->end = end;
            insert->next = last->next;
            last->next = insert;
            return;
        }

        // cmp < 0

        last = current;
        current = current->next;
    }

    tcp_data_tracker_t *insert = safe_malloc(sizeof(*insert));
    insert->offset = offset;
    insert->end = end;
    insert->next = NULL;
    last->next = insert;
}

void tcp_data_tracker_free(tcp_data_tracker_t *root)
{
    tcp_data_tracker_t *current = root;
    while(current != NULL)
    {
        tcp_data_tracker_t *next = current->next;
        free(current);
        current = next;
    }
}


uint16_t tcp_raw_write_header(uint8_t *ip_header, uint16_t payload_len, uint16_t sport, uint16_t dport,
                            uint32_t seqnum, uint32_t acknum, uint8_t flags)
{
    static uint8_t prepseudo_buffer[0x100];

    uint8_t *prepseudo;
    uint8_t prepseudo_len;
    uint8_t *tcp_header = ip_header + ((ip_header[0] & 0xf0) == 0x40 ? 20 : 40);

    if((ip_header[0] & 0xf0) == 0x40)
    {
        prepseudo_len = 12;
        prepseudo = tcp_header - prepseudo_len;
        memcpy(prepseudo_buffer, prepseudo, prepseudo_len);
        memcpy(prepseudo, ip_header + 12, 8);
        prepseudo[8] = 0;
        prepseudo[9] = IPPROTO_TCP;
        *((uint16_t*)(prepseudo + 10)) = htons(payload_len + 20);
    }
    else if((ip_header[0] & 0xf0) == 0x60)
    {
        prepseudo_len = 40;
        prepseudo = tcp_header - prepseudo_len;
        memcpy(prepseudo_buffer, prepseudo, prepseudo_len);

        // Copy source and destination address to pseudo header
        memmove(prepseudo, ip_header + 8, 32);
        *((uint32_t*)(prepseudo + 32)) = htonl(payload_len + 20);
        prepseudo[36] = 0;
        prepseudo[37] = 0;
        prepseudo[38] = 0;
        prepseudo[39] = IPPROTO_TCP;
    }
    else
    {
        abort();
    }
    *((uint16_t*)(tcp_header + 0)) = htons(sport);
    *((uint16_t*)(tcp_header + 2)) = htons(dport);
    *((uint32_t*)(tcp_header + 4)) = htonl(seqnum);
    *((uint32_t*)(tcp_header + 8)) = htonl(acknum);
    tcp_header[12] = 0x50;
    tcp_header[13] = flags;
    *((uint16_t*)(tcp_header + 14)) = htons(0xffff); // Window
    *((uint16_t*)(tcp_header + 16)) = 0;  // Checksum
    *((uint16_t*)(tcp_header + 18)) = 0; // Urgent ptr

    *((uint16_t*)(tcp_header + 16)) = ip_checksum(prepseudo, 20 + prepseudo_len + payload_len);

    memcpy(prepseudo, prepseudo_buffer, prepseudo_len);

    return 20;
}

uint16_t ip_raw_write_header(uint8_t *buf, uint16_t payload_size, struct sockaddr *src, struct sockaddr *dst, uint8_t protocol)
{
    if(dst->sa_family == AF_INET)
    {
        buf[0] = 0x45;
        buf[1] = 0x00;
        *((uint16_t *) (buf + 2)) = htons(payload_size + 20);
        *((uint16_t *) (buf + 4)) = 1;
        buf[6] = 0x40;
        buf[7] = 0x00;
        buf[8] = 64;
        buf[9] = protocol;
        buf[10] = 0;
        buf[11] = 0;

        struct sockaddr_in *src_addr = (struct sockaddr_in *) src;
        struct sockaddr_in *dst_addr = (struct sockaddr_in *) dst;
        memcpy(buf + 12, &src_addr->sin_addr.s_addr, 4);
        memcpy(buf + 16, &dst_addr->sin_addr.s_addr, 4);

        *((uint16_t *) (buf + 10)) = ip_checksum(buf, 20);

        return 20;
    }
    else if(dst->sa_family == AF_INET6)
    {
        buf[0] = 0x60;
        buf[1] = 0x00;
        buf[2] = 0x00;
        buf[3] = 0x00;
        *((uint16_t *) (buf + 4)) = htons(payload_size);
        buf[6] = protocol;
        buf[7] = 64;

        struct sockaddr_in6 *src_addr = (struct sockaddr_in6 *) src;
        struct sockaddr_in6 *dst_addr = (struct sockaddr_in6 *) dst;
        memcpy(buf + 8, &src_addr->sin6_addr, 16);
        memcpy(buf + 24, &dst_addr->sin6_addr, 16);

        return 40;
    }
    return 0;
}

uint16_t raw_ip_header_size(struct sockaddr *dst)
{
    if(dst->sa_family == AF_INET)
    {
        return 20;
    }
    return 40;
}

in_port_t get_sockaddr_port(struct sockaddr *addr)
{
    if(addr->sa_family == AF_INET)
    {
        return ntohs(((struct sockaddr_in*)addr)->sin_port);
    }
    else if(addr->sa_family == AF_INET6)
    {
        return ntohs(((struct sockaddr_in6*)addr)->sin6_port);
    }
    abort();
}

void set_sockaddr_port(struct sockaddr *addr, uint16_t port)
{
    if(addr->sa_family == AF_INET)
    {
        ((struct sockaddr_in*)addr)->sin_port = htons(port);
        return;
    }
    else if(addr->sa_family == AF_INET6)
    {
        ((struct sockaddr_in6*)addr)->sin6_port= htons(port);
        return;
    }
    abort();
}

size_t tcpip_raw_write(uint8_t *payload, uint16_t payload_size, struct sockaddr *src, struct sockaddr *dst,
        uint32_t seqnum, uint32_t acknum, uint8_t flags)
{
    uint16_t ip_header_size = raw_ip_header_size(dst);
    uint8_t *ip_header = payload - 20 - ip_header_size;
    ip_raw_write_header(ip_header, 20 + payload_size, src, dst, IPPROTO_TCP);
    in_port_t sport = get_sockaddr_port(src);
    in_port_t dport = get_sockaddr_port(dst);
    tcp_raw_write_header(ip_header, payload_size, sport, dport, seqnum, acknum, flags);
    return ip_header_size + 20;
}

#endif //MASSDNS_TCP_H
