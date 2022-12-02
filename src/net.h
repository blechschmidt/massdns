// SPDX-License-Identifier: GPL-3.0-only

#ifndef MASSRESOLVER_NET_H
#define MASSRESOLVER_NET_H

#include <stdbool.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#ifdef PCAP_SUPPORT
    #include <sys/ioctl.h>
#endif
#include <inttypes.h>

#define loop_sockets(sockets) \
        for (socket_info_t *socket = (sockets)->data; socket < ((socket_info_t*)(sockets)->data) + (sockets)->len; socket++)

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

typedef enum
{
    SOCKET_TYPE_INTERFACE,
    SOCKET_TYPE_QUERY,
    SOCKET_TYPE_QUERY_TCP,
    SOCKET_TYPE_CONTROL,
    SOCKET_TYPE_TCP_RAW_RECEIVER,
    SOCKET_TYPE_TCP_RAW_SENDER
} socket_type_t;

typedef enum
{
    NETMODE_EPOLL,
    NETMODE_BUSYPOLL
} netmode_t;

typedef struct
{
    sa_family_t family;
    int descriptor;
    socket_type_t type;
    void *data;
} socket_info_t;

void socket_noblock(socket_info_t* socket)
{
    int sd = socket->descriptor;
    int flags = fcntl(sd, F_GETFL, 0);
    fcntl(sd, F_SETFL, flags | O_NONBLOCK);
}

socklen_t sockaddr_storage_size(struct sockaddr_storage *storage)
{
    if(storage->ss_family == AF_INET)
    {
        return sizeof(struct sockaddr_in);
    }
    else if(storage->ss_family == AF_INET6)
    {
        return sizeof(struct sockaddr_in6);
    }
    abort();
}

#ifdef HAVE_EPOLL
void add_sockets(int epollfd, uint32_t events, int op, buffer_t *sockets)
{
    socket_info_t *interface_sockets = sockets->data;
    for (size_t i = 0; i < sockets->len; i++)
    {
        struct epoll_event ev;
        bzero(&ev, sizeof(ev));
        ev.data.ptr = &interface_sockets[i];
        ev.events = events;
        if (epoll_ctl(epollfd, op, interface_sockets[i].descriptor, &ev) != 0)
        {
            perror("Failed to add epoll event");
            exit(EXIT_FAILURE);
        }
    }
}
#endif

bool str_to_addr(char *str, uint16_t default_port, struct sockaddr_storage *addr)
{
    if(str == NULL || str[0] == 0)
    {
        return false;
    }
    while(*str == ' ' || *str == '\t') // Skip whitespaces ("trim left")
    {
        str++;
    }
    unsigned long int port = default_port;

    if(str[0] == '[')
    {
        str++;
        char *closing_bracket = strstr(str, "]");
        if(!closing_bracket)
        {
            return false;
        }
        if(closing_bracket[1] == ':') // Is there a port separator?
        {
            *closing_bracket = 0;
            char *invalid_char;
            port = strtoul(closing_bracket + 2, &invalid_char, 10);
            if (*invalid_char != 0 || port >= UINT16_MAX)
            {
                return false;
            }
        }
    }
    else // We either have an IPv6 address without square brackets or an IPv4 address
    {
        bool v4 = false;
        char *colon = NULL;
        for(char *c = str; *c != 0; c++)
        {
            if(*c == '.' && colon == NULL) // dot before colon
            {
                v4 = true;
            }
            if(*c == ':')
            {
                colon = c;
            }
        }
        if(v4 && colon) // We found the port separator
        {
            *colon = 0;
            char *invalid_char;
            port = strtoul(colon + 1, &invalid_char, 10);
            if (*invalid_char != 0 || port >= UINT16_MAX)
            {
                return false;
            }
        }

    }
    if (inet_pton(AF_INET, str, &((struct sockaddr_in*)addr)->sin_addr) == 1)
    {
        ((struct sockaddr_in*)addr)->sin_port = htons((uint16_t )port);
        ((struct sockaddr_in*)addr)->sin_family = AF_INET;
        return true;
    }
    else if (inet_pton(AF_INET6, str, &((struct sockaddr_in6*)addr)->sin6_addr) == 1)
    {
        ((struct sockaddr_in6*)addr)->sin6_port = htons((uint16_t )port);
        ((struct sockaddr_in6*)addr)->sin6_family = AF_INET6;
        return true;
    }
    return false;
}

// Source: http://www.microhowto.info/howto/calculate_an_internet_protocol_checksum_in_c.html
uint16_t ip_checksum(void* vdata,size_t length)
{
    // Cast the data pointer to one that can be indexed.
    char* data=(char*)vdata;

    // Initialise the accumulator.
    uint64_t acc=0xffff;

    // Handle any partial block at the start of the data.
    unsigned int offset=((uintptr_t)data)&3;
    if (offset)
    {
        size_t count=4-offset;
        if (count>length) count=length;
        uint32_t word=0;
        memcpy(offset+(char*)&word,data,count);
        acc+=ntohl(word);
        data+=count;
        length-=count;
    }

    // Handle any complete 32-bit blocks.
    char* data_end=data+(length&~3);
    while (data!=data_end)
    {
        uint32_t word;
        memcpy(&word,data,4);
        acc+=ntohl(word);
        data+=4;
    }
    length&=3;

    // Handle any partial block at the end of the data.
    if (length)
    {
        uint32_t word=0;
        memcpy(&word,data,length);
        acc+=ntohl(word);
    }

    // Handle deferred carries.
    acc=(acc&0xffffffff)+(acc>>32);
    while (acc>>16)
    {
        acc=(acc&0xffff)+(acc>>16);
    }

    // If the data began at an odd byte address
    // then reverse the byte order to compensate.
    if (offset&1)
    {
        acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}

ssize_t write_raw_header(uint8_t *buf, uint16_t payload_size, struct sockaddr_storage *src, struct sockaddr_storage *dst)
{
    buf[0] = 0;
    buf[1] = 0;
    buf[2] = 0;
    buf[3] = 0;

    // length
    *((uint16_t*)(buf + 4)) = htons(payload_size + 8);

    // To compute the checksum over the pseudo header more efficiently, some fields are swapped and some fields are
    // only filled in after checksum computation. This saves us a copy into a dedicated pseudo header buf.

    // next header
    buf[6] = 0;
    // hop limit
    buf[7] = 17; // 17 is UDP

    struct sockaddr_in6* src_range = (struct sockaddr_in6*)src;
    struct sockaddr_in6* dst_addr = (struct sockaddr_in6*)dst;
    memcpy(buf + 8, src_range->sin6_addr.s6_addr, 16);
    memcpy(buf + 24, dst_addr->sin6_addr.s6_addr, 16);

    // TODO: Remove hard-coded port by having a socket block some port.
    *((uint16_t*)(buf + 40)) = htons(666);
    *((uint16_t*)(buf + 42)) = dst_addr->sin6_port;
    *((uint16_t*)(buf + 44)) = htons(payload_size + 8);
    *((uint16_t*)(buf + 46)) = htons(0);

    *((uint16_t*)(buf + 46)) = ip_checksum(buf, payload_size + 48);

    buf[0] = 6 << 4;
    buf[6] = 17;
    buf[7] = 255;

    return payload_size + 48;
}

#ifdef PCAP_SUPPORT
int get_iface_hw_addr(char *iface, uint8_t *hw_mac)
{
    int s;
    struct ifreq buffer;

    s = socket(PF_INET, SOCK_DGRAM, 0);
    if (s < 0)
    {
        return EXIT_FAILURE;
    }
    bzero(&buffer, sizeof(buffer));
    strncpy(buffer.ifr_name, iface, IFNAMSIZ);
    buffer.ifr_name[sizeof(buffer.ifr_name) -1] = '\0';
    ioctl(s, SIOCGIFHWADDR, &buffer);
    close(s);
    memcpy(hw_mac, buffer.ifr_hwaddr.sa_data, 6);
    return EXIT_SUCCESS;
}

#define MAC_READABLE_BUFLEN 18

int get_iface_hw_addr_readable(char *iface, char *hw_mac)
{
    uint8_t buffer[6];
    int result = get_iface_hw_addr(iface, buffer);
    for(uint8_t *b = buffer; b < buffer + 6; b++)
    {
        sprintf(hw_mac, "%02x:", *b);
        hw_mac += 3;
        if(b == buffer + 5)
        {
            *(hw_mac - 1) = 0;
        }
    }
    return result;
}
#endif

char *sockaddr2str(struct sockaddr_storage *addr)
{
    static char str[INET6_ADDRSTRLEN + sizeof(":65535") + 2]; // + 2 for [ and ]
    static uint16_t port;
    size_t len;

    if(addr->ss_family == AF_INET)
    {
        port = ntohs(((struct sockaddr_in*)addr)->sin_port);
        inet_ntop(addr->ss_family, &((struct sockaddr_in*)addr)->sin_addr, str, sizeof(str));
        len = strlen(str);
        // inet_ntop does not allow us to determine, how long the printed string was.
        // Thus, we have to use strlen.
    }
    else
    {
        str[0] = '[';
        port = ntohs(((struct sockaddr_in6*)addr)->sin6_port);
        inet_ntop(addr->ss_family, &((struct sockaddr_in6*)addr)->sin6_addr, str + 1, sizeof(str) - 1);
        len = strlen(str);
        str[len++] = ']';
        str[len] = 0;
    }

    snprintf(str + len, sizeof(str) - len, ":%" PRIu16, port);

    return str;
}

/**
 * Determine the local IP address for a given destination.
 *
 * @param remote_addr The remote address.
 * @param local_addr The local address to be filled in.
 * @param local_len The size of the socket address structure.
 * @return 0 on success, -1 otherwise.
 */
int get_local_addr(struct sockaddr_storage *remote_addr, struct sockaddr_storage *local_addr, socklen_t *local_len)
{
    int sock = socket(remote_addr->ss_family, SOCK_DGRAM, 0);
    int result = 0;
    if(sock < 0)
    {
        return -1;
    }
    if(connect(sock, (struct sockaddr*)remote_addr, sizeof(*remote_addr)) < 0)
    {
        result = -1;
        goto cleanup;
    }
    if(getsockname(sock, (struct sockaddr*)local_addr, local_len) < 0)
    {
        result = -1;
        goto cleanup;
    }
    cleanup:
    close(sock);
    return result;
}

#endif //MASSRESOLVER_NET_H
