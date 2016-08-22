#include <arpa/inet.h>
#include <stdlib.h>

#include <ldns/packet.h>
#include <ldns/host2wire.h>

#include "../../massdns.h"

extern void massdns_handle_response(massdns_context_t *context, ldns_pkt *packet, struct sockaddr_storage *address)
{
    uint8_t *buffer;
    size_t len;
    if(LDNS_STATUS_OK == ldns_pkt2wire(&buffer, packet, &len))
    {
        if(len <= 0xFFFF)
        {
            struct timeval now;
            if(0 != gettimeofday(&now, NULL))
            {
                bzero(&now, sizeof(now));
            }
            uint16_t shortlen = len;
            fwrite(&now, sizeof(now), 1, context->outfile);
            fwrite(address, sizeof(*address), 1, context->outfile);
            fwrite(&shortlen, sizeof(shortlen), 1, context->outfile);
            fwrite(buffer, sizeof(*buffer), len, context->outfile);
        }
        free(buffer);
    }
}
