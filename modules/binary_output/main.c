#include <arpa/inet.h>
#include <stdlib.h>

#include <ldns/packet.h>
#include <ldns/host2wire.h>

#include "../../massdns.h"

extern void massdns_handle_response(massdns_context_t *context, ldns_pkt *packet)
{
    uint8_t *buffer;
    size_t len;
    if(LDNS_STATUS_OK == ldns_pkt2wire(&buffer, packet, &len))
    {
        if(len <= 0xFFFF)
        {
            uint16_t netlen = htons(len);
            fwrite(&netlen, sizeof(netlen), 1, context->outfile);
            fwrite(buffer, sizeof(uint8_t), len, context->outfile);
        }
        free(buffer);
    }
}
