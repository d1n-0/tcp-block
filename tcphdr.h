#pragma once

#include <cstdint>
#include <arpa/inet.h>

#include "ip.h"

struct _pseudo_header {
    uint32_t s_addr;
    uint32_t d_addr;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t length;
};

typedef struct {
    uint16_t s_port;
    uint16_t d_port;
    uint32_t seq_num;
    uint32_t ack_num;

#  if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t reserved:4;
    uint8_t offset:4;
#  endif

#  if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t offset:4;
    uint8_t reserved:4;
#  endif

    uint8_t flags;
#  define FIN  0x01
#  define SYN  0x02
#  define RST  0x04
#  define PUSH 0x08
#  define ACK  0x10
#  define URG  0x20

    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;

    uint16_t calcChecksum(Ip sip, Ip dip, uint8_t *payload, uint16_t payload_len) {
        uint32_t sum = 0;
        uint16_t *p;
        _pseudo_header pseudo_header = {
            sip,
            dip,
            0,
            IPPROTO_TCP,
            htons((offset << 2) + payload_len)
        };
        
        p = (uint16_t *)&pseudo_header;
        for (int i = 0; i < sizeof(struct _pseudo_header) >> 1; i++) {
            sum += (*p++);
        }

        p = (uint16_t *)this;
        for (int i = 0; i < (offset << 1); i++) {
            sum += (*p++);
        }
        
        p = (uint16_t *)payload;
        for (int i = 0; i < payload_len >> 1; i++) {
            sum += (*p++);
        }
        if (payload_len & 1) {
            sum += *(uint8_t *)p;
        }

        while (sum >> 16) sum = (sum >> 16) + (sum & 0xFFFF);
        
        return (uint16_t)~sum;
    }
} TcpHdr;