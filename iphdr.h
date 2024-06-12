#pragma once

#include "ip.h"

typedef struct {
	#  if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t ihl:4;
    uint8_t version:4;
	#  endif

	#  if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t version:4;
    uint8_t ihl:4;
	#  endif
    //uint8_t version_and_ihl;

    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_and_fragment_offset;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t s_addr;
    uint32_t d_addr;

    Ip sip() { return Ip(ntohl(s_addr)); }
    Ip dip() { return Ip(ntohl(d_addr)); }
    uint16_t calcChecksum() {
        uint32_t sum = 0;
        uint16_t *p = (uint16_t *)this;
        for (int i = 0; i < ihl << 2; i++) {
            sum += ntohs(*p++);
        }
        while (sum >> 16) sum = (sum >> 16) + (sum & 0xFFFF);
        
        return (uint16_t)~sum;
    }

    enum: uint8_t {
        ICMP = 1,
        TCP = 6,
        UDP = 17
    };
} IpHdr;