#include "block.h"
#include "send.h"
#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"

#include <pcap.h>

bool check(const uint8_t *packet, uint8_t *pattern, size_t pattern_len)
{
    EthHdr *eth = (EthHdr *)packet;
    if (eth->type() != EthHdr::Ip4)
        return false;

    IpHdr *ip = (IpHdr *)(packet + sizeof(EthHdr));
    if (ip->protocol != IpHdr::TCP)
        return false;

    TcpHdr *tcp = (TcpHdr *)(packet + sizeof(EthHdr) + (ip->ihl << 2));
    uint8_t *payload = (uint8_t *)(packet + sizeof(EthHdr) + (ip->ihl << 2) + (tcp->offset << 2));

    if (ntohs(ip->total_length) - (ip->ihl << 2) - (tcp->offset << 2) < pattern_len)
        return false;
    
    for (int i=0; i < (ntohs(ip->total_length) - (ip->ihl << 2) - (tcp->offset << 2)) - pattern_len; i++)
    {
        if (memcmp(payload + i, pattern, pattern_len) == 0)
            return true;
    }
    return false;
}

int block(int sd, pcap_t *pcap, uint8_t *packet, Mac smac)
{
    char *payload = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n";
    forward(sd, pcap, packet, smac);
    backward(sd, pcap, packet, smac, (uint8_t *)payload, strlen(payload));
    printf("Blocked\n");
}