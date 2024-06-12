#include "send.h"
#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/if_packet.h>

int forward(
    int sd,
    struct sockaddr_ll *sa,
    pcap_t *pcap,
    uint8_t *packet,
    Mac smac
) {
    size_t ip_len = ((IpHdr *)(packet + sizeof(EthHdr)))->ihl << 2;
    size_t tcp_len = ((TcpHdr *)(packet + sizeof(EthHdr) + ip_len))->offset << 2;

    uint8_t data[4096];
    memcpy(data, packet, sizeof(EthHdr) + ip_len + tcp_len);
    EthHdr *eth = (EthHdr *)data;
    eth->smac_ = smac;

    IpHdr *ip = (IpHdr *)(data + sizeof(EthHdr));
    ip->total_length = htons(ip_len + tcp_len);
    ip->header_checksum = 0;
    ip->header_checksum = ip->calcChecksum();

    TcpHdr *tcp = (TcpHdr *)(data + sizeof(EthHdr) + ip_len);
    tcp->seq_num = htonl(ntohl(tcp->seq_num) + ntohs(ip->total_length) - ip_len - tcp_len);
    tcp->flags = RST | ACK;
    tcp->checksum = 0;
    tcp->checksum = tcp->calcChecksum(ip->sip(), ip->dip(), NULL, 0);

    // struct sockaddr_in sin;
    // sin.sin_family = AF_INET;
    // sin.sin_port = htons(tcp->d_port);
    // sin.sin_addr.s_addr = htonl(ip->d_addr);
    if (sendto(sd, data, sizeof(EthHdr) + ip_len + tcp_len, 0, (struct sockaddr *)sa, sizeof(struct sockaddr_ll)) == -1) {
        perror("sendto() failed");
        return -1;
    }
    // if (sendto(sd, packet, sizeof(EthHdr) + ntohs(ip->total_length), 0, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
    //     perror("sendto() failed");
    //     return -1;
    // }
    printf("Forwarded\n");
    // pcap_sendpacket(pcap, data, sizeof(EthHdr) + ip_len + tcp_len);
}

int backward(
    int sd,
    struct sockaddr_ll *sa,
    pcap_t *pcap,
    uint8_t *packet,
    Mac smac,
    uint8_t *payload,
    size_t payload_len
) {
    size_t ip_len = ((IpHdr *)(packet + sizeof(EthHdr)))->ihl << 2;
    size_t tcp_len = ((TcpHdr *)(packet + sizeof(EthHdr) + ip_len))->offset << 2;

    uint8_t data[4096];
    memcpy(data, packet, sizeof(EthHdr) + ip_len + tcp_len);
    EthHdr *eth = (EthHdr *)data;
    eth->smac_ = smac;
    eth->dmac_ = eth->smac_;

    IpHdr *ip = (IpHdr *)(data + sizeof(EthHdr));
    ip->total_length = htons(ip_len + tcp_len + payload_len);
    ip->time_to_live = 128;
    ip->header_checksum = 0;
    ip->header_checksum = ip->calcChecksum();

    TcpHdr *tcp = (TcpHdr *)(data + sizeof(EthHdr) + ip_len);
    tcp->seq_num = htonl(ntohl(tcp->ack_num));
    tcp->ack_num = htonl(ntohl(tcp->seq_num) + ntohs(ip->total_length) - ip_len - tcp_len);
    tcp->flags = FIN | ACK;
    tcp->checksum = 0;
    tcp->checksum = tcp->calcChecksum(ip->sip(), ip->dip(), payload, payload_len);

    memcpy(data + sizeof(EthHdr) + ip_len + tcp_len, payload, payload_len);

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = tcp->s_port;
    sin.sin_addr.s_addr = ip->s_addr;

    if (sendto(sd, data, sizeof(EthHdr) + ip_len + tcp_len + payload_len, 0, (struct sockaddr *)sa, sizeof(struct sockaddr_ll)) == -1) {
        perror("sendto() failed");
        return -1;
    }
    // pcap_sendpacket(pcap, data, sizeof(EthHdr) + ip_len + tcp_len + payload_len);
}