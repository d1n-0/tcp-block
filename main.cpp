#include <pcap.h>
#include <cstdio>
#include <cstring>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"
#include "mac.h"
#include "util.h"
#include "send.h"
#include "block.h"

int main(int argc, char *argv[])
{
	Param param = {
		.dev_ = NULL,
        .pattern_ = NULL
	};

    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

	Mac smac;
	if (getMacFromInterface(param.dev_, &smac) == -1) return -1;

	int sd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if (sd == -1)
	{
		perror("socket");
		return -1;
	}

	struct ifreq ifr0;
	struct sockaddr_ll sa;

    memset(&ifr0, 0, sizeof(ifr0));
    strncpy(ifr0.ifr_name, param.dev_, IFNAMSIZ - 1);
    if (ioctl(sd, SIOCGIFINDEX, &ifr0) == -1) {
        fprintf(stderr, "network interface error\n");
        return -1;
    }
    sa.sll_ifindex = ifr0.ifr_ifindex;
    sa.sll_halen = ETH_ALEN;

    while (true)
    {
        struct pcap_pkthdr *header;
        const uint8_t *packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

		if (!check(packet, (uint8_t *)param.pattern_, strlen(param.pattern_))) continue;
		block(sd, &sa, pcap, (uint8_t *)packet, smac);
    }

    pcap_close(pcap);
}
