#include <pcap.h>
#include <cstdio>
#include <cstring>

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
		.dev_ = NULL
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

	int sd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sd == -1)
	{
		perror("socket");
		return -1;
	}

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

		printf("packet: %u bytes captured\n", header->caplen);
		if (!check(packet, (uint8_t *)"Host: www.gilgil.net", 3)) continue;
		block(sd, pcap, (uint8_t *)packet, smac);
    }

    pcap_close(pcap);
}
