#include "util.h"
#include "mac.h"

#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <string>

void usage() {
    printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

bool parse(Param *param, int argc, char *argv[])
{
    if (argc != 3)
    {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    param->pattern_ = argv[2];
    return true;
}

int getMacFromInterface(char* dev, Mac* mac) {
    if (dev == NULL) {
        fprintf(stderr, "dev is NULL\n");
        return -1;
    }

    if (strlen(dev) >= IFNAMSIZ) {
        fprintf(stderr, "dev name is too long\n");
        return -1;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(sock);
        return -1;
    }

    close(sock);

    *mac = Mac((uint8_t *)ifr.ifr_hwaddr.sa_data);
    return 0;
}
