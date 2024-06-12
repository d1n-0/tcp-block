#include "util.h"
#include "mac.h"

#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <string>

// https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods
const char* http_request_methods[] = {"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"};

void usage() {
    printf("syntax : 1m-block <site list file>\n");
    printf("sample : 1m-block top-1m.txt\n");
}

bool parse(Param *param, int argc, char *argv[])
{
    if (argc != 2)
    {
        usage();
        return false;
    }
    param->dev_ = argv[1];
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