#include "mac.h"
#include <pcap.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <unistd.h>

bool check(const uint8_t *packet, uint8_t *pattern, size_t pattern_len);
int block(int sd, struct sockaddr_ll *sa, pcap_t *pcap, uint8_t *packet, Mac smac);