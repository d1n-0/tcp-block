#include "mac.h"
#include <pcap.h>

bool check(const uint8_t *packet, uint8_t *pattern, size_t pattern_len);
int block(int sd, pcap_t *pcap, uint8_t *packet, Mac smac);