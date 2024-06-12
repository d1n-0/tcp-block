#include "mac.h"
#include <pcap.h>

int forward(int sd, struct sockaddr_ll *sa, pcap_t *pcap, uint8_t *packet, Mac smac);
int backward(int sd, struct sockaddr_ll *sa, pcap_t *pcap, uint8_t *packet, Mac smac, uint8_t *payload, size_t payload_len);