#pragma once

#include <cstdint>
#include <arpa/inet.h>
#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"

struct Packet final {
    EthHdr eth_;
    IpHdr ip_;
    TcpHdr tcp_;
};
typedef Packet *PPacket;
