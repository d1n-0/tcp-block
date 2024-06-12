#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unordered_set>
#include <string>

#include <netinet/in.h>
#include "iphdr.h"
#include "tcphdr.h"
#include "mac.h"

typedef struct
{
    char *dev_;
} Param;

void usage();
bool parse(Param *param, int argc, char *argv[]);
int getMacFromInterface(char* dev, Mac* mac);