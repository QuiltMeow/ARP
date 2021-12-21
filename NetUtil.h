#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <ctype.h>

#include "Bool.h"

// 檢查 IP 位址格式是否正確
bool isValidIPv4Address(const char* ipAddress) {
    struct sockaddr_in ip;
    int ret = inet_pton(AF_INET, ipAddress, &(ip.sin_addr));
    return ret != 0;
}

// 檢查 MAC 位址格式是否正確
bool isValidMACAddress(const char* mac) {
    int word = 0, symbol = 0;
    while (*mac) {
        if (isxdigit(*mac)) {
            ++word;
        } else if (*mac == ':') {
            if (word == 0 || word / 2 - 1 != symbol) {
                break;
            }
            ++symbol;
        } else {
            symbol = EOF;
        }
        ++mac;
    }
    return word == 12 && symbol == 5;
}

// 將 MAC 字串轉為位元陣列
// 不用時需手動釋放記憶體
unsigned char* MACAddressToByteArray(const char* mac) {
    unsigned char* ret = malloc(ETH_ALEN);
    sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &ret[0], &ret[1], &ret[2], &ret[3], &ret[4], &ret[5]);
    return ret;
}
