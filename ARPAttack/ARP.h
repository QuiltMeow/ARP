#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <netpacket/packet.h>

// 乙太網路包頭長度
#define ETHER_HEADER_LENGTH sizeof(struct ether_header)

// ARP 結構長度
#define ETHER_ARP_LENGTH sizeof(struct ether_arp)

// ARP 封包長度
#define ETHER_ARP_PACKET_LENGTH ETHER_HEADER_LENGTH + ETHER_ARP_LENGTH

// IPv4 位址長度
#define IP_ADDRESS_LENGTH 4
#define IP_ADDRESS_STRING_MAX_LENGTH 16

// 廣播 MAC 位址
#define BROADCAST_MAC_ADDRESS { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }

// 全零 MAC 位址 (ARP 請求封包目標 MAC 位址)
#define ZERO_MAC_ADDRESS { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }

// 無效 Socket 錯誤碼
#define INVALID_SOCKET -1

// 填充 ARP 請求封包
struct ether_arp* fillARPRequestPacket(const unsigned char* srcMACAddress, const char* srcIPAddress, const char* dstIPAddress) {
    struct in_addr srcIP, dstIP;
    unsigned char dstMACAddress[ETH_ALEN] = ZERO_MAC_ADDRESS;

    // IP 位址轉換
    inet_pton(AF_INET, srcIPAddress, &srcIP);
    inet_pton(AF_INET, dstIPAddress, &dstIP);

    // ARP 封包填充
    struct ether_arp* ret = (struct ether_arp*) malloc(ETHER_ARP_LENGTH);
    ret->arp_hrd = htons(ARPHRD_ETHER); // 硬體位址格式
    ret->arp_pro = htons(ETHERTYPE_IP); // 協定位址格式
    ret->arp_hln = ETH_ALEN; // 硬體位址長度
    ret->arp_pln = IP_ADDRESS_LENGTH; // 協定位址長度
    ret->arp_op = htons(ARPOP_REQUEST); // 類型 (請求)
    memcpy(ret->arp_sha, srcMACAddress, ETH_ALEN); // 來源 MAC 位址
    memcpy(ret->arp_tha, dstMACAddress, ETH_ALEN); // 目標 MAC 位址
    memcpy(ret->arp_spa, &srcIP, IP_ADDRESS_LENGTH); // 來源 IP 位址
    memcpy(ret->arp_tpa, &dstIP, IP_ADDRESS_LENGTH); // 目標 IP 位址
    return ret;
}

// 填充 ARP 欺騙請求封包 [自我更新]
struct ether_arp* fillARPSpoofRequestPacket(const u_int8_t* srcMACAddress, const u_int8_t* srcIPAddress) {
    unsigned char dstMACAddress[ETH_ALEN] = ZERO_MAC_ADDRESS;

    // ARP 封包填充
    struct ether_arp* ret = (struct ether_arp*) malloc(ETHER_ARP_LENGTH);
    ret->arp_hrd = htons(ARPHRD_ETHER); // 硬體位址格式
    ret->arp_pro = htons(ETHERTYPE_IP); // 協定位址格式
    ret->arp_hln = ETH_ALEN; // 硬體位址長度
    ret->arp_pln = IP_ADDRESS_LENGTH; // 協定位址長度
    ret->arp_op = htons(ARPOP_REQUEST); // 類型 (請求)
    memcpy(ret->arp_sha, srcMACAddress, ETH_ALEN); // 來源 MAC 位址
    memcpy(ret->arp_tha, dstMACAddress, ETH_ALEN); // 目標 MAC 位址
    memcpy(ret->arp_spa, srcIPAddress, IP_ADDRESS_LENGTH); // 來源 IP 位址
    memcpy(ret->arp_tpa, srcIPAddress, IP_ADDRESS_LENGTH); // 目標 IP 位址
    return ret;
}

// 填充 ARP 欺騙回應封包
struct ether_arp* fillARPReplySpoofPacket(const u_int8_t* srcMACAddress, const u_int8_t* srcIPAddress, const u_int8_t* dstIPAddress, const u_int8_t* fakeMACAddress) {
    // ARP 封包填充
    struct ether_arp* ret = (struct ether_arp*) malloc(ETHER_ARP_LENGTH);
    ret->arp_hrd = htons(ARPHRD_ETHER); // 硬體位址格式
    ret->arp_pro = htons(ETHERTYPE_IP); // 協定位址格式
    ret->arp_hln = ETH_ALEN; // 硬體位址長度
    ret->arp_pln = IP_ADDRESS_LENGTH; // 協定位址長度
    ret->arp_op = htons(ARPOP_REPLY); // 類型 (回應)
    memcpy(ret->arp_sha, fakeMACAddress, ETH_ALEN); // 來源 MAC 位址
    memcpy(ret->arp_tha, srcMACAddress, ETH_ALEN); // 目標 MAC 位址
    memcpy(ret->arp_spa, dstIPAddress, IP_ADDRESS_LENGTH); // 來源 IP 位址
    memcpy(ret->arp_tpa, srcIPAddress, IP_ADDRESS_LENGTH); // 目標 IP 位址
    return ret;
}
