#define MAX_LEN 100
#define MAX_SSID 20
#include "function.h"



int main(int argc, char* argv[]) {

    if(argc != 3) {
        printf("\nsyntax : beacon-flood <interface> <ssid-list-file>\n");
        printf("sample : beacon-flood mon0 ssid-list.txt\n");
        exit(1);
    }

    char* dev = argv[1];
   // char* txt[MAX_SSID][MAX_LEN] = {0}; //SSID

    //txt read
   /* FILE *fp = fopen(argv[2], "r");
    if(fp == NULL) {
        printf("\n<file is not existed!>\n");
        exit(1);
    }

    printf("\n-----SSID NAME------");
    for(;fgets(txt[line],100, fp); line++)
        printf("\n%d. %s", line+1, txt[line]);*/

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
            fprintf(stderr, "couldn't open device %s: %s (handle)\n", dev, errbuf);
            return -1;
    }

    int size = sizeof(radiotap_header) + sizeof(Dot11) + strlen(argv[2]) + 1;
    u_char beacon_packet[size];

//    for(int i = 0; i < line; i++) {
        memset(beacon_packet, 0, size);
        make_beacon_packet(beacon_packet, argv[2]);
        insert((char*)beacon_packet, argv[2], sizeof(radiotap_header)-2 + sizeof(Dot11) - 10, sizeof(beacon_packet));
//    }


    //debug
/*    int i = 0;
    for(; i<sizeof(beacon_packet); i++)
        printf("%x  ",beacon_packet[i]);
    printf("\n(%d)\n",i);
    exit(1);*/

   while(1){// for(int i = 0; i<line; i++){
        if(pcap_sendpacket(handle, beacon_packet, sizeof(beacon_packet)) != 0)
            printf("\nError sending the packet(pcap_sendpacket(packet~) \n");
      //  if(i == line-1)
      //      i = 0;
        usleep(5000);
    }
}
