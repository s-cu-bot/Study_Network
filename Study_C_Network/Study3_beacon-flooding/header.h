#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <unistd.h>

extern const int t_len;

typedef struct radiotap_header {
    u_int8_t version; //set to 0
    u_int8_t pad;
    u_int16_t len;

    //Present_flags present_flags;
    u_int32_t present_flags;

    //Mac timestampe
    u_int8_t mac_timestamp[8];

    //Flags flags;
    u_int8_t flags;

    u_int16_t c_frequency;

    //Channel_flags channel_flags;
    u_int16_t channel_flags;
    u_int8_t ant_signal;
    u_int8_t ant;
    u_int16_t rx_flags;
}radiotap_header;

typedef struct Dot11_Frame_Control_Field{
    u_int8_t Version:2;
    u_int8_t Type:2;
    u_int8_t Subtype:4;
    u_int8_t Flags;
}Dot11_Frame_Control_Field;

typedef struct Tagged_para{

    //SSID para
    u_int8_t para_set;
    u_int8_t stag_len;
    u_int8_t name;//same with length

    //Channel para
    u_int8_t ds_para;
    u_int8_t ctag_len;
    u_int8_t channel;

    //Rates para
    u_int8_t tag_num;
    u_int8_t rtag_len;
    u_int8_t rate[3];
}tagged_para;


typedef struct Dot11{
    //802.11 Beacon frame
        Dot11_Frame_Control_Field Frame_Control_Field;
        u_int16_t duration;
        u_int8_t dest_mac[6]; // destination
        u_int8_t src_mac[6]; // source
        u_int8_t bssid_mac[6]; // bssid
        u_int16_t number;

     //802.11 Wireless Management
        u_int32_t fixed_para[3];
        tagged_para tag;

}Dot11;

