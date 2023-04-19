#include "header.h"
/*void flag_assign(radiotap_header* r) { // for beacon frame

//present_flags set


    r->present_flags.flags = 1;
    r->present_flags.rate = 1;
    r->present_flags.channel = 1;
    r->present_flags.dbm_antenna_sig = 1;
    r->present_flags.antenna = 1;
    r->present_flags.rx_flags = 1;

//(basic)flags set

//channel_flags set
    r->channel_flags.cck = 1;
    r->channel_flags.two_ghz = 1;
 }*/

void insert (char *m, char *s, int n, int size) {

    for(int i = 1; i<=size-n-strlen(s); i++)
        m[size-i] = m[size-strlen(s)-i];

    memmove(m+n, s, strlen(s));
}

void make_beacon_packet(u_char* beacon_packet, char* title){

    radiotap_header r_header;

    //radiotap_header make
    r_header.version = 0;
    r_header.pad = 0;
    r_header.len = 0x1a;
    //r_header.data_rate = 2;
    r_header.c_frequency = 2412;
    r_header.ant_signal = 0xce;
    r_header.ant = 0;
    r_header.rx_flags = 0;

    //flag
    r_header.present_flags = 0x0000482b;
    memset(r_header.mac_timestamp, 0,sizeof(r_header.mac_timestamp));
    r_header.flags = 0x10;
    r_header.channel_flags = 0x00a0;

    memcpy(beacon_packet, &r_header, sizeof(r_header)-2); // 2 is padding (size allocation -> *4)

    Dot11 dot11;

    //dot11_header make
    //dot11 frame_control_field
    dot11.Frame_Control_Field.Version = 0;
    dot11.Frame_Control_Field.Type = 0;
    dot11.Frame_Control_Field.Subtype = 8;
    dot11.Frame_Control_Field.Flags =0;

    //beacon frame
    dot11.duration = 0;
    dot11.number = 0;
    memset(dot11.dest_mac, 0xff, sizeof(dot11.dest_mac));
    memset(dot11.src_mac, 0x11, sizeof(dot11.src_mac));
    memset(dot11.bssid_mac, 0, sizeof(dot11.src_mac));

    //wireless management
    //SSID para
    memset(dot11.fixed_para, 0,sizeof(dot11.fixed_para));
    dot11.tag.para_set = 0;
    dot11.tag.stag_len = strlen(title) + 1; //space
    //SSID name
    dot11.tag.name = ' ';

    //Channel para
    dot11.tag.ds_para = 3;
    dot11.tag.ctag_len = 1;
    dot11.tag.channel = 10; //10channel use

    //Rates para
    dot11.tag.tag_num = 1;
    dot11.tag.rtag_len = 3;
    dot11.tag.rate[0] = 0x82;
    dot11.tag.rate[1] = 0x8b;
    dot11.tag.rate[2] = 0x96;

    memcpy(beacon_packet + sizeof(r_header)-2, &dot11, sizeof(dot11));
}
