#include <stdint.h>

/* eth */
#define ETH_ALEN 6
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806

struct libnet_ethernet_hdr {
	uint8_t ether_dhost[ETH_ALEN];
	uint8_t ether_shost[ETH_ALEN];
	uint16_t ether_type;
};

/* ipv4 */

struct libnet_ipv4_hdr 
{
    u_int8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */
    u_int8_t ip_tos;       /* type of service */

    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;

    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};


/* tcp */
struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
    
    u_int8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */
    
    u_int8_t  th_flags;       /* control flags */
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

/* arp */
struct libnet_arp_hdr
{
	u_int16_t arp_htype; //hardware type
	u_int16_t arp_ptype; //protocol type
	u_int8_t arp_hlen; //hardware address length
	u_int8_t arp_plen; //protocol address length
	u_int16_t arp_opcode; //operation code
	u_char send_mac[6]; //sender mac
	u_char send_ip[4]; //sender ip
	u_char target_mac[6]; //receiver mac
	u_char target_ip[4]; //receiver ip
      
};
