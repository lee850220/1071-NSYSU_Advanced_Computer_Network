#ifndef __FILLPACKET__H_
#define __FILLPACKET__H_

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string.h>

typedef unsigned char u8;
typedef unsigned short u16;

#define ICMP				0x01
#define ICMP_TTL			1
#define PACKET_SIZE 		92
#define IP_OPTION_SIZE 		8
#define IP_HEADER_SIZE      (sizeof(struct ip) + IP_OPTION_SIZE) / 4
#define ICMP_PACKET_SIZE    PACKET_SIZE - (int)sizeof(struct ip) - IP_OPTION_SIZE
#define ICMP_DATA_SIZE      ICMP_PACKET_SIZE - (int)sizeof(struct icmphdr)
#define DEFAULT_SEND_COUNT 	4
#define DEFAULT_TIMEOUT 	1500

typedef struct {

    struct ip ip_hdr;
    u8 ip_option[IP_OPTION_SIZE];
    struct icmphdr icmp_hdr;
    u8 data[ICMP_DATA_SIZE];

} myicmp;

void fill_iphdr(struct ip *ip_hdr, const u_int32_t src_ip, const u_int32_t dst_ip);

void fill_icmphdr(struct icmphdr *icmp_hdr);

void fill_cksum(struct icmphdr *icmp_hdr);

u16 ip_checksum(u16* data, size_t len);

#endif
