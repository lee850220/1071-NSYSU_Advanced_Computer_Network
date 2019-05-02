#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>

#include "fill_packet.h"

extern pid_t pid;
extern u_int16_t seq;

void fill_iphdr(struct ip *ip_hdr, const u_int32_t src_ip, const u_int32_t dst_ip) {

    ip_hdr->ip_v = IPVERSION;
    ip_hdr->ip_hl = (uint8_t)IP_HEADER_SIZE;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(PACKET_SIZE);
    ip_hdr->ip_id = 0;
    ip_hdr->ip_off = htons(IP_DF);
    ip_hdr->ip_ttl = ICMP_TTL;
    ip_hdr->ip_p = ICMP;
    //ip_hdr->ip_sum;
    ip_hdr->ip_src = *(struct in_addr*)&src_ip;
    ip_hdr->ip_dst = *(struct in_addr*)&dst_ip;

}

void fill_icmphdr(struct icmphdr *icmp_hdr) {
    
    icmp_hdr->type = 8;
    icmp_hdr->code = 0;
    icmp_hdr->un.echo.id = htons(pid);
    icmp_hdr->un.echo.sequence = htons(seq);

}

u16 ip_checksum(u16* data, size_t len) {

    size_t i;

    // Initialise the accumulator.
    uint32_t acc=0x0000;

    // Handle complete 16-bit blocks.
    for (i = 0; i < len; i += 2) {
        u16 word;
        memcpy(&word, &data[i], 2);
        acc += ntohs(word);
        if (acc > 0xffff) {
            acc -= 0xffff;
        }
    }

    // Handle any partial block at the end of the data.
    if (len % 2 == 1) {
        u16 word = 0;
        memcpy(&word, data + len - 1, 1);
        acc += ntohs(word);
        if (acc > 0xffff) {
            acc -= 0xffff;
        }
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}

void fill_cksum(struct icmphdr *icmp_hdr) {
    
    //memset(&icmp_hdr->checksum, 0, sizeof(u16));
    icmp_hdr->checksum = ip_checksum((u16*)icmp_hdr, 64);
    
}