#ifndef __PCAP__H_
#define __PCAP__H_

#include <arpa/inet.h>
#include <linux/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "fill_packet.h"

#define FILTER_STRING_SIZE 100
#define IPV4_CHAR_LEN 16

void pcap_init(const char* const dst_ip, int timeout);

int pcap_get_reply(void);

#endif
