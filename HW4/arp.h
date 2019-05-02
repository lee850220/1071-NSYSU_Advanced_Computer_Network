#ifndef __ARP_UTIL_H__
#define __ARP_UTIL_H__

/*     Definition Parameters     */
#define HARDWARE_ADDR_STR_UNIT		2
#define PROTOCOL_ADDR_STR_UNIT		3
#define HARDWARE_ADDR_LENGTH 		6
#define PROTOCOL_ADDR_LENGTH 		4

#define ETH_DST_LENGTH				6
#define ETH_SRC_LENGTH				6
#define ETH_TYPE_LENGTH				2
#define HARDWARE_TYPE_LENGTH		2
#define PROTOCOL_TYPE_LENGTH		2
#define HARDWARE_SIZE_LENGTH		1
#define PROTOCOL_SIZE_LENGTH		1
#define OPCODE_LENGTH				2
#define SEND_HARDWARE_ADDR_LENGTH	6
#define SEND_PROTOCOL_ADDR_LENGTH	4
#define TARG_HARDWARE_ADDR_LENGTH	6
#define TARG_PROTOCOL_ADDR_LENGTH	4
#define ARP_PACKET_LENGTH			42

#define ETH_DST_OFFSET				0
#define ETH_SRC_OFFSET				6
#define ETH_TYPE_OFFSET				12
#define HARDWARE_TYPE_OFFSET		14
#define PROTOCOL_TYPE_OFFSET		16
#define HARDWARE_SIZE_OFFSET		18
#define PROTOCOL_SIZE_OFFSET		19
#define OPCODE_OFFSET				20
#define SEND_HARDWARE_ADDR_OFFSET	22
#define SEND_PROTOCOL_ADDR_OFFSET	28
#define TARG_HARDWARE_ADDR_OFFSET	32
#define TARG_PROTOCOL_ADDR_OFFSET	38

/*     Dependent Library     */
#ifdef WIN32

#define ETH_ALEN HARDWARE_ADDR_LENGTH
#define u_int8_t uint8_t
#define u_int16_t uint16_t

typedef unsigned short u_short;
typedef unsigned char u_char;
typedef u_char u_int8_t;
typedef u_short u_int16_t;

struct arphdr {
	u_short	ar_hrd;		/* format of hardware address */
#define ARPHRD_ETHER 	1	/* ethernet hardware format */
#define ARPHRD_FRELAY 	15	/* frame relay hardware format */
	u_short	ar_pro;		/* format of protocol address */
	u_char	ar_hln;		/* length of hardware address */
	u_char	ar_pln;		/* length of protocol address */
	u_short	ar_op;		/* one of: */
#define	ARPOP_REQUEST	1	/* request to resolve address */
#define	ARPOP_REPLY	2	/* response to previous request */
#define	ARPOP_REVREQUEST 3	/* request protocol address given hardware */
#define	ARPOP_REVREPLY	4	/* response giving protocol address */
#define ARPOP_INVREQUEST 8 	/* request to identify peer */
#define ARPOP_INVREPLY	9	/* response identifying peer */
/*
 * The remaining fields are variable in size,
 * according to the sizes above.
 */
#ifdef COMMENT_ONLY
	u_char	ar_sha[];	/* sender hardware address */
	u_char	ar_spa[];	/* sender protocol address */
	u_char	ar_tha[];	/* target hardware address */
	u_char	ar_tpa[];	/* target protocol address */
#endif
};

struct ether_header
{
  uint8_t  ether_dhost[ETH_ALEN];	/* destination eth addr	*/
  uint8_t  ether_shost[ETH_ALEN];	/* source ether addr	*/
  uint16_t ether_type;		        /* packet type ID field	*/
} __attribute__ ((__packed__));

struct	ether_arp {
	struct	arphdr ea_hdr;		/* fixed-size header */
	uint8_t arp_sha[ETH_ALEN];	/* sender hardware address */
	uint8_t arp_spa[4];		/* sender protocol address */
	uint8_t arp_tha[ETH_ALEN];	/* target hardware address */
	uint8_t arp_tpa[4];		/* target protocol address */
};

//#include <winsock.h>

#else

#include <netinet/if_ether.h>
#include <net/ethernet.h>

#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*     Data Structure     */

struct arp_packet {

	struct ether_header eth_hdr;
	struct ether_arp arp;

} __attribute__((packed));

typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;

/*     Function Declaration     */
void print_usage();

void set_ether_dhost(struct ether_header*, uchar*);
void set_ether_shost(struct ether_header*, uchar*);
void set_ether_type(struct ether_header*, ushort);

void set_hard_type(struct ether_arp*, ushort);
void set_prot_type(struct ether_arp*, ushort);
void set_hard_size(struct ether_arp*, uchar);
void set_prot_size(struct ether_arp*, uchar);
void set_op_code(struct ether_arp*, short);

void set_sender_hardware_addr(struct ether_arp*, uchar*);
void set_sender_protocol_addr(struct ether_arp*, uchar*);
void set_target_hardware_addr(struct ether_arp*, uchar*);
void set_target_protocol_addr(struct ether_arp*, uchar*);
void get_target_protocol_addr(struct ether_arp*, char*); 
void get_sender_protocol_addr(struct ether_arp*, char*); 
void get_sender_hardware_addr(struct ether_arp*, char*); 
void get_target_hardware_addr(struct ether_arp*, char*); 

#endif
