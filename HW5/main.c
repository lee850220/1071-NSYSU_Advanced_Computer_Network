/*     Dependent Library     */
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>


#include "fill_packet.h"
#include "pcap.h"
#include "arp.h"

/*     Definition Parameters     */
#define CLEAR                   	"\33[H\33[2J"
#define COLOR_NORMAL            	COLOR_GREEN_BLACK
#define COLOR_B_RED              	"\033[1;31m"
#define COLOR_B_WHITE               "\033[1;37m"
#define COLOR_B_YELLOW          	"\033[1;33m"
#define COLOR_B_LIGHTBLUE       	"\033[1;36m"
#define COLOR_B_LIGHTPURPLE     	"\033[1;35m"
#define COLOR_GREEN_BLACK       	"\033[1;32;40m"
#define ICMP_DATA					"M073040099"
#define ARP_PACKET_LENGTH			42
#define ETH_PROTOCOL_TYPE_ARP       0x0806
#define RECV_NORMAL             	0
#define SEND_NORMAL                 0
#define HARDWARE_TYPE_ETHERNET      0x0001
#define PROTOCOL_TYPE_IPV4          0x0800
#define OPCODE_REQ                  0x0001
#define OPCODE_REPLY                0x0002
#define PROTOCOL_ADDR_STR_LENGTH 	16
#define HARDWARE_ADDR_STR_LENGTH	18

#define MSG_ARP_REPLY               "["COLOR_B_LIGHTBLUE"ARP Reply "COLOR_NORMAL"to "COLOR_B_WHITE"%s"COLOR_NORMAL"]: "COLOR_B_YELLOW"%s"COLOR_NORMAL" is at %s\n"

/*     Global Variable Declaration     */
pid_t pid;
char dev[IFNAMSIZ] = "";
u_int16_t seq = 0;
extern u_int32_t net;
extern u_int32_t mask;

/*     Function Declaration     */
int cal_subhost(const u_int32_t);
void uint_32touchar4(u_int32_t*);
void set_arp(struct arp_packet*, u8* const);
ushort strutons(u8*);
/*---------------------------------MAIN Function---------------------------------*/

int main(int argc, char *argv[]) {
	
	u_int32_t i, hosts;
	int sockfd, sockfd_send;
    int on = 1;
	int count = DEFAULT_SEND_COUNT;
    int timeout = DEFAULT_TIMEOUT;
	char target_ip[IPV4_CHAR_LEN] = "";
	struct ifreq req;
	struct sockaddr_in dst;
	struct sockaddr_ll sa;
	struct in_addr sender_ip, trg;
	u8 buf[ARP_PACKET_LENGTH];
	socklen_t len;
    myicmp *packet = (myicmp *)malloc(PACKET_SIZE);
	memset(packet, 0, sizeof(PACKET_SIZE));

	pid = getpid();

	if (argc >= 5) {
		timeout = atoi(argv[4]);
	}

    /* initialize the pcap */
	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("socket");
        exit(1);
    }

	// Open a send socket in data-link layer.
    if((sockfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror(COLOR_B_RED"open send socket error"COLOR_NORMAL);
        exit(1);
    }

	/* get interface ip */
	memcpy(dev, argv[2], IFNAMSIZ);
	strncpy(req.ifr_name, dev, IFNAMSIZ);
	if (ioctl(sockfd, SIOCGIFADDR, &req) == -1) {
		perror(COLOR_B_RED"get self IP address failed"COLOR_NORMAL);
		exit(1);
	}

	/* set socket property */
	if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt");
        exit(1);
    }


	/* init capture program */
	struct sockaddr_in* addr = (struct sockaddr_in*)&req.ifr_addr;
	struct in_addr src;
	memcpy(&src, &addr->sin_addr, sizeof(src));
	strcpy(target_ip, inet_ntoa(addr->sin_addr));
    pcap_init(target_ip, timeout);
	hosts = cal_subhost(~mask);

	/* get interface info */
	strncpy(req.ifr_name, dev, IFNAMSIZ);
	if (ioctl(sockfd, SIOCGIFINDEX, &req) == -1) {
		perror(COLOR_B_RED"get interface info failed"COLOR_NORMAL);
		exit(1);
	}	


	/* setup sockaddr_ll structure */
	bzero(&dst, sizeof(dst));
	//dst.sll_family   = AF_PACKET;                    // protocol family
	//dst.sll_protocol = 0;							 // Physical-layer protocol
	/*dst.sll_ifindex  = req.ifr_ifindex;              // interface number
	dst.sll_hatype   = 0;                 // ARP hardware type
	dst.sll_pkttype  = 4;             // packet type
	dst.sll_halen    = 0;                            // Length of address*/
	//memcpy(dst.sll_addr, 0, sizeof(dst.sll_addr));    // Physical-layer address

	/* get self MAC */
	if (ioctl(sockfd, SIOCGIFHWADDR, &req) == -1) {
		perror(COLOR_B_RED"get self MAC failed"COLOR_NORMAL);
		exit(1);
	}

	//memcpy(dst.sll_addr, req.ifr_hwaddr.sa_data, sizeof(u8) * 6);   // Ethernet SRC address

	/* set ethernet layer header */
	bzero(&dst, sizeof(dst));
	dst.sin_family = AF_INET;
	//sp = getservbyname("icmp", "icmp");
	dst.sin_port = 0;
	dst.sin_addr = *(struct in_addr*)&addr->sin_addr;
	//memset(&dst.sin_zero, 0, sizeof(dst.sin_zero));

	
	/* send request to all subnet host */ 
	for (i = 1; i <= hosts; i++) {
		
		u_int32_t target = net + htonl(i);

		/* send ARP request */
		if (1) {
			
			struct ether_header* eth = (struct ether_header*)buf;
			struct ether_arp* arp = (struct ether_arp*)(buf + 14);

			memset(buf, 0, sizeof(buf));
			
			/* get interface info */
			strncpy(req.ifr_name, dev, IFNAMSIZ);
			if (ioctl(sockfd, SIOCGIFINDEX, &req) == -1) {
				perror(COLOR_B_RED"get interface info failed"COLOR_NORMAL);
				exit(1);
			}
			
			/* setup sockaddr_ll structure */
			sa.sll_family   = PF_PACKET;                    // protocol family
			sa.sll_protocol = htons(ETH_PROTOCOL_TYPE_ARP); // Physical-layer protocol
			sa.sll_ifindex  = req.ifr_ifindex;              // interface number
			sa.sll_hatype   = ARPHRD_ETHER;                 // ARP hardware type
			sa.sll_pkttype  = PACKET_BROADCAST;             // packet type
			sa.sll_halen    = 0;                            // Length of address
			memset(sa.sll_addr, 0, sizeof(sa.sll_addr));    // Physical-layer address

			/* get self MAC */
			if (ioctl(sockfd, SIOCGIFHWADDR, &req) == -1) {
				perror(COLOR_B_RED"get self MAC failed"COLOR_NORMAL);
				exit(1);
			}
			
			/* fill ARP frame */
			// fill ethernet header
			memset(eth->ether_dhost, 255, sizeof(u8) * ETH_DST_LENGTH); // Ethernet DST address (broadcast=ff:ff:ff:ff:ff:ff) (ff in dec is 255)
			memcpy(eth->ether_shost, req.ifr_hwaddr.sa_data, sizeof(u8) * ETH_DST_LENGTH); // Ethernet SRC address
			eth->ether_type = htons(ETH_PROTOCOL_TYPE_ARP);
			//printf("Successfully got our MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",req.ifr_hwaddr.sa_data[0],req.ifr_hwaddr.sa_data[1],req.ifr_hwaddr.sa_data[2],req.ifr_hwaddr.sa_data[3],req.ifr_hwaddr.sa_data[4],req.ifr_hwaddr.sa_data[5]);
			//printf("address: %02X:%02X:%02X:%02X:%02X:%02X\n",eth->ether_shost[0],eth->ether_shost[1],eth->ether_shost[2],eth->ether_shost[3],eth->ether_shost[4],eth->ether_shost[5]);
			//printf("%04X\n", eth->ether_type);

			/* get self IP address */
			if (ioctl(sockfd, SIOCGIFADDR, &req) == -1) {
				perror(COLOR_B_RED"get self IP address failed"COLOR_NORMAL);
				exit(1);
			}

			struct sockaddr_in* addr = (struct sockaddr_in*)&req.ifr_addr;

			// fill ARP request
			arp->ea_hdr.ar_hrd  = htons(HARDWARE_TYPE_ETHERNET);    // hardware type
			arp->ea_hdr.ar_pro  = htons(PROTOCOL_TYPE_IPV4);        // protocol type
			arp->ea_hdr.ar_hln  = HARDWARE_ADDR_LENGTH;             // hardware addr size
			arp->ea_hdr.ar_pln  = PROTOCOL_ADDR_LENGTH;             // protocol addr size
			arp->ea_hdr.ar_op   = htons(OPCODE_REQ);                // opcode

			memcpy(arp->arp_sha, eth->ether_shost, sizeof(u8) * SEND_HARDWARE_ADDR_LENGTH);          // sender's hardware address
			memcpy(arp->arp_spa, &addr->sin_addr, sizeof(u8) * SEND_PROTOCOL_ADDR_LENGTH);           // sender's protocol address
			memset(arp->arp_tha, 0, sizeof(u8) * TARG_HARDWARE_ADDR_LENGTH);                         // target's hardware address (not set)
			memcpy(arp->arp_tpa, &target, sizeof(u8) * TARG_PROTOCOL_ADDR_LENGTH);         		// target's protocol address
			
			// send ARP request
			if (sendto(sockfd_send, buf, sizeof(buf), SEND_NORMAL, (struct sockaddr*)&sa, sizeof(sa)) == -1) {
				perror(COLOR_B_RED"sendto():"COLOR_NORMAL);
				exit(1);
			}
			
			// print request message
			//printf(MSG_ARP_REQUEST_1, inet_ntoa(*(struct in_addr*)&arp->arp_tpa));
			//printf(MSG_ARP_REQUEST_2, inet_ntoa(*(struct in_addr*)&arp->arp_spa));

			//printf(MSG_WAIT_REPLY);
			memcpy(&sender_ip.s_addr, &arp->arp_tpa, sizeof(u8) * SEND_PROTOCOL_ADDR_LENGTH); // filter sender's IP for target IP
		}

		/* receive ARP reply */
		while (1) {

			char *tmp, *tmp2, *tmp3;
			struct arp_packet packet;
			memset(buf, 0, ARP_PACKET_LENGTH);
			recvfrom(sockfd, buf, sizeof(buf), RECV_NORMAL, &recv, &len); // catching packets
			set_arp(&packet, buf); // fill arp packet info

			/* catch ARP packet (Type=0x0806) */
			if (htons(packet.eth_hdr.ether_type) == ETH_PROTOCOL_TYPE_ARP) {
				
				/* ARP Request */
				if (htons(packet.arp.ea_hdr.ar_op) == OPCODE_REPLY) {

					/* when "wrong sender IP" skip */
					if (*(u_int32_t*)packet.arp.arp_spa != sender_ip.s_addr) continue;

						tmp = (char*)malloc(sizeof(char) * PROTOCOL_ADDR_STR_LENGTH);
						tmp2 = (char*)malloc(sizeof(char) * HARDWARE_ADDR_STR_LENGTH);
						tmp3 = (char*)malloc(sizeof(char) * PROTOCOL_ADDR_STR_LENGTH);
						memset(tmp, 0, sizeof(PROTOCOL_ADDR_STR_LENGTH));
						memset(tmp2, 0, sizeof(HARDWARE_ADDR_STR_LENGTH));
						memset(tmp3, 0, sizeof(PROTOCOL_ADDR_STR_LENGTH));
						get_sender_protocol_addr(&packet.arp, tmp);
						get_sender_hardware_addr(&packet.arp, tmp2);
						get_target_protocol_addr(&packet.arp, tmp3);
						printf(MSG_ARP_REPLY"\n", tmp3, tmp, tmp2);
						free(tmp);
						free(tmp2);
						free(tmp3);

					break;

				}

			}

		}

		/* fill sending packet */
		seq = i;
		memset(packet, 0, sizeof(PACKET_SIZE));
		fill_iphdr(&packet->ip_hdr, src.s_addr, target);
		fill_icmphdr(&packet->icmp_hdr);
		strcpy(packet->data, ICMP_DATA);
		//fill_cksum(&packet->icmp_hdr);

		
		/* send request */
		printf("Ping %s (data size = %d, id = 0x%x, seq = %d, timeout = %d ms)\n", inet_ntoa(*(struct in_addr*)&target), (int)strlen(ICMP_DATA), pid, seq, timeout);
		if (sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
			perror("sendto");
			exit(1);
    	}

	}

	/* get reply */
	while (1) {
		pcap_get_reply();
	}

    free(packet);

    return 0;
}

int cal_subhost(const u_int32_t imask4) {

	int i;
	u_int32_t tot;
	u8 *p1 = (u8*)&imask4;
	u8 *p2 = (u8*)&tot;
	for (i = 0; i < 4; i++) {
		p2[i] = p1[3 - i];
	}
	return tot;

}

/*
 *	Convert unsigned int to unsigned char.
 *	Input:	converted string, value to convert
 *  Output:	void
 */
void uint_32touchar4(u_int32_t* val) {
    
	u8 str[4];
    str[3] = *val >> 24;
    str[2] = *val >> 16;
    str[1] = *val >> 8;
    str[0] = *val;
	printf("%hhu.%hhu.%hhu.%hhu\n", str[3], str[2], str[1], str[0]);

}


/*
 *	Fill ARP packet from socket.
 *	Input:	packet to fill, message buffer
 *  Output:	void
 */
void set_arp(struct arp_packet* packet, u8* const buf) {

    /* fill ethernet header */
	set_ether_dhost(&packet->eth_hdr, &buf[ETH_DST_OFFSET]);
	set_ether_shost(&packet->eth_hdr, &buf[ETH_SRC_OFFSET]);
	set_ether_type(&packet->eth_hdr, strutons(&buf[ETH_TYPE_OFFSET]));

    /* fill ARP message info */
	set_hard_type(&packet->arp, strutons(&buf[HARDWARE_TYPE_OFFSET]));
	set_prot_type(&packet->arp, strutons(&buf[PROTOCOL_TYPE_OFFSET]));
	set_hard_size(&packet->arp, buf[HARDWARE_SIZE_OFFSET]);
	set_prot_size(&packet->arp, buf[PROTOCOL_SIZE_OFFSET]);
	set_op_code(&packet->arp, strutons(&buf[OPCODE_OFFSET]));

    /* fill ARP address info */
	set_sender_hardware_addr(&packet->arp, &buf[SEND_HARDWARE_ADDR_OFFSET]);
	set_sender_protocol_addr(&packet->arp, &buf[SEND_PROTOCOL_ADDR_OFFSET]);
	set_target_hardware_addr(&packet->arp, &buf[TARG_HARDWARE_ADDR_OFFSET]);
	set_target_protocol_addr(&packet->arp, &buf[TARG_PROTOCOL_ADDR_OFFSET]);

}

/*
 *	Transfer unsigned char to unsigned short.
 *	Input:	unsigned
 *  Output:	unsigned short
 */
ushort strutons(u8* src) {

    int i;
    ushort val;
    u8* tmp = (u8*)malloc(sizeof(u8) * 3);
    memset(tmp, 0, sizeof(u8) * 3);

    for (i = 0; i < 2; i++) {
        tmp[i] = src[i];
    }
    val = *(ushort*)tmp;

    free(tmp);
    return val; 

}