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

/*     Definition Parameters     */
#define CLEAR                   	"\33[H\33[2J"
#define COLOR_NORMAL            	COLOR_GREEN_BLACK
#define COLOR_B_RED              	"\033[1;31m"
#define COLOR_B_WHITE               "\033[1;37m"
#define COLOR_B_YELLOW          	"\033[1;33m"
#define COLOR_B_LIGHTBLUE       	"\033[1;36m"
#define COLOR_B_LIGHTPURPLE     	"\033[1;35m"
#define COLOR_GREEN_BLACK       	"\033[1;32;40m"

/*     Global Variable Declaration     */
pid_t pid;
char dev[IFNAMSIZ] = "";
u_int16_t seq = 0;
extern u_int32_t net;
extern u_int32_t mask;

/*     Function Declaration     */
int cal_subhost(const u_int32_t);
void uint_32touchar4(u_int32_t*);
/*---------------------------------MAIN Function---------------------------------*/

int main(int argc, char *argv[]) {
	
	u_int32_t i, hosts;
	int sockfd;
    int on = 1;
	int count = DEFAULT_SEND_COUNT;
    int timeout = DEFAULT_TIMEOUT;
	char target_ip[IPV4_CHAR_LEN] = "";
	struct ifreq req;
	struct sockaddr_in dst;
    myicmp *packet = (myicmp *)malloc(PACKET_SIZE);
	memset(packet, 0, sizeof(PACKET_SIZE));

	pid = getpid();

    /* initialize the pcap */
	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("socket");
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
	strcpy(target_ip, inet_ntoa(addr->sin_addr));
    pcap_init(target_ip, timeout);
	hosts = cal_subhost(~mask);

	

	/* set ethernet layer header */
	bzero(&dst, sizeof(dst));
	dst.sin_family = AF_INET;
	//sp = getservbyname("icmp", "icmp");
	dst.sin_port = 0;
	dst.sin_addr = *(struct in_addr*)&addr->sin_addr;
	//memset(&dst.sin_zero, 0, sizeof(dst.sin_zero));

	
	/* send request to all subnet host */ 
	for (i = 1; i <= hosts; i++) {

		/* fill sending packet */
		seq = i;
		memset(packet, 0, sizeof(PACKET_SIZE));
		fill_iphdr(&packet->ip_hdr, dst.sin_addr.s_addr, net + htonl(i));
		fill_icmphdr(&packet->icmp_hdr);
		strcpy(packet->data, "M073040099");
		//fill_cksum(&packet->icmp_hdr);

		/* send request */
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
