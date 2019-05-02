/*     Dependent Library     */
#include "arp.h"


/*     Function Definition     */

/*
 *	Set Ethernet destination address.
 *	Input:	Ethernet header structure, address
 *  Output:	void
 */
void set_ether_dhost(struct ether_header* packet, u8* address) {
	memcpy(packet->ether_dhost, address, HARDWARE_ADDR_LENGTH);
}

/*
 *	Set Ethernet source address.
 *	Input:	Ethernet header structure, address
 *  Output:	void
 */
void set_ether_shost(struct ether_header* packet, u8* address) {
	memcpy(packet->ether_shost, address, HARDWARE_ADDR_LENGTH);
}

/*
 *	Set Ethernet packet type.
 *	Input:	Ethernet header structure, type
 *  Output:	void
 */
void set_ether_type(struct ether_header* packet, ushort type) {
	packet->ether_type = type;
}

/*
 *	Set hardware type of ARP frame.
 *	Input:	ARP frame structure, type
 *  Output:	void
 */
void set_hard_type(struct ether_arp* packet, ushort type) {
	packet->ea_hdr.ar_hrd = type;
}

/*
 *	Set protocol type of ARP frame.
 *	Input:	ARP frame structure, type
 *  Output:	void
 */
void set_prot_type(struct ether_arp* packet, ushort type) {
	packet->ea_hdr.ar_pro = type;
}

/*
 *	Set hardware size of ARP frame.
 *	Input:	ARP frame structure, size
 *  Output:	void
 */
void set_hard_size(struct ether_arp* packet, u8 size) {
	packet->ea_hdr.ar_hln = size;
}

/*
 *	Set protocol size of ARP frame.
 *	Input:	ARP frame structure, size
 *  Output:	void
 */
void set_prot_size(struct ether_arp* packet, u8 size) {
	packet->ea_hdr.ar_pln = size;
}

/*
 *	Set op code of ARP frame.
 *	Input:	ARP frame structure, op code
 *  Output:	void
 */
void set_op_code(struct ether_arp* packet, short code) {
	packet->ea_hdr.ar_op = code;
}

/*
 *	Set sender's hardware address of ARP frame.
 *	Input:	ARP frame structure, address
 *  Output:	void
 */
void set_sender_hardware_addr(struct ether_arp* packet, u8* address) {
	//packet->arp_sha = (u_char*)malloc(sizeof(u_char) * HARDWARE_ADDR_LENGTH);
	memcpy(packet->arp_sha, address, HARDWARE_ADDR_LENGTH);
}

/*
 *	Set sender's protocol address of ARP frame.
 *	Input:	ARP frame structure, address
 *  Output:	void
 */
void set_sender_protocol_addr(struct ether_arp* packet, u8* address) {
	memcpy(packet->arp_spa, address, PROTOCOL_ADDR_LENGTH);
}

/*
 *	Set target's hardware address of ARP frame.
 *	Input:	ARP frame structure, address
 *  Output:	void
 */
void set_target_hardware_addr(struct ether_arp* packet, u8* address) {
	memcpy(packet->arp_tha, address, HARDWARE_ADDR_LENGTH);
}

/*
 *	Set target's protocol address of ARP frame.
 *	Input:	ARP frame structure, address
 *  Output:	void
 */
void set_target_protocol_addr(struct ether_arp* packet, u8* address) {
	memcpy(packet->arp_tpa, address, PROTOCOL_ADDR_LENGTH);
}

/*
 *	Get sender's hardware address of ARP frame.
 *	Input:	ARP frame structure
 *  Output:	address
 */
void get_sender_hardware_addr(struct ether_arp* packet, char* address) {
	
	int i;
	char tmp[HARDWARE_ADDR_STR_UNIT + 1];
	memset(tmp, 0, sizeof(tmp));
	for (i = 0; i < HARDWARE_ADDR_LENGTH; i++) {
		sprintf(tmp, "%02x", packet->arp_sha[i]);
		strcat(address, tmp);
		if (i == HARDWARE_ADDR_LENGTH - 1) break;
		strcat(address, ":");
	}
}

/*
 *	Get sender's protocol address of ARP frame.
 *	Input:	ARP frame structure
 *  Output:	address
 */
void get_sender_protocol_addr(struct ether_arp* packet, char* address) {
	
	int i;
	char tmp[PROTOCOL_ADDR_STR_UNIT + 1];
	memset(tmp, 0, sizeof(tmp));
	for (i = 0; i < PROTOCOL_ADDR_LENGTH; i++) {
		sprintf(tmp, "%d", packet->arp_spa[i]);
		strcat(address, tmp);
		if (i == PROTOCOL_ADDR_LENGTH - 1) break;
		strcat(address, ".");
	}
}

/*
 *	Get target's hardware address of ARP frame.
 *	Input:	ARP frame structure
 *  Output:	address
 */
void get_target_hardware_addr(struct ether_arp* packet, char* address) {
	int i;
	char tmp[HARDWARE_ADDR_STR_UNIT + 1];
	memset(tmp, 0, sizeof(tmp));
	for (i = 0; i < HARDWARE_ADDR_LENGTH; i++) {
		sprintf(tmp, "%02x", packet->arp_tha[i]);
		strcat(address, tmp);
		if (i == HARDWARE_ADDR_LENGTH - 1) break;
		strcat(address, ":");
	}
}

/*
 *	Get target's protocol address of ARP frame.
 *	Input:	ARP frame structure
 *  Output:	address
 */
void get_target_protocol_addr(struct ether_arp* packet, char* address) {

	int i;
	char tmp[PROTOCOL_ADDR_STR_UNIT + 1];
	memset(tmp, 0, sizeof(tmp));
	for (i = 0; i < PROTOCOL_ADDR_LENGTH; i++) {
		sprintf(tmp, "%d", packet->arp_tpa[i]);
		strcat(address, tmp);
		if (i == PROTOCOL_ADDR_LENGTH - 1) break;
		strcat(address, ".");
	}
}
