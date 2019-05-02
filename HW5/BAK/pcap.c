#include <netinet/in.h>
#include <pcap/pcap.h>
#include <string.h>
#include <sys/types.h>

#include "pcap.h"


//extern u16 icmp_req;

extern char dev[IFNAMSIZ];
u_int32_t net, mask;

static char filter_string[FILTER_STRING_SIZE] = "";
static pcap_t *p;
static struct pcap_pkthdr hdr;

void pcap_init(const char* const dst_ip, int timeout) {

    int ret;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fcode;

    /* get subnet network ip & mask */
    ret = pcap_lookupnet(dev, &net, &mask, errbuf);
    if (ret == -1) {
        fprintf(stderr, "%s\n", errbuf);
        exit(1);
    }

    /* open a device for capturing */
    p = pcap_open_live(dev, 8000, 1, timeout, errbuf);
    if (!p) {
        fprintf(stderr, "%s\n", errbuf);
        exit(1);
    }

    /* set capture filter string (regular exp), only for "icmp echo reply" */
    strcpy(filter_string, "icmp and dst host ");
    strcat(filter_string, dst_ip);
    if (pcap_compile(p, &fcode, filter_string, 0, mask) == -1) {
        pcap_perror(p, "pcap_compile");
        exit(1);
    }

    /* set filter function */
    if (pcap_setfilter(p, &fcode) == -1) {
        pcap_perror(p, "pcap_setfilter");
        exit(1);
    }
}

int pcap_get_reply(void) {

    const u_char *ptr;

    ptr = pcap_next(p, &hdr);

    printf("YYY\n");
    if (*(ptr+34) == 0) ;
        

    /*
     * google "pcap_next" to get more information
     * and check the packet that ptr pointed to.
     */

    return 0;
}