#include<pcap.h>
#include<stdlib.h>
#include<string.h>

// ARP Header, (assuming Ethernet+IPV4)

#define ARP_REQUEST 1 // ARP Request
#define ARP_REPLY 2 // ARP REPLY
typedef __u_char    u_char;

typedef struct arphdr {
    u_int16_t   htype;
    u_int16_t   ptype;
    u_char      hlen;
    u_char      plen;
    u_int16_t   oper;
    u_char      sha[6];
    u_char      spa[4];
    u_char      tha[6];
    u_char      tpa[4];
}arphdr_t;

#define MAXBYTES2CAPTURE 2048


int main(int argc, char const *argv[])
{
    int i = 0;
    bpf_u_int32 netaddr = 0, mask = 0;
    struct bpf_program fliter;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *descr = NULL;
    struct pcap_pkthdr pkthdr;
    const unsigned char *packet = NULL;
    arphdr_t *arpheader = NULL;
    memset(errbuf,0,PCAP_ERRBUF_SIZE);

    if(argc!=2)
    {
        
    }

    return 0;
}
