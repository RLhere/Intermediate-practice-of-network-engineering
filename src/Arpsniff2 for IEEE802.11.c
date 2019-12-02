#include<stdio.h>
#include<unistd.h>
#include<signal.h>
#include<net/if.h>
#include<pcap.h>
#include<net/ethernet.h>
#include<netinet/if_ether.h>

#define ETH_HEADER_SIZE 14
#define AVS_HEADER_SIZE 64
#define DATA_80211_FRAME_SIZE 24
#define LLC_HEADER_SIZE 8

typedef __u_char u_char;

struct snap_header
{
    u_int8_t    dsap;
    u_int8_t    ssap;
    u_int8_t    ctl;
    u_int16_t   org;
    u_int8_t    org2;
    u_int16_t   ether_type;
}__attribute__((__packed___));

char    *device;
int     verbose = 0;
pcap_t  *handle;
int     wired = 0;

void ctrl_c()
{
    printf("Exiting\n");
    pcap_breakloop(handle);
    pcap_close(handle);
    exit(0);
}

void usage(char *name)
{
    printf("%s - simple ARP sniffer\n",name);
    printf("Usage: %s [-i interface] [-l] [-v]\n",name);
    printf("    -i  interface to sniff on\n");
    printf("    -l  list available interfaces\n");
    printf("    -v  print verbose info\n\n");
    exit(1);
}

void process_packet(u_char * args, const struct pcap_pkthdr *header, const u_char * packet)
{
    struct ether_header *eth_header;
    struct snap_header  *llc_header;
    struct ether_arp * arp_packet;

    if(wired)
    {
        eth_header = (struct ether_header *)packet;
        arp_packet = (struct ether_header *)(packet + ETH_HEADER_SIZE);
        if(ntohs(eth_header->ether_type)!=ETHERTYPE_ARP)return;
    }
}