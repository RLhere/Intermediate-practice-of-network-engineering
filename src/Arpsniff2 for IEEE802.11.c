#include<stdio.h>
#include<unistd.h>
#include<signal.h>
#include<net/if.h>
#include<pcap.h>
#include<netinet/if_ether.h>

#define ETH_HEADER_SIZE 14
#define AVS_HEADER_SIZE 64
#define DATA_80211_FRAME_SIZE 24
#define LLC_HEADER_SIZE 8

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
