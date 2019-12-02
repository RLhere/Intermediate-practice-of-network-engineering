#include<stdio.h>
#include<unistd.h>
#include<signal.h>
#include<net/if.h>
#include<pcap.h>
#include<net/ethernet.h>
#include<netinet/if_ether.h>
#include<x86_64-linux-gnu/bits/getopt_core.h>

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
    else
    {
        llc_header = (struct ether_header *)
                (packet + AVS_HEADER_SIZE + DATA_80211_FRAME_SIZE);
        arp_packet = (struct ether_arp *)
                (packet + AVS_HEADER_SIZE + DATA_80211_FRAME_SIZE + LLC_HEADER_SIZE);
        if(ntohs(llc_header->ether_type)!=ETHERTYPE_ARP)return;
    }

    printf("Source:%d.%d.%d.%d\t\tDestination:%d.%d.%d.%d\n",
    arp_packet->arp_spa[0],
    arp_packet->arp_spa[1],
    arp_packet->arp_spa[2],
    arp_packet->arp_spa[3],
    arp_packet->arp_tpa[0],
    arp_packet->arp_tpa[1],
    arp_packet->arp_tpa[2],
    arp_packet->arp_tpa[3]);
}

int main(int argc, char const *argv[])
{
    char o;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const u_char *packet;
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    char *filter = "arp";
    struct bpf_program fp;
    int r;
    pcap_if_t * alldevsp;

    while((o = getopt(argc,argv,"i:vl"))>0)
    {
        switch(0)
        {
            case 'i':
                device = optarg;
                break;

            case 'l':
                if(pcap_findalldevs(&alldevsp,errbuf)<0)
                {
                    fprintf(stderr,"%s",errbuf);
                    exit(1);
                }
                while(alldevsp!=NULL)
                {
                    printf("%s\n",alldevsp->name);
                    alldevsp = alldevsp->next;
                }
                exit(0);
            case 'v':
                verbose = 1;
                break;
            default:
                usage(argv[0]);
                break;
        }
    }

    signal(SIGINT,ctrl_c);

    if(device == NULL)
    {
        device = pcap_lookupdev(errbuf);
        if(device == NULL)
        {
            fprintf(stderr,"%s",errbuf);
            exit(1);
        }
    }
    errbuf[0] = 0;

    handle = pcap_open_live(device,BUFSIZ,1,0,errbuf);

    if(handle == NULL)
    {
        fprintf(stderr,"%s",errbuf);
        exit(1);
    }

    if(strlen(errbuf)>0)
    {
        fprintf(stderr,"Warning:%s",errbuf);
        errbuf[0] = 0;
    }

    if(verbose)
    {
        printf("Using device:%s\n",device);
    }

    if(pcap_datalink(handle)==DLT_EN10MB)
    {
        wired = 1;
    }
    else
    {
        if(pcap_datalink(handle)==DLT_IEEE802_11_RADIO_AVS)
        {
            wired = 0;
        
        }
        else
        {
            fprintf(stderr,"I don't support this interface type!\n");
            exit(1);
        }   
    }
    

    if(pcap_lookupnet(device,&netp,&maskp,errbuf)==-1)
    {
        fprintf(stderr,"%s",errbuf);
        exit(1);
    }

    if(pcap_compile(handle,&fp,filter,0,maskp)==-1)
    {
        fprintf(stderr,"%s",pcap_geterr(handle));
        exit(1);
    }

    if(pcap_setfilter(handle,&fp)==-1)
    {
        fprintf(stderr,"%s",pcap_geterr(handle));
        exit(1);
    }

    pcap_freecode(&fp);

    if((r = pcap_loop(handle,-1,process_packet,NULL))<0)
    {
        if(r==-1)
        {
            fprintf(stderr,"%s",pcap_geterr(handle));
            exit(1);
        }
    }

    pcap_close(handle);
}
