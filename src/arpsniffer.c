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
        printf("USAGE:arpsniffer <interface>\n");
        exit(1);
    }

    if((descr = pcap_open_live(argv[1],MAXBYTES2CAPTURE,0,512,errbuf))==NULL)
    {
        fprintf(stderr,"ERROR:%s\n",errbuf);
        exit(1);
    }

    if(pcap_lookupnet(argv[1],&netaddr,&mask,errbuf)==-1)
    {
        fprintf(stderr,"ERROR:%s\n",pcap_geterr(descr));
        exit(1);
    }

    if(pcap_compile(descr,&fliter,"arp",1,mask)==-1)
    {
        fprintf(stderr,"ERROR:%s\n",pcap_geterr(descr));
        exit(1);
    }

    if(pcap_setfilter(descr,&fliter)==-1)
    {
        fprintf(stderr,"ERROR:%s\n",pcap_geterr(descr));
        exit(1);
    }

    while(1)
    {
        if((packet = pcap_next(descr,&pkthdr))==NULL)
        {
            fprintf(stderr,"ERROR:Error getting the packet.\n",errbuf);
            exit(1);
        }

        arpheader = (struct arphdr *)(packet+14);

        printf("\n\nReceived Packet Size:%d bytes\n",pkthdr.len);
        printf("Hardware type:%s\n",(ntohs(arpheader->htype)==1)?"Ethernet":"Unknown");
        printf("Protocol type:%s\n",(ntohs(arpheader->ptype)==0x0800)?"IPv4":"Unknown");
        printf("Operation:%s\n",(ntohs(arpheader->oper)==ARP_REQUEST)?"ARP Request":"ARP Reply");

        if(ntohs(arpheader->htype)==1 && ntohs(arpheader->ptype)==0x0800)
        {
            printf("Sender MAC:");

            for(i=0;i<6;i++)
                printf("%02X:",arpheader->sha[i]);

            printf("\nSender IP:");

            for(i=0;i<4;i++)
                printf("%d.",arpheader->spa[i]);

            printf("\nTarget MAC:");

            for(i=0;i<6;i++)
                printf("%02X:",arpheader->tha[i]);

            printf("\nTarget IP:");

            for(i=0;i<4;i++)
                printf("%d.",arpheader->tpa[i]);

            printf("\n");
        }
    }

    return 0;
}
