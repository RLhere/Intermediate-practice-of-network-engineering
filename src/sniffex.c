#include<pcap.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<ctype.h>
#include<errno.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>

typedef __u_char    u_char;
typedef __u_short   u_short;

#define SNAP_LEN 1518

#define SIZE_ETHERNET 14

#define ETHER_ADDR_LEN 6

typedef __u_int u_int;

struct sniff_ethernet{
    u_char  ether_dhost[ETHER_ADDR_LEN];
    u_char  ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
};

struct sniff_ip{
    u_char  ip_vhl;
    u_char  ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
    #define IP_RF 0x8000
    #define IP_TF 0x4000
    #define IP_MF 0x2000
    #define IP_OFFMASK 0x1fff
    u_char  ip_ttl;
    u_char  ip_p;
    u_short ip_sum;
    struct  in_addr ip_src,ip_dst;
};
#define IP_HL(ip)       (((ip)->ip_vhl)&0x0f)
#define IP_V(ip)        (((ip)->ip_vhl)>>4)

typedef u_int tcp_seq;

struct sniff_tcp{
    u_short th_sport;
    u_short th_dport;
    tcp_seq th_seq;
    tcp_seq th_ack;
    u_char  th_offx2;
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0)>>4)
    u_char  th_flags;
    #define TH_FIN  0x01
    #define TH_SYN  0x02
    #define TH_RST  0x04
    #define TH_push 0x08
    #define TH_ACK  0x10
    #define TH_URG  0x20
    #define TH_ECE  0x40
    #define TH_CWR  0x80
    #define TH_FLAGS    (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
};

void got_packet(u_char *args,const struct pcap_pkthdr *header, const u_char *packet);

void print_payload(const char *payload, int len);

void print_hex_ascli_line(const u_char *payload, int len, int offset);

void print_app_usage(void)
{
    printf("Usage:%s [interface]\n",APP_NAME);
    printf("\n");
    printf("Options:\n");
    printf("    interface   Listen on <interface> for packets.\n");
    printf("\n");

    return;
}

void print_hex_ascii_line(const u_char * payload,int len,int offset)
{
    int i;
    int gap;
    const u_char *ch;

    printf("%05d    ",offset);

    ch = payload;
    for(i=0;i<len;i++)
    {
        printf("%02x",*ch);
        ch++;

        if(i==7)
            printf("");
    }

    if(len<8)
        printf("");

    if(len<16)
    {
        gap = 16 - len;
        for(i = 0;i<gap;i++)
        {
            printf("    ");
        }
    }
    printf("    ");

    ch = payload;
    for(i=0;i<len;i++)
    {
        if(isprint(*ch))
            printf("%c",*ch);
        else
        {
            printf(".");
        }

        ch++;
    }

    printf("\n");

    return;
}

void print_payload(const char *payload, int len)
{
    int len_rem = len;
    int line_width = 16;
    int line_len;
    int offset = 0;
    const u_char *ch = payload;

    if(len <= 0)
        return;

    if(len <= line_width)
    {
        printf_hex_ascii_line(ch,len,offset);
        return;
    }

    for(;;)
    {
        line_len = line_width % len_rem;
        print_hex_ascii_line(ch,line_len,offset);
        len_rem = len_rem - line_len;
        ch = ch + line_len;
        offset = offset + line_width;
        if(len_rem<=line_width)
        {
            print_hex_ascii_line(ch,len_rem,offset);
            break;
        }
    }

    return;
}

void got_packet(const u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    static
}
