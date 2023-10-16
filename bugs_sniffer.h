#ifndef BUGS_SNIFFER_H
#define BUGS_SNIFFER_H
#include<pcap.h>
#include<cstdio>
#include<unistd.h>
#include<cstring>
#include<ctime>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<cerrno>
#include<vector>
#include<signal.h>
#include<fcntl.h>
#include<sys/types.h>
#include<cstring>
#include<unistd.h>
#include<stdlib.h>

// define some common number
#define ETHER_ADDR_LEN 6

#define ETHER_TYPE_IPV4      (0x0800)
#define ETHER_TYPE_IPV6      (0x86DD)
#define ETHER_TYPE_ARP       (0x0806)
#define ETHER_TYPE_PARP      (0x8035) /* DARP */
#define ETHER_TYPE_APPLETALK (0x80F3)
#define ETHER_TYPE_PPP       (0x880B)
#define ETHER_TYPE_LLDP      (0x88CC)
#define ETHER_TYPE_VLAN      (0x9100)
#define ETHER_TYPE_VLAN2      (0x9200)

// IP offset
#define IP_RF      (0x8000) /* 保留 */
#define IP_DF      (0x4000) /* 别分段 */
#define IP_MF      (0x2000) /* 多碎片标志 */
#define IP_OFFMASK (0x1FFF) /* 分段 */

#define IP_TYPE_ICMP (1)
#define IP_TYPE_IGMP (2)
#define IP_TYPE_IP (4)
#define IP_TYPE_TCP (6)
#define IP_TYPE_UDP (17)
#define IP_TYPE_RDP (27)
#define IP_TYPE_OSPF (89)

// tcp head flags
#define TH_FIN (0x01)
#define TH_SYN (0x02)
#define TH_RST (0x04)
#define TH_PUSH (0x08)
#define TH_ACK (0x10)
#define TH_URG (0x20)
#define TH_ECE (0x40)
#define TH_CWR (0x80)

// define header struct
struct eth_header{
    u_char dst_mac[ETHER_ADDR_LEN]; /* target host mac address */
    u_char src_mac[ETHER_ADDR_LEN]; /* source host mac address */
    u_short eth_type;               /* IP: 0x0800, IPv6: 0x86DD, ARP: 0x0806, RARP: 0x8035*/
};

struct ip_header{
    /* the byte order matters actually... */
    #if BYTE_ORDER == LITTLE_ENDIAN
    u_int header_len: 4;
    u_int version: 4;
    #if BYTE_ORDER == BIG_ENDIAN
    u_int version:4;    /* ip version */
    u_int header_len:4; /* header len */
    #endif
    #endif
    u_char tos:8;      /* service type */
    u_short total_len; /* .. */
    u_short ident;     /* identifier */
    u_short offset;    /**/
    u_char ttl:8;
    u_char protocol:8;
    int checksum:16;
    u_char sourceIP[4];
    u_char destIP[4];
};

struct tcp_header{
    u_short sport;
    u_short dport;
    u_int seq;
    u_int ack;
    u_char head_len;
    u_char flags;
    u_short wind_size;
    u_short check_sum;
    u_short urg_ptr;   /* for urgent... */
};

struct udp_header{
    u_short sport;
    u_short dport;
    u_short tot_len;
    u_short check_sum;
};
eth_header* eth_hdr;
ip_header* ip_hdr;
tcp_header* tcp_hdr;
udp_header* udp_hdr;
// callback function
int listAll(vector<char*>& result); // 返回所有的dev_name
void get_dev_IP(char* dev_name, vector<char*>& results);
void get_dev_info(char* dev_name vector<char*>& results);
void get_dev_statistics(char* dev_name, vector<vector<int> >& results);

void do_analyze(char* dev_name, vector<vector<<char*>>& results);
void do_ether();
void do_ip();
void do_tcp();
void do_udp();
void do_http();
void do_https();
void do_icmp();
void do_DoH();
void do_DNS_query();

void do_trace();

void do_save();
void do_load();

void findProcess(char* name);

// callback functions
void pcap_callback(unsigned char* args, const struct pcap_pkthdr* packet_header, const unsigned char* packet_content);
int pcap_protocal(pcap_dumper_t* args, const struct pcap_pkthdr* packet_header, const u_char* packet);
#endif