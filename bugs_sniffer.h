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
// struct
struct eth_header{
    u_char dst_mac[6];
    u_char src_mac[6];
    u_short eth_type;
};

struct ip_header{
    int version:4;
    int header_len:4;
    u_char tos:8;
    int total_len:16;
    int ident:16;
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
    u_short urg_ptr;
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
void pcap_callback(unsigned char* arg, const struct pcap_pkthdr* packet_header, const unsigned char* packet_content);
int listAll(vector<char*>& result); // 返回所有的dev_name
void getDevIP();
void getDev();
void getDevInfo();
void getDevStatistics();

void analyze();
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
#endif