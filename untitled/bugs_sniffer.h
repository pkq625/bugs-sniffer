//
// Created by neko on 23-10-16.
//

#ifndef UNTITLED_BUGS_SNIFFER_H
#define UNTITLED_BUGS_SNIFFER_H
#include <pcap.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <map>
#include <ctime>
#include <cstdio>
#include <vector>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <iostream>
#include <algorithm>
using namespace std;
static const bool DEBUG_MODE = true;
/* define some constants here... */
#define ETHER_ADDR_LEN 6
// ether type
#define ETHER_TYPE_IPV4      (0x0800)
#define ETHER_TYPE_IPV6      (0x86DD)
#define ETHER_TYPE_ARP       (0x0806)
#define ETHER_TYPE_PARP      (0x8035) /* DARP */
#define ETHER_TYPE_APPLETALK (0x80F3)
#define ETHER_TYPE_PPP       (0x880B)
#define ETHER_TYPE_LLDP      (0x88CC)
#define ETHER_TYPE_VLAN      (0x9100)
#define ETHER_TYPE_VLAN2     (0x9200)
// IP offset
#define IP_RF      (0x8000) /* 保留 */
#define IP_DF      (0x4000) /* 别分段 */
#define IP_MF      (0x2000) /* 多碎片标志 */
#define IP_OFFMASK (0x1FFF) /* 分段 */
// IP type
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
/* define some structures here... */
struct ether_header{
    u_char dst_mac[ETHER_ADDR_LEN];
    u_char src_mac[ETHER_ADDR_LEN];
    u_short ether_type;
};
struct ip_header {
#if BYTE_ORDER == LITTLE_ENDIAN
    u_int header_len: 4;
    u_int version: 4;
#endif
#if BYTE_ORDER == BIG_ENDIAN
    u_int version: 4;
    u_int header_len: 4;
#endif
    u_char tos: 8;
    u_short total_len; /* .. */
    u_short ident;     /* identifier */
    u_short offset;    /**/
    u_char ttl:8;
    u_char protocol:8;
    int checksum:16;
    u_char src_ip[4];
    u_char dst_ip[4];
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
// some usually used variable struct
struct dev_info{
    char* dev_name;
    char* dev_description;
    pcap_t* dev_handle;
    bpf_u_int32 ipaddress;
    vector<string> dev_ips;
    char* filter_exp;
};
struct ip_info{
    char* src_ip;
    char* src_dst;
};
struct port_info{
    int src_port;
    int dst_port;
};
struct Msg{
    int timestamp;
    port_info* portInfo;
    ip_info* ipInfo;
    char* content;
};
/* define some variables here... */
static char ERROR_BUFFER[PCAP_ERRBUF_SIZE];
/* define some functions here... */
// 统一用传回参数，函数只返回运行结果的状态
// basic information
pcap_t* open_dev(char* dev_name, int timeout);
void close_dev(pcap_t* handle);
bool set_filter(struct dev_info& devInfo, char* filter_exp);
bool unset_filter(struct dev_info& devInfo);
int list_all_dev(bool detailed, map<char*,vector<string> >& results);                   /* 获得所有的网卡名称 */
bool get_dev_masked_ip(struct dev_info& devInfo, vector<char*>& results);
void get_dev_statistics(struct dev_info& devInfo, int timeWindow, int cnt, vector<int>& results, bool legacy);
pcap_t* do_open_dev(char* dev_name, int snapLen, int promisc, int timeout);
// analyze the traffic
uint16_t check_ethernet_type(struct ether_header& etherhdr);
bool convert_to_mac(char* mac, string& result); // convert_to_mac(mac, &result)
port_info* do_tcp(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent);
port_info* do_udp(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent);
bool do_icmp();
bool do_arp();
bool do_rarp();
bool do_ip();
bool do_ipv6();
bool do_http();
bool do_https();
bool analyze();
// file related
bool save_traffic(struct dev_info& devInfo);
bool load_traffic();
// test function
void nop_callback(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent);
void pcap_callback(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent);
// some time function
void alarm_callback(int sig);
#endif //UNTITLED_BUGS_SNIFFER_H
