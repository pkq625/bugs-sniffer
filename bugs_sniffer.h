//
// Created by neko on 23-10-16.
//

#ifndef UNTITLED_BUGS_SNIFFER_H
#define UNTITLED_BUGS_SNIFFER_H
#include <pcap.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <thread>
#include <map>
#include <set>
#include <list>
#include <ctime>
#include <pthread.h>
#include <cstdio>
#include <chrono>
#include <cerrno>
#include <sstream>
#include <fstream>
#include <csignal>
#include <cstring>
#include <iostream>
#include <algorithm>
using namespace std;
static const bool DEBUG_MODE = true;
static ostringstream oss;
/* define some constants here... */
//#define ETHER_ADDR_LEN 6
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
//#define IP_RF      (0x8000) /* 保留 */
//#define IP_DF      (0x4000) /* 别分段 */
//#define IP_MF      (0x2000) /* 多碎片标志 */
//#define IP_OFFMASK (0x1FFF) /* 分段 */
// IP type
#define IP_TYPE_ICMP (1)
#define IP_TYPE_IGMP (2)
#define IP_TYPE_IP (4)
#define IP_TYPE_TCP (6)
#define IP_TYPE_UDP (17)
#define IP_TYPE_RDP (27)
#define IP_TYPE_OSPF (89)
// tcp head flags
//#define TH_FIN (0x01)
//#define TH_SYN (0x02)
//#define TH_RST (0x04)
//#define TH_PUSH (0x08)
//#define TH_ACK (0x10)
//#define TH_URG (0x20)
//#define TH_ECE (0x40)
//#define TH_CWR (0x80)
/* define some structures here... */
//struct ether_header{
//    u_char dst_mac[ETHER_ADDR_LEN];
//    u_char src_mac[ETHER_ADDR_LEN];
//    u_short ether_type;
//};
//struct ip_header {
//#if BYTE_ORDER == LITTLE_ENDIAN
//    u_int header_len: 4;
//    u_int version: 4;
//#endif
//#if BYTE_ORDER == BIG_ENDIAN
//    u_int version: 4;
//    u_int header_len: 4;
//#endif
//    u_char tos: 8;
//    u_short total_len; /* .. */
//    u_short ident;     /* identifier */
//    u_short offset;    /**/
//    u_char ttl:8;
//    u_char protocol:8;
//    int checksum:16;
//    struct in_addr src_ip, dst_ip;
//};
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
struct Msg{
    int timestamp;
    ip_info* ipInfo;
    char* content;
};
/* define some variables here... */
static char ERROR_BUFFER[PCAP_ERRBUF_SIZE];
/* define some functions here... */
// 统一用传回参数，函数只返回运行结果的状态
// basic information
pcap_t* open_dev(const char* dev_name, int timeout);
void close_dev(pcap_t* handle);
bool set_filter(struct dev_info& devInfo, char* filter_exp);
bool unset_filter(struct dev_info& devInfo);
int list_all_dev(bool detailed, map<char*,vector<string> >& results);                   /* 获得所有的网卡名称 */
bool get_dev_masked_ip(struct dev_info& devInfo, vector<char*>& results);
//int get_dev_statistics(const char*dev_name, //struct dev_info& devInfo,
//        int timeWindow, bool legacy);
pcap_t* do_open_dev(const char* dev_name, int snapLen, int promisc, int timeout);
// analyze the traffic
uint16_t check_ethernet_type(struct ether_header& etherhdr);
bool convert_to_mac(char* mac, string& result); // convert_to_mac(mac, &result)
void analyze_ether_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent);
void analyze_arp_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent,
                        uint16_t ether_type);
void analyze_rarp_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent,
                        uint16_t ether_type);
void analyze_ip_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent,
                       uint16_t ether_type);
void analyze_ipv6_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent,
                         uint16_t ether_type);
void analyze_tcp_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent,
        string lower_layer_type);
void analyze_udp_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent,
        string lower_layer_type);
void analyze_icmp_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent);
void analyze_others_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent);
void analyze_icmpv6_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent);
// file related
bool save_traffic(struct dev_info& devInfo);
bool load_traffic();
// test function
void packet_counter_callback(const struct pcap_pkthdr* pkthdr, const unsigned char* packet, const string& interface);
void packet_counter_callback(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent);
void packet_processor_callback(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent);
void* capture_thread(void* dev);
// some time function
// for convert to human readable
string check_arp_hardware_type(uint16_t t);
string check_arp_protocol_type(uint16_t t);
string check_arp_opcode(uint16_t t);
string convert_uint16_to_hex_string(uint16_t t);
string convert_uint8_to_hex_string(uint8_t t);
string check_ip6_nxt_header_protocol(uint8_t nxt);
string convert_uint32_to_hex_string(uint32_t t);
void check_icmp_type_code(uint8_t type, uint8_t code, string&icmp_type, string&icmp_code);
// for debugging... ignore me, ignore me...
string unsignedCharToHexString(unsigned char ch);
string unsigned_short_to_hex_string(unsigned short int a);
#endif //UNTITLED_BUGS_SNIFFER_H
