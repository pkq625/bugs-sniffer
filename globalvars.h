//
// Created by neko on 23-10-20.
//
#pragma once
#ifndef UNTITLED_GLOBALVARS_H
#define UNTITLED_GLOBALVARS_H
// some global vars 一些用来共享的变量
#include <string>
#include <unordered_map>
#include <vector>
#include <fstream>
#include <atomic>
#include <pcap.h>
#include <set>

using namespace std;
extern unordered_map<string, int> packetCounts;
extern unordered_map<string, unsigned int> traffics;
extern pthread_mutex_t packetCountMutex;
extern pthread_mutex_t trafficCountMutex;
extern pthread_mutex_t packetProcessMutex;
extern vector<const char*> interfaces;
extern atomic<bool> isRunning;
extern atomic<bool> isRunning2;
extern pthread_mutex_t mutex;
extern ofstream debug_fileout;
extern pthread_cond_t cond;
extern unordered_map<const char*, pcap_t*>get_statistic_handles;
extern bool is_paused;
#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f) /*拿到header len*/
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)   /*拿到ip version*/
#define OPTIONS_LENGTH 2
#define IP_ADDRESS_LENGTH 16
#define MAC_ADDRESS_LENGTH 18
#define TIME_BUFFER_LENGTH 26
struct display_ether{
    string src_mac;
    string dst_mac;
    string type;
    int nxt_type; // ip:1,arp:2,rarp:4,ip6:8,vlan:16
    int nxt_idx;
    int tot_len;
    unsigned long timestamp;
};
struct display_ip{
    int version;
    int header_len;
    string tos;
    int tot_len;
    string ident;
    string flags;
    int offset;
    int ttl;
    string protocol;
    string checksum;
    string src_ip, dst_ip;
    int nxt_type; // ip:0001, ip6:0010,arp:0100,vlan:1000
    int nxt_idx;
};
struct display_arp{
    string hardware_type;
    string protocol_type;
    int hardware_size;
    int protocol_size;
    string opcode;
    string sender_mac;
    string sender_ip;
    string target_mac;
    string target_ip;
};
struct display_ipv6{
    string traffic_class;
    unsigned int payload_len;
    string nxt_header_protocol;
    unsigned int hop_limit;
    string src_ip;
    string dst_ip;
    int nxt_type; // ip:0001, ip6:0010,arp:0100,vlan:1000
    int nxt_idx;
};
struct display_tcp{
    int src_port;
    int dst_port;
    unsigned int seq;
    unsigned int ack;
    int data_offset;
    string flags;
    int window_size;
    string checksum;
    int urgent_pointer;
    int relative_seq; /*还没做*/
    int relative_ack;
    int nxt_type; // ip:0001, ip6:0010,arp:0100,vlan:1000
    int nxt_idx;
};
struct display_udp{
    int src_port;
    int dst_port;
    int len;
    string checksum;
    int nxt_type; // ip:0001, ip6:0010,arp:0100,vlan:1000
    int nxt_idx;
};
struct display_icmp{
    string type;
    string code;
    string checksum;
    string identifier;
    string seq;
};
struct display_icmp6{
    string type;
    string code;
    string checksum;
    string flags;
};
struct dns_query{
    string name;
    string query_type;
    string query_class;
};
struct display_dns{
    string transaction_id;
    string flags;
    int question_num;
    struct dns_query query; // for simplicity, 只记录第一个，要记多个就开个数组。。。
};
struct display_tls{
    string type;
    string version;
};
struct display_dtls{
    string type;
};
struct display_stun{
    string type;
};
//struct packet{
//
//};
//struct FlowKey {
//    in_addr src_ip;
//    in_addr dst_ip;
//    uint16_t src_port;
//    uint16_t dst_port;
//
//    bool operator==(const FlowKey& other) const {
//        return src_ip.s_addr == other.src_ip.s_addr &&
//               dst_ip.s_addr == other.dst_ip.s_addr &&
//               src_port == other.src_port &&
//               dst_port == other.dst_port;
//    }
//};
//struct FlowKeyHash {
//    std::size_t operator()(const FlowKey& key) const {
//        return std::hash<std::string>()(
//                std::to_string(key.src_ip.s_addr) +
//                std::to_string(key.dst_ip.s_addr) +
//                std::to_string(key.src_port) +
//                std::to_string(key.dst_port)
//        );
//    }
//};
//struct FlowStats {
//    int packets_sent = 0;
//    int packets_received = 0;
//    int bytes_sent = 0;
//    int bytes_received = 0;
//};
//unordered_map<FlowKey, FlowStats, FlowKeyHash> flow_table;
//std::mutex flow_table_mutex;
extern vector<display_ether>ethers;
extern vector<display_ip>ips;
extern vector<display_ipv6>ip6s;
extern vector<display_arp>arps;
extern vector<display_arp>rarps;
extern vector<display_icmp>icmps;
extern vector<display_icmp6>icmp6s;
extern vector<display_tcp>tcps;
extern vector<display_udp>udps;
extern vector<display_tls>tlss;
extern vector<display_dtls>dtlss;
extern vector<display_dns>dnss;
extern vector<display_stun>stuns;
extern set<string> DCID, SCID;

#endif //UNTITLED_GLOBALVARS_H
