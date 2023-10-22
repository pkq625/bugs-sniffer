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

using namespace std;
extern unordered_map<string, int> packetCounts;
extern pthread_mutex_t packetCountMutex;
extern vector<const char*> interfaces;
extern atomic<bool> isRunning;
extern pthread_mutex_t mutex;
extern ofstream debug_fileout;
extern pthread_cond_t cond;
extern unordered_map<const char*, pcap_t*>get_statistic_handles;
#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f) /*拿到header len*/
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)   /*拿到ip version*/
#define OPTIONS_LENGTH 2
#define IP_ADDRESS_LENGTH 16
#define MAC_ADDRESS_LENGTH 18
#define TIME_BUFFER_LENGTH 26

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
};
struct display_udp{
    int src_port;
    int dst_port;
    int len;
    string checksum;
};
struct display_icmp{

};
#endif //UNTITLED_GLOBALVARS_H
