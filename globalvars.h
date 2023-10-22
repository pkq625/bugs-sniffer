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

struct display_ip_layer{
    string src_ip, dst_ip;
};
#endif //UNTITLED_GLOBALVARS_H
