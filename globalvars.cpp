//
// Created by neko on 23-10-20.
//
#include "globalvars.h"
//initialze these global vars
unordered_map<string, int> packetCounts;
pthread_mutex_t packetCountMutex = PTHREAD_MUTEX_INITIALIZER;
vector<const char*> interfaces;
atomic<bool> isRunning = true;
atomic<bool> isRunning2 = false;
ofstream debug_fileout = ofstream("./debug_logs.txt",ofstream::app);
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
unordered_map<const char*, pcap_t*>get_statistic_handles;
unordered_map<string, unsigned int> traffics;
pthread_mutex_t trafficCountMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t packetProcessMutex = PTHREAD_MUTEX_INITIALIZER;
vector<display_ether>ethers;
vector<display_ip>ips;
vector<display_ipv6>ip6s;
vector<display_arp>arps;
vector<display_arp>rarps;
vector<display_icmp>icmps;
vector<display_icmp6>icmp6s;
vector<display_tcp>tcps;
vector<display_udp>udps;
vector<display_tls>tlss;
vector<display_dtls>dtlss;
vector<display_dns>dnss;
vector<display_stun>stuns;
set<string> DCID, SCID;
bool is_paused = false;