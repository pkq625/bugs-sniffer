//
// Created by neko on 23-10-20.
//
#include "globalvars.h"
//initialze these global vars
unordered_map<string, int> packetCounts;
pthread_mutex_t packetCountMutex = PTHREAD_MUTEX_INITIALIZER;
vector<const char*> interfaces;
atomic<bool> isRunning = true;
ofstream debug_fileout = ofstream("./debug_logs.txt",ofstream::app);
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
unordered_map<const char*, pcap_t*>get_statistic_handles;