//
// Created by neko on 23-10-16.
//
#include "bugs_sniffer.h"
int list_all_dev(bool detailed, vector<char*>&results){
    pcap_if_t* all_dev;
    if ((pcap_findalldevs(&all_dev, ERROR_BUF)) == -1){
        cout << "Cannot find any device..." << endl;
        return 0;
    }
    while (all_dev){
        results.push_back(all_dev->name);
        if (detailed) results.push_back(all_dev->description);
        all_dev = all_dev->next;
    }
    if (detailed) return (int) results.size()/2;
    return (int) results.size();
}

pcap_t* open_dev(char* dev_name){
    pcap_t* pcap_handle = pcap_open_live(dev_name, 65535, 1, 0, ERROR_BUF);
    if (pcap_handle == nullptr){
        cout<<ERROR_BUF<<endl;
        return nullptr;
    }
    return pcap_handle;
}
void close_dev(pcap_t* handle){
    pcap_close(handle);
}
bool set_filter(struct dev_info& devInfo, char filter_exp[]){
    devInfo.filter_exp = filter_exp;
    struct bpf_program filter{};
    if (pcap_compile(devInfo.dev_handle, &filter, devInfo.filter_exp, 0, devInfo.ipaddress) != -1){
        if (pcap_setfilter(devInfo.dev_handle, &filter) != -1) return true;
    }
    return false;
}
bool unset_filter(struct dev_info& devInfo){
    char empty_filter[] = "";
    return set_filter(devInfo, empty_filter);
}
bool get_dev_ip(char* dev_name, vector<char*>& results){
    struct in_addr addr{};
    bpf_u_int32 ipaddress, ipmask; // unsigned int
    char* dev_ip;
    char* mask_ip;
    if (pcap_lookupnet(dev_name, &ipaddress, &ipmask, ERROR_BUF) == -1){
        cout<<ERROR_BUF<<endl;
        return false;
    }
    addr.s_addr = ipaddress;
    dev_ip = inet_ntoa(addr); // 这个同样也可以转换ipv6
    addr.s_addr = ipmask;
    mask_ip = inet_ntoa(addr);
    results.push_back(dev_ip);
    results.push_back(mask_ip);
    return true;
}

void get_dev_statistics(struct dev_info& devInfo, int timeWindow, int cnt, vector<int>& results, bool legacy){
    if (legacy){ // use old method to count packets number within a time window cnt-times
        time_t start_time, end_time;
        int packet_count;
        for (int i = 0; i < cnt; ++i) {
            start_time = time(nullptr);
            end_time = start_time + timeWindow;  // seconds
            packet_count = 0;
            while (true){
                struct pcap_pkthdr header{};
                const u_char *packet = pcap_next(devInfo.dev_handle, &header);
                if (header.ts.tv_sec >= start_time && header.ts.tv_sec <= end_time)packet_count++;
                if (time(nullptr) > end_time) break;
            }
            results.push_back(packet_count);
        }
    } else{ // use the dispatch function's feature to count packets number within a time window cnt-times
        int packet_count;
        pcap_set_timeout(devInfo.dev_handle, timeWindow); // ms
        packet_count = pcap_dispatch(devInfo.dev_handle, -1, nullptr, nullptr);
        results.push_back(packet_count);
    }
}
// analyze traffic
uint16_t check_ethernet_type(struct ether_header& etherhdr){
    uint16_t ether_type = ntohs(etherhdr.ether_type);
    switch (ether_type) {
        case ETHER_TYPE_IPV4:
            return ETHER_TYPE_IPV4;
        case ETHER_TYPE_IPV6:
            return ETHER_TYPE_IPV6;
        case ETHER_TYPE_ARP:
            return ETHER_TYPE_ARP;
        case ETHER_TYPE_PARP:
            return ETHER_TYPE_PARP;
        default:
            return 0x00;
    }
}
bool convert_to_mac(char* mac, string& result){
    string token = strtok(mac, ":\n");
    while (!token.empty()){
        if (result.empty()){
            if (token.size() != 2){
                result += "0";
            }
        } else{
            if (token.size() == 2){
                result += ":";
            } else{
                result += ":0";
            }
        }
        result += token;
        token = strtok(nullptr, ":\n");
    }
    return true;
}

// test function
void pcap_callback(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent){
    int* id = (int*) args;
    cout<<"Packet id: "<<++(*id)<<endl;
    cout<<"Packet length: "<<packetHeader->len<<endl;
    cout<<"Number of Bytes: "<<packetHeader->caplen<<endl;
    cout<<"Received time: "<<ctime((const time_t*)&packetHeader->ts.tv_sec)<<endl;
    for (int i = 0; i < packetHeader->caplen; ++i) {
        printf("%02x", packetContent[i]);
        if ((i + 1) % 16 == 0){
            printf("\n");
        }
    }
    printf("\n\n");
}
