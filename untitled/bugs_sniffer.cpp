//
// Created by neko on 23-10-16.
//
#include "bugs_sniffer.h"
int list_all_dev(bool detailed, map<char*,vector<string> >& results) {
    pcap_if_t *all_dev;
    if ((pcap_findalldevs(&all_dev, ERROR_BUFFER)) == -1) {
        cout << "Cannot find any device..." << endl;
        return 0;
    }
    while (all_dev) {
        vector<string> dev_ips;
        for (pcap_addr_t *a = all_dev->addresses; a; a = a->next) {
            if (a->addr->sa_family == AF_INET) {
                string ip = inet_ntoa(((struct sockaddr_in *) a->addr)->sin_addr);
                dev_ips.push_back(ip);
                //cout << ip << endl;
            }else if (a->addr->sa_family == AF_INET6){
                char ip6text[INET6_ADDRSTRLEN];
                string ip = inet_ntop(AF_INET6, &((struct sockaddr_in6 *) a->addr)->sin6_addr, ip6text, sizeof(ip6text));
                dev_ips.push_back(ip);
            }
        }
        if (detailed) dev_ips.emplace_back(all_dev->description);
        results[all_dev->name] = dev_ips;
        all_dev = all_dev->next;
    }
    return (int) results.size();
}

pcap_t* open_dev(char* dev_name, int timeout){
    // snaplen是以太网数据包长度
    // promisc是混杂模式
    // timeout是设置长度
    pcap_t* pcap_handle = do_open_dev(dev_name, 65535, 1, timeout);
    if (pcap_handle == nullptr){
        cout << ERROR_BUFFER << endl;
        return nullptr;
    }
    return pcap_handle;
}
pcap_t* do_open_dev(char* dev_name, int snapLen, int promisc, int timeout){
    int status;
    pcap_t* handle = pcap_create(dev_name, ERROR_BUFFER);
    status = pcap_set_snaplen(handle, snapLen);
    if (status != 0)cout<<pcap_statustostr(status)<<endl;

    if (promisc) {
        status = pcap_set_immediate_mode(handle, 1);
        if (status != 0)cout << pcap_statustostr(status) << endl;
    }

    status = pcap_set_timeout(handle, timeout);
    if (status != 0)cout<<pcap_statustostr(status)<<endl;

    status = pcap_activate(handle);
    if (status < 0) {
        cout << pcap_statustostr(status) << endl;
    }
    else if (status > 0) {
        //pcap_activate() succeeded, but it's warning us of a problem it had.
        cout<< dev_name<<": "<<
            pcap_statustostr(status)<<", "<< pcap_geterr(handle)<<endl;
    }
    //cout<< status<<endl;
    return handle;
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
bool get_dev_masked_ip(struct dev_info& devInfo, vector<char*>& results){
    struct in_addr addr{};
    bpf_u_int32 ipaddress, ipmask; // unsigned int
    char* dev_ip;
    char* mask_ip;
    if (pcap_lookupnet(devInfo.dev_name, &ipaddress, &ipmask, ERROR_BUFFER) == -1){
        cout << ERROR_BUFFER << endl;
        return false;
    }
    devInfo.ipaddress = ipaddress;
    addr.s_addr = ipaddress;
    dev_ip = inet_ntoa(addr); // 这个同样也可以转换ipv6
    results.push_back(dev_ip);
    //addr.s_addr = ipmask;
    //mask_ip = inet_ntoa(addr);
    //results.push_back(mask_ip);
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
            cout<<start_time<<", "<<end_time<<endl;
            while (true){
                struct pcap_pkthdr header{};
                const u_char *packet = pcap_next(devInfo.dev_handle, &header);
                if (header.ts.tv_sec >= start_time && header.ts.tv_sec <= end_time)packet_count++;
                if (time(nullptr) > end_time) break;
            }
            cout<<i<<": "<<packet_count<<endl;
            results.push_back(packet_count);
        }
    } else{ // use the dispatch function's feature to count packets number within a time window cnt-times
        int packet_count;
        int id = 0;
        for (int i = 0; i < cnt; ++i) {
            id = 0;
            pcap_t* handle = open_dev(devInfo.dev_name, timeWindow);
            packet_count = pcap_dispatch(handle, -1, nop_callback, (unsigned char*)&id);
            close_dev(handle);
            results.push_back(packet_count);
            cout<<"Packets captured in "<<(i+1)*timeWindow<<"s: "<<packet_count<<endl;
        }
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
port_info* do_tcp(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent){
    int prev_len = sizeof(struct ether_header) + sizeof(ip_header);
    tcp_header* tcpHdr = (tcp_header*)(packetContent + prev_len);
    unsigned int tcp_len = tcpHdr->head_len - prev_len;
    port_info* portInfo = (port_info*) malloc(sizeof(port_info));
    if (tcp_len < sizeof(tcp_header)){
        cout<<"Invalid TCP Packet. Discarding the packet: "<<tcp_len<<endl;
        portInfo->src_port = 0; portInfo->dst_port = 0;
        return portInfo;
    }
    portInfo->src_port = ntohs(tcpHdr->sport);
    portInfo->dst_port = ntohs(tcpHdr->dport);
    return portInfo;
}
port_info* do_udp(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent){
    int prev_len = sizeof(struct ether_header) + sizeof(ip_header);
    udp_header* udpHdr = (udp_header*)(packetContent + prev_len);
    unsigned int udp_len = udpHdr->tot_len - prev_len;
    port_info* portInfo = (port_info*) malloc(sizeof(port_info));
    if (udp_len < sizeof(udp_header)){
        cout<<"Invalid UDP Packet. Discarding the packet: "<<udp_len<<endl;
        portInfo->src_port = 0; portInfo->dst_port = 0;
        return portInfo;
    }
    portInfo->src_port = ntohs(udpHdr->sport);
    portInfo->dst_port = ntohs(udpHdr->dport);
    return portInfo;
}
// test function

void nop_callback(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent){
    int* id = (int*) args;
    ++(*id);
    //cout<<"Packet id: "<<++(*id)<<endl;
}
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