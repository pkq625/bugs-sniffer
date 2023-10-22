//
// Created by neko on 23-10-16.
//
#include "globalvars.h"
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

pcap_t* open_dev(const char* dev_name, int timeout){
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
pcap_t* do_open_dev(const char* dev_name, int snapLen, int promisc, int timeout){
    int status;
    pcap_t* handle = pcap_create(dev_name, ERROR_BUFFER);
    if (handle != nullptr) {
        status = pcap_set_snaplen(handle, snapLen);
        if (status != 0)cout << pcap_statustostr(status) << endl;
    }
    if (handle != nullptr) {
        if (promisc) {
            status = pcap_set_immediate_mode(handle, 1);
            if (status != 0)cout << pcap_statustostr(status) << endl;
        }
    }
    if (handle != nullptr) {
        status = pcap_set_timeout(handle, timeout);
        if (status != 0)cout << pcap_statustostr(status) << endl;
    }

    if (handle != nullptr) {
        status = pcap_activate(handle);
        if (status < 0) {
            cout << pcap_statustostr(status) << endl;
        } else if (status > 0) {
            //pcap_activate() succeeded, but it's warning us of a problem it had.
            cout << dev_name << ": " <<
                 pcap_statustostr(status) << ", " << pcap_geterr(handle) << endl;
        }
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
//int get_dev_statistics(const char* dev_name, //struct dev_info& devInfo,
//        int timeWindow, bool legacy){
////    if (legacy){ // use old method to count packets number within a time window cnt-times
////        time_t start_time, end_time;
////        int packet_count;
////        for (int i = 0; i < cnt; ++i) {
////            start_time = time(nullptr);
////            end_time = start_time + timeWindow;  // seconds
////            packet_count = 0;
////            cout<<start_time<<", "<<end_time<<endl;
////            while (true){
////                struct pcap_pkthdr header{};
////                const u_char *packet = pcap_next(devInfo.dev_handle, &header);
////                if (header.ts.tv_sec >= start_time && header.ts.tv_sec <= end_time)packet_count++;
////                if (time(nullptr) > end_time) break;
////            }
////            cout<<i<<": "<<packet_count<<endl;
////            results.push_back(packet_count);
////        }
//    } else { // use the dispatch function's feature to count packets number within a time window cnt-times
////        alarm(1);
////        int packet_count;
////        int id = 0;
////        pcap_t *handle = open_dev(dev_name, timeWindow*1000);
////        if (handle != nullptr) {
////            packet_count = pcap_dispatch(handle, 0, packet_counter_callback, (unsigned char *) &id);
////            close_dev(handle);
////        }
////        return packet_count;
////        cout << dev_name<< ": " << "[" << time(nullptr) << "] Packets captured in " << (i + 1) * timeWindow << "s: " << packet_count
////             << endl;
//
//    }
//}
// analyze traffic
uint16_t check_ethernet_type(struct ether_header* etherhdr){
    uint16_t ether_type = ntohs(etherhdr->ether_type);
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
    char* token = strtok(mac, ":\n");
    while (token != NULL){
        if (result.empty()){
            if (strlen(token) != 2){
                result += "0";
            }
        } else{
            if (strlen(token) == 2){
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
void do_tcp(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent){
    int prev_len = sizeof(struct ether_header) + sizeof(ip_header);
    tcp_header* tcpHdr = (tcp_header*)(packetContent + prev_len);
    unsigned int tcp_len = tcpHdr->head_len - prev_len;
//    port_info* portInfo = (port_info*) malloc(sizeof(port_info));
//    if (tcp_len < sizeof(tcp_header)){
//        cout<<"Invalid TCP Packet. Discarding the packet: "<<tcp_len<<endl;
//        portInfo->src_port = 0; portInfo->dst_port = 0;
//        return portInfo;
//    }
//    portInfo->src_port = ntohs(tcpHdr->sport);
//    portInfo->dst_port = ntohs(tcpHdr->dport);
//    return portInfo;
}
void do_udp(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent){
    int prev_len = sizeof(struct ether_header) + sizeof(ip_header);
    udp_header* udpHdr = (udp_header*)(packetContent + prev_len);
    unsigned int udp_len = udpHdr->tot_len - prev_len;
//    port_info* portInfo = (port_info*) malloc(sizeof(port_info));
//    if (udp_len < sizeof(udp_header)){
//        cout<<"Invalid UDP Packet. Discarding the packet: "<<udp_len<<endl;
//        portInfo->src_port = 0; portInfo->dst_port = 0;
//        return portInfo;
//    }
//    portInfo->src_port = ntohs(udpHdr->sport);
//    portInfo->dst_port = ntohs(udpHdr->dport);
//    return portInfo;
}
// throw the first packet here... it will call a bulk of functions to unpack the layers...
void analyze_ether_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent){
    uint16_t ether_type;
    for (int i = 0; i < strlen((const char*)packetContent); ++i) {
        cout<<unsignedCharToHexString(packetContent[i])<<" ";
    }
    cout<<endl;
    struct ether_header* etherHeader = (struct ether_header*)packetContent;
    ether_type = check_ethernet_type(etherHeader);
    string srcmac, dstmax;
    convert_to_mac(ether_ntoa((struct ether_addr *)&etherHeader->ether_shost), srcmac);
    convert_to_mac(ether_ntoa((struct ether_addr *)&etherHeader->ether_dhost), dstmax);
    cout<<etherHeader->ether_type<<", "<<srcmac<<", "<<dstmax<<endl;
    if (ether_type == ETHER_TYPE_IPV4){
//        cout<<"ipv4"<<endl;
        analyze_ip_packet(args, packetHeader, packetContent, ether_type);
    }else if (ether_type == ETHER_TYPE_ARP){
//        cout<<"arp"<<endl;
        analyze_arp_packet(args, packetHeader, packetContent, ether_type);
    }else if (ether_type == ETHER_TYPE_PARP){
//        cout<<"rarp"<<endl;
        analyze_rarp_packet(args, packetHeader, packetContent, ether_type);
    }else if (ether_type == ETHER_TYPE_IPV6){
//        cout<<"ipv6"<<endl;
        analyze_ipv6_packet(args, packetHeader, packetContent, ether_type);
    }else if (ether_type == ETHERTYPE_VLAN){
        cout<<"vlan"<<endl;
    }
    else if (ether_type == 0x00){
        // TODO
        cout<<"unknown!!!"<<endl;
    }else{
        // TODO
        cout<<"others"<<endl;
    }
}
// throw the ip packet here...
void analyze_ip_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent,
        uint16_t ether_type){
    display_ip_layer displayIpLayer = {};

    struct ether_header *etherHeader = (struct ether_header*)packetHeader;
    ip_header* ipHeader = (ip_header*)(packetContent + sizeof(struct ether_header));
    unsigned int ip_len = packetHeader->len - sizeof(struct ether_header);
    if (ip_len < sizeof(struct ip_header)){
        cout << "Invalid IP packet"<<endl;
        return;
    }
    // 拿到src ip和dst ip
    displayIpLayer.src_ip = inet_ntoa(ipHeader->src_ip);
    displayIpLayer.dst_ip = inet_ntoa(ipHeader->dst_ip);

    struct tm* pkt_time = localtime((const time_t*)&packetHeader->ts.tv_sec);

    // 判断protocol，如果还有上一层，就传给对应的处理函数
//    if (ipHeader->protocol == IP_TYPE_TCP){
//        do_tcp();
//    }else if (ipHeader->protocol == IP_TYPE_UDP){
//        do_udp();
//    }else if (ipHeader->protocol == IP_TYPE_ICMP){
//        do_icmp();
//    }else if (ipHeader->protocol == IP_TYPE_IGMP){
//
//    }else {
//        do_others();
//    }
}
//
string unsignedCharToHexString(unsigned char ch){
    const char hex_chars[] = "0123456789abcdef";
    string result = "";
    unsigned int highHalfByte = (ch >> 4) & 0x0f;
    unsigned int lowHalfByte = (ch & 0x0f);
    result += hex_chars[highHalfByte];
    result += hex_chars[lowHalfByte];
    return result;
}
string unsigned_short_to_hex_string(unsigned short int a){
    string result = "";
    while (a){
        result += (a&1)?"1":"0";
        a/=2;
    }
    return result;
}
void analyze_arp_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent,
                        uint16_t ether_type){
    unsigned int arp_len = packetHeader->len - sizeof(struct ether_header);
    if (arp_len < sizeof(arphdr)){
        cout<<"Invalid ARP packet..."<<endl;
        return;
    }
    for (int i = 0; i < packetHeader->len; i++) {
        printf("%02X ", packetContent[i]);
    }
    printf("\n");
    cout<< sizeof(ether_header)<<endl;
    cout<< arp_len<<endl;

    ether_arp* etherArp = (ether_arp*)(packetContent + sizeof(struct ether_header));
    arphdr* arp_header = &etherArp->ea_hdr;
    printf("Hardware type: %d\n", ntohs(arp_header->ar_hrd));
    printf("Protocol type: 0x%04X\n", ntohs(arp_header->ar_pro));
    printf("Hardware size: %d\n", arp_header->ar_hln);
    printf("Protocol size: %d\n", arp_header->ar_pln);
    printf("Operation: %s\n", ntohs(arp_header->ar_op) == ARPOP_REQUEST ? "Request" : "Reply");
    printf("Sender MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           etherArp->arp_sha[0], etherArp->arp_sha[1],
           etherArp->arp_sha[2], etherArp->arp_sha[3],
           etherArp->arp_sha[4], etherArp->arp_sha[5]);
    printf("Sender IP: %d.%d.%d.%d\n",
           etherArp->arp_spa[0], etherArp->arp_spa[1],
           etherArp->arp_spa[2], etherArp->arp_spa[3]);

    printf("Target MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           etherArp->arp_tha[0], etherArp->arp_tha[1],
           etherArp->arp_tha[2], etherArp->arp_tha[3],
           etherArp->arp_tha[4], etherArp->arp_tha[5]);
    printf("Target IP: %d.%d.%d.%d\n",
           etherArp->arp_tpa[0], etherArp->arp_tpa[1],
           etherArp->arp_tpa[2], etherArp->arp_tpa[3]);
}
void analyze_rarp_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent,
                        uint16_t ether_type){
    cout<<"rarp"<<endl;
}
void analyze_ipv6_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent,
                         uint16_t ether_type){
    cout<<"ipv6"<<endl;
}
// do the real packet cunting job
void packet_counter_callback(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent){
//    int id = *(int*)args;
//    pthread_mutex_lock(&packetCountMutex);
//    packetCounts[id]++;
//    pthread_mutex_unlock(&packetCountMutex);
}
// do the real packet cunting job
void packet_counter_callback(const struct pcap_pkthdr* pkthdr, const unsigned char* packet, const string& interface) {
    if (!isRunning)return;
    pthread_mutex_lock(&packetCountMutex);
    packetCounts[interface]++;
    pthread_mutex_unlock(&packetCountMutex);
}
// this is for counting for each interface, when a packet is captured, this will call packet_counter_callback
void* capture_thread(void* dev){
    char* device = (char*)dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    // Open the capture device
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);

    if (handle == nullptr) {
        cout << "Couldn't open device " << device << ": " << errbuf << endl;
        return nullptr;
    }
    get_statistic_handles[device] = handle;
    while (isRunning) {
//        debug_fileout << time(nullptr) << ": "<<device<<" capturing"<<endl;
        struct pcap_pkthdr header{};
        const u_char* packet = pcap_next(get_statistic_handles[device], &header);

        if (packet != nullptr) {
            packet_counter_callback(&header, packet, device);
        }
    }

    pcap_close(get_statistic_handles[device]);
    cout<<device <<": quited..."<<endl;
    return nullptr;
}
void packet_processor_callback(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent){
    // process the packet in layers
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