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
    int prev_len = sizeof(struct ether_header) + sizeof(iphdr);
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
    int prev_len = sizeof(struct ether_header) + sizeof(iphdr);
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
string check_ip_protocol(uint8_t t){
    string res;
    if (t == IP_TYPE_TCP) res += "TCP";
    else if (t == IP_TYPE_UDP) res += "UDP";
    else if (t == IP_TYPE_ICMP) res += "ICMP";
    else if (t == IP_TYPE_RDP) res += "RDP";
    res += " (";
    res += convert_uint16_to_hex_string(t);
    res += ")";
    return res;
}
string check_ip_flags(uint16_t t){
    string res;
    if (t == IP_DF) res += "Don't fragment";
    else if (t == IP_MF) res += "Multi fragment";
    else if (t == IP_RF) res += "Reserved";
    else res += "UNKNOWN";
    res += " (";
    res += convert_uint16_to_hex_string(t);
    res += ")";
    return res;
}
void analyze_ip_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent,
        uint16_t ether_type){
    display_ip displayIP = {};
    struct ether_header *etherHeader = (struct ether_header*)packetHeader;
    iphdr* ip_header = (iphdr*)(packetContent + sizeof(struct ether_header));
    unsigned int ip_len = packetHeader->len - sizeof(struct ether_header);
    if (ip_len < sizeof(struct iphdr)){
        cout << "Invalid IP packet"<<endl;
        return;
    }
    // 转为hunman readable
    displayIP.version = ip_header->version;
    displayIP.header_len += ip_header->ihl * 4;
    displayIP.ttl = ip_header->ttl;
    displayIP.protocol = check_ip_protocol(ip_header->protocol);
    displayIP.tot_len = ntohs(ip_header->tot_len);
    displayIP.ident = convert_uint16_to_hex_string(ntohs(ip_header->id));
    displayIP.offset = ntohs(ip_header->frag_off) & IP_OFFMASK;
    displayIP.checksum = convert_uint16_to_hex_string(ntohs(ip_header->check));
    displayIP.flags = check_ip_flags(ntohs(ip_header->frag_off));
    displayIP.tos = convert_uint8_to_hex_string(ip_header->tos);
    struct in_addr ipv4_address{};
    ipv4_address.s_addr = htonl(ip_header->saddr);
    displayIP.src_ip = inet_ntoa(ipv4_address);
    ipv4_address.s_addr = htonl(ip_header->daddr);
    displayIP.dst_ip = inet_ntoa(ipv4_address);

//    cout<<displayIP.version<<endl;
//    cout<<displayIP.header_len<<endl;
//    cout<<displayIP.protocol<<endl;
//    cout<<displayIP.tot_len<<endl;
//    cout<<displayIP.ttl<<endl;
//    cout<<displayIP.tos<<endl;
//    cout<<displayIP.ident<<endl;
    cout<<displayIP.checksum<<endl;
//    cout<<displayIP.flags<<endl;
//    cout<<displayIP.offset<<endl;
//    cout<<endl;

//    printf("Captured an IP packet (length: %d bytes):\n", packetHeader->len);
//    printf("Version: %d\n", ip_header->version);
//    printf("Header Length: %d bytes\n", ip_header->ihl * 4);
//    printf("Type of Service (TOS): 0x%02X\n", ip_header->tos);
//    printf("Total Length: %d bytes\n", ntohs(ip_header->tot_len));
//    printf("Identifier: 0x%04X\n", ntohs(ip_header->id));
//    printf("Flags: 0x%02X\n", ntohs(ip_header->frag_off));
//    printf("Fragment Offset: %d bytes\n", ntohs(ip_header->frag_off) & IP_OFFMASK);
//    printf("Time to Live (TTL): %d\n", ip_header->ttl);
//    printf("Protocol: %d\n", ip_header->protocol);
//    printf("Checksum: 0x%04X\n", ntohs(ip_header->check));
//    printf("Source IP: %s\n", inet_ntoa(ip_header->saddr));
//    printf("Destination IP: %s\n", inet_ntoa(ip_header->daddr));
    struct tm* pkt_time = localtime((const time_t*)&packetHeader->ts.tv_sec);

    // 判断protocol，如果还有上一层，就传给对应的处理函数
    if (ip_header->protocol == IP_TYPE_TCP){
        analyze_tcp_packet(args, packetHeader, packetContent, "ip");
    }else if (ip_header->protocol == IP_TYPE_UDP){
        analyze_udp_packet(args, packetHeader, packetContent, "ip");
    }else if (ip_header->protocol == IP_TYPE_ICMP){
        analyze_icmp_packet(args, packetHeader, packetContent);
    }else if (ip_header->protocol == IP_TYPE_IGMP){

    }else {
        analyze_others_packet(args, packetHeader, packetContent);
    }
}
string check_tcp_flags(uint8_t t){
    int tmp = 1;
    string res = convert_uint8_to_hex_string(t);
    res += " (";
    for (int i = 0; i < 5; ++i) {
        if (t & tmp){
            if (res.size() > 7) res += ", ";
            if (tmp == TH_ACK) res += "ACK";
            else if (tmp == TH_FIN) res += "FIN";
            else if (tmp == TH_RST) res += "RST";
            else if (tmp == TH_PUSH) res += "PUSH";
            else if (tmp == TH_SYN) res += "SYN";
            else if (tmp == TH_URG) res += "URG";
        }
        tmp <<= 1;
    }
    res += ")";
    return res;
}
void analyze_tcp_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent,
        string lower_layer_type){
    tcphdr* tcpHeader;
    if (lower_layer_type == "ip"){
        tcpHeader = (tcphdr*) (packetContent + sizeof(struct iphdr)+sizeof(ether_header));
    }else if (lower_layer_type == "ip6"){
        tcpHeader = (tcphdr*) (packetContent + sizeof(struct ip6_hdr)+sizeof(ether_header));
    }


//    printf("Captured a TCP packet (length: %d bytes):\n", packetHeader->len);
//    printf("Source Port: %d\n", ntohs(tcpHeader->th_sport));
//    printf("Destination Port: %d\n", ntohs(tcpHeader->th_dport));
//    printf("Sequence Number: %u\n", ntohl(tcpHeader->seq));
//    printf("Acknowledgment Number: %u\n", ntohl(tcpHeader->ack));
//    printf("Data Offset: %d bytes\n", tcpHeader->th_off * 4);
//    printf("Flags: 0x%02X\n", tcpHeader->th_flags);
//    printf("Window Size: %d\n", ntohs(tcpHeader->window));
//    printf("Checksum: 0x%04X\n", ntohs(tcpHeader->check));
//    printf("Urgent Pointer: %d\n", ntohs(tcpHeader->urg_ptr));

    display_tcp displayTcp{};
    displayTcp.src_port = ntohs(tcpHeader->th_sport);
    displayTcp.dst_port = ntohs(tcpHeader->th_dport);
    displayTcp.seq = ntohl(tcpHeader->seq);
    displayTcp.ack = ntohl(tcpHeader->ack);
    displayTcp.data_offset = tcpHeader->th_off * 4;
    displayTcp.flags = check_tcp_flags(tcpHeader->th_flags);
    displayTcp.window_size = ntohs(tcpHeader->window);
    displayTcp.checksum = convert_uint16_to_hex_string(ntohs(tcpHeader->check));
    displayTcp.urgent_pointer = ntohs(tcpHeader->urg_ptr);

//    cout<<displayTcp.src_port<<endl;
//    cout<<displayTcp.dst_port<<endl;
//    cout<<displayTcp.seq<<endl;
//    cout<<displayTcp.ack<<endl;
//    cout<<displayTcp.data_offset<<endl;
//    cout<<displayTcp.flags<<endl;
//    cout<<displayTcp.window_size<<endl;
//    cout<<displayTcp.check_sum<<endl;
//    cout<<displayTcp.urgent_pointer<<endl;
}
void analyze_udp_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent,
        string lower_layer_type){
    udphdr* udpHeader;
    if (lower_layer_type == "ip"){
        udpHeader = (udphdr*) (packetContent + sizeof(struct iphdr)+sizeof(ether_header));
    }else if (lower_layer_type == "ip6"){
        udpHeader = (udphdr*) (packetContent + sizeof(struct ip6_hdr)+sizeof(ether_header));
    }
//    cout<<ntohs(udpHeader->uh_sport)<<endl;
//    cout<<ntohs(udpHeader->uh_dport)<<endl;
//    cout<<ntohs(udpHeader->uh_ulen)<<endl;
//    cout<<convert_uint16_to_hex_string(ntohs(udpHeader->uh_sum))<<endl;
    display_udp displayUdp{};
    displayUdp.src_port = ntohs(udpHeader->uh_sport);
    displayUdp.dst_port = ntohs(udpHeader->uh_dport);
    displayUdp.dst_port = ntohs(udpHeader->uh_ulen);
    displayUdp.checksum = convert_uint16_to_hex_string(ntohs(udpHeader->uh_sum));
}
void analyze_icmp_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent){
    struct icmphdr *icmp_header = (struct icmphdr *)(packetContent + sizeof(struct ether_header) + sizeof(iphdr));
//    cout<<convert_uint8_to_hex_string(icmp_header->type)<<endl;
//    cout<<convert_uint8_to_hex_string(icmp_header->code)<<endl;
//    cout<<convert_uint16_to_hex_string(ntohs(icmp_header->checksum))<<endl;
    struct display_icmp displayIcmp{};
    check_icmp_type_code(icmp_header->type, icmp_header->code, displayIcmp.type, displayIcmp.code);
    displayIcmp.checksum = convert_uint16_to_hex_string(ntohs(icmp_header->checksum));
    displayIcmp.identifier = convert_uint16_to_hex_string(ntohs(icmp_header->un.echo.id));
    displayIcmp.seq = convert_uint16_to_hex_string(ntohs(icmp_header->un.echo.sequence));
//    cout<<displayIcmp.type<<endl;
//    cout<<displayIcmp.code<<endl;
//    cout<<displayIcmp.checksum<<endl;
//    cout<<displayIcmp.identifier<<endl;
//    cout<<displayIcmp.seq<<endl;
}

void check_icmp_type_code(uint8_t type, uint8_t code, string&icmp_type, string&icmp_code) {
    icmp_type = convert_uint8_to_hex_string(type);
    icmp_type += " (";
    icmp_code = convert_uint8_to_hex_string(code);
    icmp_code += " (";
    if (type == ICMP_ECHO) {
        icmp_type += "ICMP Echo (Ping) Request";

    } else if(type == ICMP_ECHOREPLY){
        icmp_type += "ICMP Echo (Ping) Reply";

    }
    else if (type == ICMP_DEST_UNREACH) {
        icmp_type += "Destination Unreachable";
        /* Codes for Destination Unreachable. */
        if (code == ICMP_NET_UNREACH){
            icmp_code += "Network Unreachable";
        }else if (code == ICMP_HOST_UNREACH){
            icmp_code += "Host Unreachable";
        }else if (code == ICMP_PROT_UNREACH){
            icmp_code += "Protocol Unreachable";
        }else if (code == ICMP_PORT_UNREACH){
            icmp_code += "Port Unreachable";
        }
    } else if (type == ICMP_TIME_EXCEEDED) {
        icmp_type += "Time Exceeded";
        /* Codes for TIME_EXCEEDED. */
        if (code == ICMP_EXC_TTL){
            icmp_code += "TTL count exceeded";
        }else if (code == ICMP_EXC_FRAGTIME){
            icmp_code += "Fragment Reass time exceeded";
        }
    } else if (type == ICMP_REDIRECT){
        icmp_type += "Redirect (change route)";
        /* Codes for Redirect. */
        if (code == ICMP_REDIR_NET){
            icmp_code += "Redirect Net";
        }else if (code == ICMP_REDIR_HOST){
            icmp_code += "Redirect Host";
        }else if (code == ICMP_REDIR_NETTOS){
            icmp_code += "Redirect Net for TOS";
        }else if (code == ICMP_REDIR_HOSTTOS){
            icmp_code += "Redirect Host for TOS";
        }
    }
    icmp_type += ")";
    icmp_code += ")";
}

void analyze_others_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent){
    cout<<"others..."<<endl;
}
//
string unsignedCharToHexString(unsigned char ch){
    const char hex_chars[] = "0123456789ABCDEF";
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
string check_arp_hardware_type(uint16_t t){
    string res;
    if (t == ARPHRD_ETHER) res += "Ethernet";
    else if (t == ARPHRD_IEEE802) res += "IEEE802";
    else res += "UNKNOWN";
    res += " (";
    res += to_string(t);
    res += ")";
    return res;
}
string convert_uint16_to_hex_string(uint16_t t){
    oss << "0x" << std::hex << t;
    string res = oss.str();
    oss.str("");
    return res;
}
string convert_uint8_to_hex_string(uint8_t t){
    char str[20];
    sprintf(str, "0x%02X", t);
    return str;
}
string convert_uint32_to_hex_string(uint32_t t){
    char str[30];
    sprintf(str, "0x%02X", t);
    return str;
}
string check_arp_protocol_type(uint16_t t){
    string res;
    if (t == ETHER_TYPE_IPV4) res += "IPv4";
    else res += "UNKNOWN";
    res += " (";
    res += convert_uint16_to_hex_string(t);
    res += ")";
    return res;
}
string check_arp_opcode(uint16_t t){
    string res;
    if (t == ARPOP_REQUEST)res += "request";
    else if (t == ARPOP_REPLY) res += "reply";
    else if (t == ARPOP_RREQUEST) res += "rarp request";
    else if (t == ARPOP_RREPLY) res += "rarp reply";
    else res += "UNKNOWN";
    res += " (";
    res += to_string(t);
    res += ")";
    return res;
}
void analyze_arp_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent,
                        uint16_t ether_type){
    unsigned int arp_len = packetHeader->len - sizeof(struct ether_header);
    if (arp_len < sizeof(arphdr)){
        cout<<"Invalid ARP packet..."<<endl;
        return;
    }
    /*打印raw的*/
//    for (int i = 0; i < packetHeader->len; i++) {
//        printf("%02X ", packetContent[i]);
//    }
//    printf("\n");
//    cout<< sizeof(ether_header)<<endl;
//    cout<< arp_len<<endl;

    ether_arp* etherArp = (ether_arp*)(packetContent + sizeof(struct ether_header));
    arphdr* arp_header = &etherArp->ea_hdr;
    /*转为人类可读的。。。*/
    struct display_arp displayArp{};
    displayArp.hardware_type = check_arp_hardware_type(ntohs(arp_header->ar_hrd));
    displayArp.protocol_type = check_arp_protocol_type(ntohs(arp_header->ar_pro));
    displayArp.hardware_size = arp_header->ar_hln;
    displayArp.protocol_size = arp_header->ar_pln;
    displayArp.opcode = check_arp_opcode(ntohs(arp_header->ar_op));

    convert_to_mac(ether_ntoa((struct ether_addr *)&etherArp->arp_sha), displayArp.sender_mac);
    convert_to_mac(ether_ntoa((struct ether_addr *)&etherArp->arp_tha), displayArp.target_mac);
    struct in_addr ipv4_address{};
    memcpy(&ipv4_address.s_addr, etherArp->arp_spa, 4);
    displayArp.sender_ip = inet_ntoa(ipv4_address);
    memcpy(&ipv4_address.s_addr, etherArp->arp_tpa, 4);
    displayArp.target_ip = inet_ntoa(ipv4_address);
//    cout<<hardware_type<<endl;
//    cout<<protocol_type<<endl;
//    cout<<hardware_size<<endl;
//    cout<<protocol_size<<endl;
//    cout<<op<<endl;
//    cout<<sender_mac<<endl;
//    cout<<target_mac<<endl;
//    cout<<sender_ip<<endl;
//    cout<<target_ip<<endl;
//    cout<<endl;

//    printf("Hardware type: %d\n", ntohs(arp_header->ar_hrd));
//    printf("Protocol type: 0x%04X\n", ntohs(arp_header->ar_pro));
//    printf("Hardware size: %d\n", arp_header->ar_hln);
//    printf("Protocol size: %d\n", arp_header->ar_pln);
//    printf("Operation: %s\n", ntohs(arp_header->ar_op) == ARPOP_REQUEST ? "Request" : "Reply");
//    printf("Sender MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
//           etherArp->arp_sha[0], etherArp->arp_sha[1],
//           etherArp->arp_sha[2], etherArp->arp_sha[3],
//           etherArp->arp_sha[4], etherArp->arp_sha[5]);
//    printf("Sender IP: %d.%d.%d.%d\n",
//           etherArp->arp_spa[0], etherArp->arp_spa[1],
//           etherArp->arp_spa[2], etherArp->arp_spa[3]);
//
//    printf("Target MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
//           etherArp->arp_tha[0], etherArp->arp_tha[1],
//           etherArp->arp_tha[2], etherArp->arp_tha[3],
//           etherArp->arp_tha[4], etherArp->arp_tha[5]);
//    printf("Target IP: %d.%d.%d.%d\n",
//           etherArp->arp_tpa[0], etherArp->arp_tpa[1],
//           etherArp->arp_tpa[2], etherArp->arp_tpa[3]);
}
void analyze_rarp_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent,
                        uint16_t ether_type){
    ether_arp* etherArp = (ether_arp*)(packetContent + sizeof(struct ether_header));
    arphdr* arp_header = &etherArp->ea_hdr;
    /*转为人类可读的。。。*/
    struct display_arp displayArp{};
    displayArp.hardware_type = check_arp_hardware_type(ntohs(arp_header->ar_hrd));
    displayArp.protocol_type = check_arp_protocol_type(ntohs(arp_header->ar_pro));
    displayArp.hardware_size = arp_header->ar_hln;
    displayArp.protocol_size = arp_header->ar_pln;
    displayArp.opcode = check_arp_opcode(ntohs(arp_header->ar_op));

    convert_to_mac(ether_ntoa((struct ether_addr *)&etherArp->arp_sha), displayArp.sender_mac);
    convert_to_mac(ether_ntoa((struct ether_addr *)&etherArp->arp_tha), displayArp.target_mac);
    struct in_addr ipv4_address{};
    memcpy(&ipv4_address.s_addr, etherArp->arp_spa, 4);
    displayArp.sender_ip = inet_ntoa(ipv4_address);
    memcpy(&ipv4_address.s_addr, etherArp->arp_tpa, 4);
    displayArp.target_ip = inet_ntoa(ipv4_address);
//    unsigned int arp_len = packetHeader->len - sizeof(struct ether_header);
//    if (arp_len < sizeof(arphdr)){
//        cout<<"Invalid ARP packet..."<<endl;
//        return;
//    }
//    for (int i = 0; i < packetHeader->len; i++) {
//        printf("%02X ", packetContent[i]);
//    }
//    printf("\n");
//    cout<< sizeof(ether_header)<<endl;
//    cout<< arp_len<<endl;
//
//    ether_arp* etherArp = (ether_arp*)(packetContent + sizeof(struct ether_header));
//    arphdr* arp_header = &etherArp->ea_hdr;
//    printf("Hardware type: %d\n", ntohs(arp_header->ar_hrd));
//    printf("Protocol type: 0x%04X\n", ntohs(arp_header->ar_pro));
//    printf("Hardware size: %d\n", arp_header->ar_hln);
//    printf("Protocol size: %d\n", arp_header->ar_pln);
//    printf("Operation: %s\n", ntohs(arp_header->ar_op) == ARPOP_RREQUEST  ? "Request" : "Reply");
//    printf("Sender MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
//           etherArp->arp_sha[0], etherArp->arp_sha[1],
//           etherArp->arp_sha[2], etherArp->arp_sha[3],
//           etherArp->arp_sha[4], etherArp->arp_sha[5]);
//    printf("Sender IP: %d.%d.%d.%d\n",
//           etherArp->arp_spa[0], etherArp->arp_spa[1],
//           etherArp->arp_spa[2], etherArp->arp_spa[3]);
//
//    printf("Target MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
//           etherArp->arp_tha[0], etherArp->arp_tha[1],
//           etherArp->arp_tha[2], etherArp->arp_tha[3],
//           etherArp->arp_tha[4], etherArp->arp_tha[5]);
//    printf("Target IP: %d.%d.%d.%d\n",
//           etherArp->arp_tpa[0], etherArp->arp_tpa[1],
//           etherArp->arp_tpa[2], etherArp->arp_tpa[3]);
}
void analyze_ipv6_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent,
                         uint16_t ether_type){
    struct ip6_hdr* ipv6Header = (struct ip6_hdr*)(packetContent + sizeof(ether_header));
    struct display_ipv6 displayIpv6{};
    // Print the source and destination IPv6 addresses
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ipv6Header->ip6_src, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET6, &ipv6Header->ip6_dst, dst_ip, sizeof(dst_ip));
//    printf("Source IP: %s\n", src_ip);
//    printf("Destination IP: %s\n", dst_ip);
//
//    printf("Traffic Class: 0x%02X\n", ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_flow);
//    printf("Payload Length: %u\n", ntohs(ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_plen));
//    printf("Next Header (Protocol): %u\n", ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt);
//    printf("Hop Limit: %u\n", ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_hlim);

    displayIpv6.src_ip = src_ip;
    displayIpv6.dst_ip = dst_ip;
    displayIpv6.traffic_class = convert_uint32_to_hex_string(ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_flow);
    displayIpv6.payload_len = ntohs(ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_plen);
    displayIpv6.nxt_header_protocol = check_ip6_nxt_header_protocol(ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt);
    displayIpv6.hop_limit = ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_hlim;

//    cout<<displayIpv6.src_ip<<endl;
//    cout<<displayIpv6.dst_ip<<endl;
//    cout<<displayIpv6.traffic_class<<endl;
//    cout<<displayIpv6.payload_len<<endl;
//    cout<<displayIpv6.nxt_header_protocol<<endl;
//    cout<<displayIpv6.hop_limit<<endl;

    if (ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_ICMPV6){
        analyze_icmpv6_packet(args, packetHeader, packetContent);
    }
}
void analyze_icmpv6_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent){
    struct icmp6_hdr* icmp6Hdr = (struct icmp6_hdr*)(packetContent + sizeof(struct ether_header) + sizeof(struct ip6_hdr));

    printf("ICMPv6 Type: %u\n", icmp6Hdr->icmp6_type);
    printf("ICMPv6 Code: %u\n", icmp6Hdr->icmp6_code);
    icmp6Hdr->icmp6_cksum;

}
string check_icmpv6_type_code(uint8_t type){
    string res;
    if (type == ICMP6_ECHO_REQUEST){
        res += "ICMPv6 Type: Echo Request (Ping)";
    }else if(type == ICMP6_ECHO_REPLY){
        res += "ICMPv6 Type: Echo Reply (Ping Reply)";
    }else if(type == ND_NEIGHBOR_ADVERT){

    }
    return res;
}
string check_ip6_nxt_header_protocol(uint8_t nxt) {
    string res;
    if (nxt == IPPROTO_TCP){
        res += "TCP";
    }else if (nxt == IPPROTO_UDP){
        res += "UDP";
    }else if (nxt == IPPROTO_ICMPV6){
        res += "ICMPv6";
    }
    res += " (";
    res += convert_uint8_to_hex_string(nxt);
    res += ")";
    return res;
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