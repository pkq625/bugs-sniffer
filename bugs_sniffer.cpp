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
string check_ethertype(uint16_t t){
    string res;
    if (t == ETHER_TYPE_IPV4){
        res += "IPv4";
    }else if (t == ETHER_TYPE_ARP){
        res += "ARP";
    }else if (t == ETHER_TYPE_PARP){
        res += "PARP";
    }else if (t == ETHER_TYPE_IPV6){
        res += "IPV6";
    }else if (t == ETHERTYPE_VLAN){
        res += "VLAN";
    }else{
        return convert_uint16_to_hex_string(t);
    }
    res += " (";
    res += convert_uint16_to_hex_string(t);
    res += ")";
    return res;
}
void analyze_ether_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent){
    uint16_t ether_type;
//    for (int i = 0; i < strlen((const char*)packetContent); ++i) {
//        cout<<unsignedCharToHexString(packetContent[i])<<" ";
//    }
//    cout<<endl;
    struct ether_header* etherHeader = (struct ether_header*)packetContent;
    ether_type = check_ethernet_type(etherHeader);
    string srcmac, dstmax;
    convert_to_mac(ether_ntoa((struct ether_addr *)&etherHeader->ether_shost), srcmac);
    convert_to_mac(ether_ntoa((struct ether_addr *)&etherHeader->ether_dhost), dstmax);
//    cout<<etherHeader->ether_type<<", "<<srcmac<<", "<<dstmax<<endl;
    display_ether displayEther{};
    displayEther.src_mac = srcmac;
    displayEther.dst_mac = dstmax;
    displayEther.type = check_ethertype(ether_type);
    displayEther.tot_len = packetHeader->len;
    displayEther.timestamp = packetHeader->ts.tv_sec;

    if (ether_type == ETHER_TYPE_IPV4){
        displayEther.nxt_type = 1;
        analyze_ip_packet(args, packetHeader, packetContent, ether_type);
    }else if (ether_type == ETHER_TYPE_ARP){
        displayEther.nxt_type = (1<<1);
        analyze_arp_packet(args, packetHeader, packetContent, ether_type);
    }else if (ether_type == ETHER_TYPE_PARP){
        displayEther.nxt_type = (1<<2);
        analyze_rarp_packet(args, packetHeader, packetContent, ether_type);
    }else if (ether_type == ETHER_TYPE_IPV6){
        displayEther.nxt_type = (1<<3);
        analyze_ipv6_packet(args, packetHeader, packetContent, ether_type);
    }else if (ether_type == ETHERTYPE_VLAN){
        displayEther.nxt_type = (1<<4);
        analyze_vlan_packet(args, packetHeader, packetContent, ether_type);
    }else{
//        displayEther.nxt_type = 1;
        analyze_others_packet(args, packetHeader, packetContent, ether_type);
    }
    ethers.emplace_back(displayEther);
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
int analyze_vlan_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent,
                       uint16_t ether_type){
    //TODO
}
int analyze_others_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent,
                         uint16_t ether_type){
    //TODO
}
int analyze_ip_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent,
        uint16_t ether_type){
    display_ip displayIP = {};
    struct ether_header *etherHeader = (struct ether_header*)packetHeader;
    iphdr* ip_header = (iphdr*)(packetContent + sizeof(struct ether_header));
    unsigned int ip_len = packetHeader->len - sizeof(struct ether_header);
    if (ip_len < sizeof(struct iphdr)){
//        cout << "Invalid IP packet"<<endl;
        return -1;
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
//    cout<<displayIP.checksum<<endl;
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
        displayIP.nxt_type = 1;
        displayIP.nxt_idx = analyze_tcp_packet(args, packetHeader, packetContent, "ip");
    }else if (ip_header->protocol == IP_TYPE_UDP){
        displayIP.nxt_type = (1<<1);
        displayIP.nxt_idx = analyze_udp_packet(args, packetHeader, packetContent, "ip");
    }else if (ip_header->protocol == IP_TYPE_ICMP){
        displayIP.nxt_type = (1<<2);
        displayIP.nxt_idx = analyze_icmp_packet(args, packetHeader, packetContent);
    }else if (ip_header->protocol == IP_TYPE_IGMP){

    }else {
        analyze_others_packet(args, packetHeader, packetContent);
    }
    ips.emplace_back(displayIP);
    return ips.size() - 1;
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
int analyze_tcp_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent,
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
    const unsigned char* data = (packetContent + sizeof(struct ether_header) + sizeof(iphdr) + sizeof(tcp_header));
    unsigned long data_size = packetHeader->len - (unsigned long)(sizeof(struct ether_header) + sizeof(iphdr) + sizeof(tcp_header));
    if (displayTcp.src_port == 443 || displayTcp.dst_port == 443){
        displayTcp.nxt_type = 1;
        displayTcp.nxt_idx = analyze_tls_packet(data);
    }else{
        string tmp = uchar2string(data, 0, data_size < 50?data_size:50);
        cout<<tmp<<endl;
        if (tmp.find("485454502F312E31") != string::npos || // HTTP/1.1
        tmp.find("474554")!= string::npos // GET
        || tmp.find("504F5354")!= string::npos){ // POST
            // http
            displayTcp.nxt_type = (1<<1);
            displayTcp.nxt_idx = analyze_http_packet(data);
        }else{
//            cout<<"tcp"<<endl;
        }
    }
    tcps.emplace_back(displayTcp);
    return tcps.size() - 1;
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
int analyze_http_packet(const unsigned char* data){
    return 0;
}
int analyze_tls_packet(const unsigned char* data){
    string tmp;
    tmp = uchar2string(data, 0, 1);
    display_tls displayTls{};
    if (tmp== "16"){
        // handshake
        displayTls.type = "Handshake";
//        cout<<"tls handshake"<<endl;
    }else if(tmp == "17"){
        //application data
        displayTls.type = "Application Data";
//        cout<<"application data"<<endl;
    }else if(tmp == "15"){
        displayTls.type = "Alert";
//        cout<<"Alert"<<endl;
    }
    if (uchar2string(data, 1, 3) == "0303") {
        // TLS1.3
        displayTls.version = "TLS 1.3";
//        cout<<"tls 1.3"<<endl;
    }else if(uchar2string(data, 1, 3) == "0301"){
        // TLS1.0
        displayTls.version = "TLS 1.0";
//        cout<<"tls 1.0"<<endl;
    }
    tlss.emplace_back(displayTls);
    return tlss.size() - 1;
}
int analyze_udp_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent,
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
    displayUdp.len = ntohs(udpHeader->uh_ulen);
    displayUdp.checksum = convert_uint16_to_hex_string(ntohs(udpHeader->uh_sum));
    const unsigned char* data = packetContent + sizeof(struct ether_header) + sizeof(iphdr) + sizeof(udphdr);
    unsigned long data_size = packetHeader->len - (unsigned long)(sizeof(struct ether_header) + sizeof(iphdr) + sizeof(udphdr));
    if(displayUdp.src_port == 53 || displayUdp.dst_port == 53){
        /*DNS*/
        // 端口一定是53
        displayUdp.nxt_type = 1;
        displayUdp.nxt_idx = analyze_dns_packet(data, data_size);
    }else if((displayUdp.src_port == 68 && displayUdp.dst_port == 67) || (displayUdp.src_port == 67 && displayUdp.dst_port == 68)){
        /*DHCP*/
        displayUdp.nxt_type = (1<<1);
        displayUdp.nxt_idx = analyze_dhcp_packet(data);
    }else if(displayUdp.dst_port == 1900){
        /*ssdp*/
        displayUdp.nxt_type = (1<<2);
        displayUdp.nxt_idx = analyze_ssdp_packet(data);
    }else if(uchar2string(data, 1, 3) == "fefd"
             && hexstring2decnum(uchar2string(data, 0, 1)) / 20 < 4
             && hexstring2decnum(uchar2string(data, 0, 1)) / 20 >= 0
    ){
        /*dtls12*/
        displayUdp.nxt_type = (1<<3);
        displayUdp.nxt_idx = analyze_dtls12_packet(data);
    }else if((uchar2string(data, 0, 2) == "0001" || uchar2string(data, 0, 2) == "0101")
            && data_size <= 120
    ){
        /*stun*/
        // stun头部的开始两位必须为0
        // 0001, 0101
        displayUdp.nxt_type = (1<<4);
        displayUdp.nxt_idx = analyze_stun_packet(data);
    }else if((lower_layer_type == "ip" && data_size <= 1370) || (lower_layer_type == "ip6" && data_size <= 1350)

    ){
        /*QUIC*/
        // 当前QUIC在IPV6下的最大报文长度为1350，IPV4下的最大报文长度为1370.
        // 所有的Quic包都是以一个1~51字节的公共头开始的
        // TODO
        displayUdp.nxt_type = (1<<5);
        displayUdp.nxt_idx = analyze_quic_packet(data);
    }
    udps.emplace_back(displayUdp);
    return udps.size() - 1;
}
string uchar2string(const unsigned  char* s, int lidx, int ridx){
    char str[100];
    for (int i = lidx; i < ridx; ++i) {
        sprintf(str+2*i, "%02X", s[i]);
    }
    return str;
}
int hexstring2decnum(const string& hexstr){
    char *endptr;
    int ans = (int)strtoul(hexstr.c_str(), &endptr, 16);
    if (*endptr != '\0') {
//        cerr << "Error: Invalid hexadecimal string." << endl;
        return 0;
    }
    return ans;
}
int analyze_dns_packet(const unsigned char* data, unsigned int len){
    struct display_dns displayDns{};
    displayDns.transaction_id = uchar2string(data, 0, 2);
    displayDns.flags = uchar2string(data, 2, 4);
    if (displayDns.flags == "8180"){
        displayDns.flags = "Standard query response";
    }else if (displayDns.flags == "0100"){
        displayDns.flags = "Standard query";
    }
    displayDns.question_num = hexstring2decnum(uchar2string(data, 4, 6));
    // TODO
    data[6];
    dnss.emplace_back(displayDns);
    return dnss.size() - 1;
}
int analyze_dhcp_packet(const unsigned char* data){
//    cout<<"DHCP!"<<endl;
    return 0;
}
int analyze_ssdp_packet(const unsigned char* data){
//    cout<<"SSDP"<<endl;
    return 0;
}
int analyze_quic_packet(const unsigned char* data){
//    cout<<"QUIC"<<endl;
    return 0;;
}
int analyze_dtls12_packet(const unsigned char* data){
    int tmp = hexstring2decnum(uchar2string(data, 0, 1));
    display_dtls displayDtls{};
    switch (tmp) {
        case 20:
//            cout << "ChangeCipherSpec" << endl;
            displayDtls.type = "ChangeCipherSpec";
            break;
        case 21:
//            cout << "Alert" << endl;
            displayDtls.type = "Alert";
            break;
        case 22:
//            cout << "Handshake" << endl;
            displayDtls.type = "Handshake";
            break;
        case 23:
//            cout << "Application Data" << endl;
            displayDtls.type = "Application Data";
            break;
        default:
//            cout << "wrong!!!" << endl;
            break;
    }
    dtlss.emplace_back(displayDtls);
    return dtlss.size() - 1;
}
int analyze_stun_packet(const unsigned char* data){
    string tmp = uchar2string(data, 0, 2);
    display_stun displayStun{};
    if (tmp == "0001"){
        displayStun.type = "Binding request";
//        cout << "Binding request"<<endl;
    }else if (tmp == "0101"){
//        cout<<"Binding success"<<endl;
        displayStun.type = "Binding success";
    }
    stuns.emplace_back(displayStun);
    return stuns.size();
}
int analyze_icmp_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent){
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
    icmps.emplace_back(displayIcmp);
    return icmps.size() - 1;
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

int analyze_others_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent){
//    cout<<"others..."<<endl;
return 0;
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
int analyze_arp_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent,
                        uint16_t ether_type){
    unsigned int arp_len = packetHeader->len - sizeof(struct ether_header);
    if (arp_len < sizeof(arphdr)){
//        cout<<"Invalid ARP packet..."<<endl;
        return 0;
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
    arps.emplace_back(displayArp);
    return arps.size() - 1;
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
int analyze_rarp_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent,
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
    rarps.emplace_back(displayArp);
    return rarps.size() - 1;
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
int analyze_ipv6_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent,
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
        displayIpv6.nxt_type = 1;
        displayIpv6.nxt_idx = analyze_icmpv6_packet(args, packetHeader, packetContent);
    }
    ip6s.emplace_back(displayIpv6);
    return ip6s.size() - 1;
}
int analyze_icmpv6_packet(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent){
    struct icmp6_hdr* icmp6Hdr = (struct icmp6_hdr*)(packetContent + sizeof(struct ether_header) + sizeof(struct ip6_hdr));

//    printf("ICMPv6 Type: %u\n", icmp6Hdr->icmp6_type);
//    printf("ICMPv6 Code: %u\n", icmp6Hdr->icmp6_code);

    struct display_icmp6 displayIcmp6{};
    displayIcmp6.type = check_icmpv6_type_code(icmp6Hdr->icmp6_type);
    displayIcmp6.code = convert_uint8_to_hex_string(icmp6Hdr->icmp6_code);
    displayIcmp6.checksum = icmp6Hdr->icmp6_cksum;
//    displayIcmp6.flags = icmp6Hdr.
    icmp6s.emplace_back(displayIcmp6);
    return icmp6s.size() - 1;
}
string check_icmpv6_type_code(uint8_t type){
    string res;
    if (type == ICMP6_ECHO_REQUEST){
        res += "ICMPv6 Type: Echo Request (Ping)";
    }else if(type == ICMP6_ECHO_REPLY){
        res += "ICMPv6 Type: Echo Reply (Ping Reply)";
    }else if(type == ND_NEIGHBOR_ADVERT){
        res += "Neighbor Advertisement";
    }else if(type == ND_NEIGHBOR_SOLICIT){
        res += "Neighbor Solicitation";
    }
    res += " (";
    res += convert_uint8_to_hex_string(type);
    res += ")";
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
// this is a callback func
void packet_saver(unsigned char* args, const struct pcap_pkthdr *packetHeader, const unsigned char*packetContent) {
    pcap_dumper_t *dumper = (pcap_dumper_t *)args;
    // Save the packet to the pcap file
    pcap_dump((u_char *)dumper, packetHeader, packetContent);
}
pcap_dumper_t * open_pcap_dumper(pcap_t* handle, const char *filepath){
    pcap_dumper_t *dumper = pcap_dump_open(handle, filepath);
    if (dumper == nullptr) {
//        fprintf(stderr, "Error opening pcap file: %s\n", pcap_geterr(handle));
        return nullptr;
    }
    return dumper;
}
void close_dumper(pcap_dumper_t * dumper){
    pcap_dump_close(dumper);
}
void packet_reader(unsigned char*args, const struct pcap_pkthdr *packetHader, const unsigned char*packetContent) {
    // This function is called for each packet in the pcap file
    analyze_ether_packet(args, packetHader, packetContent);
}
bool load_traffic(const char *filepath) {
    pcap_t *handle = pcap_open_offline(filepath, ERROR_BUFFER);
    if (handle == nullptr) {
        fprintf(stderr, "Error opening pcap file: %s\n", ERROR_BUFFER);
        return false;
    }
    // Process packets from the pcap file
    if (pcap_loop(handle, 0, packet_reader, nullptr) < 0) {
//        fprintf(stderr, "Error processing packets: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return false;
    }
    pcap_close(handle);
    return true;
}
/*tcp flow track*/
// Function to replace a placeholder in a string with a value
void track_tcp_ip_port_bpf_based(char*dev_name, const string& src_ip, int src_port, const string& dst_ip, int dst_port){
    char filter[200];
    sprintf(filter, "tcp and (host %s and port %d) or (host %s and port %d)", src_ip.c_str(), src_port, dst_ip.c_str(), dst_port);
    struct bpf_program fp{};
    pcap_t* handle = pcap_open_live(dev_name, 65536, 1, 0, ERROR_BUFFER);
    if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
//        cerr << "Error compiling filter" << endl;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
//        cerr << "Error setting filter" << endl;
    }
    pcap_loop(handle, 0, analyze_ether_packet, nullptr);
    pcap_close(handle);
}
//void track_tcp_ip_port_hashtable_handler(unsigned char* args, const struct pcap_pkthdr* packetHeader, const unsigned char* packetContent) {
//    struct iphdr *ip_header = (struct iphdr *) (packetContent + sizeof(ether_header));
//    struct tcphdr *tcp_header = (struct tcphdr *) (packetContent + sizeof(ether_header) + sizeof(iphdr));
//    if (ip_header->protocol == IPPROTO_TCP) {
//        FlowKey flow_key{};
//        flow_key.src_ip = in_addr{ip_header->saddr};
//        flow_key.dst_ip = {ip_header->daddr};
//        flow_key.src_port = ntohs(tcp_header->th_sport);
//        flow_key.dst_port = ntohs(tcp_header->th_dport);
//
//        lock_guard<std::mutex> lock(flow_table_mutex);
//        FlowStats &flow_stats = flow_table[flow_key];
//        flow_stats.packets_sent++;
//        flow_stats.bytes_sent += packetHeader->len;
//    }
//}
//void print_flow_statistics() {
//    while (true) {
//        std::this_thread::sleep_for(std::chrono::seconds(1));
//
//        std::lock_guard<std::mutex> lock(flow_table_mutex);
//        for (const auto& entry : flow_table) {
//            const FlowKey& flow_key = entry.first;
//            const FlowStats& flow_stats = entry.second;
//
//            // Print statistics
//            cout << "Flow: " << inet_ntoa(flow_key.src_ip) << ":" << flow_key.src_port << " -> "
//                      << inet_ntoa(flow_key.dst_ip) << ":" << flow_key.dst_port << " - "
//                      << "Sent Packets: " << flow_stats.packets_sent << " - "
//                      << "Sent Bytes: " << flow_stats.bytes_sent << endl;
//        }
//    }
//}
//void track_tcp_ip_port_hashtable_based(const string& ip, int port){
//    const char* dev = "wlo1"; // Replace with your network interface
//    char errbuf[PCAP_ERRBUF_SIZE];
//    pcap_t* handle;
//
//    handle = pcap_open_live(dev, 65536, 1, 0, errbuf);
//    if (handle == nullptr) {
//        cerr << "Error opening device: " << errbuf << endl;
//    }
//
//    std::string filter = "tcp"; // Filter for TCP traffic
//    struct bpf_program fp;
//
//    if (pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
//        cerr << "Error compiling filter" << endl;
//    }
//
//    if (pcap_setfilter(handle, &fp) == -1) {
//        cerr << "Error setting filter" << endl;
//    }
//
//    // Start a separate thread to periodically print flow statistics
//    std::thread statistics_thread(print_flow_statistics);
//
//    pcap_loop(handle, 0, track_tcp_ip_port_hashtable_handler, nullptr);
//
//    pcap_close(handle);
//}
int get_ip_port(string s, int sidx, string& ip, int& port){
    int idx = s.find(':', sidx);
    if (idx != std::string::npos){
        int len = 0;
        for (int i = idx+1; i < s.size(); ++i) {
            if (!isdigit(s[i])){
                break;
            }
            len++;
        }
        port = std::stoi(s.substr(idx+1, len));
        len = 0;
        for (int i = idx-1; i >= 0; --i) {
            if (!isdigit(s[i]) && s[i] != '.'){
                break;
            }
            len++;
        }
        ip = s.substr(idx-len, len);
        return idx;
    }
    return -1;
}
void get_all_ports(int pid, vector<string>&src_ips,vector<int>&src_ports,
                   vector<string>&dst_ips,vector<int>&dst_ports
){
    // Build the netstat command
    char cmd[100];
    std::strcpy(cmd, "netstat -nap | grep ");
    std::strcat(cmd, std::to_string(pid).c_str());

    // Execute the command and capture the output
    FILE* pipe = popen(cmd, "r");
    if (!pipe) {
//        cerr << "Command execution failed." << endl;
        return;
    }
    char buffer[128];
    int idx;
    string src_ip, dst_ip;
    int src_port, dst_port;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        if (strstr(buffer, "tcp")) {
            idx = get_ip_port(buffer, 0, src_ip, src_port);
            idx = get_ip_port(buffer, idx+1, dst_ip, dst_port);
            src_ips.push_back(src_ip);
            src_ports.push_back(src_port);
            dst_ips.push_back(dst_ip);
            dst_ports.push_back(dst_port);
        }
    }
}
void track_process_ports_based(int pid, char* dev_name){
    vector<string>src_ips, dst_ips;
    vector<int>src_ports, dst_ports;
    get_all_ports(pid, src_ips, src_ports, dst_ips, dst_ports);
    for (int i = 0; i < src_ips.size(); ++i) {
        track_tcp_ip_port_bpf_based(dev_name, src_ips[i], src_ports[i], dst_ips[i], dst_ports[i]);
    }
}
void track_process_bpf_based(int pid){
    //TODO
}