//
// Created by neko on 2023/10/22.
//
#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <cstring>

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14);
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header->ip_hl * 4);

    if (ip_header->ip_p == IPPROTO_TCP &&
        (ip_header->ip_src.s_addr == inet_addr("SOURCE_IP") ||
         ip_header->ip_dst.s_addr == inet_addr("DEST_IP")) &&
        (tcp_header->th_sport == htons(PORT1) || tcp_header->th_dport == htons(PORT2))
            ) {
        std::cout << "Source IP: " << inet_ntoa(ip_header->ip_src) << std::endl;
        std::cout << "Destination IP: " << inet_ntoa(ip_header->ip_dst) << std::endl;
        std::cout << "Source Port: " << ntohs(tcp_header->th_sport) << std::endl;
        std::cout << "Destination Port: " << ntohs(tcp_header->th_dport) << std::endl;
    }
}

int main() {
    const char *dev = "eth0";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live(dev, 65536, 1, 0, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        return 1;
    }

    std::string filter = "tcp and (host SOURCE_IP and port PORT1) or (host DEST_IP and port PORT2)";
    struct bpf_program fp;

    if (pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Error compiling filter" << std::endl;
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Error setting filter" << std::endl;
        return 1;
    }

    pcap_loop(handle, 0, packet_handler, nullptr);

    pcap_close(handle);

    return 0;
}
