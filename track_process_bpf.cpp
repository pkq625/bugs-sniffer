//
// Created by tery on 2023/10/22.
//
#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <cstring>
#include <vector>

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14); // Skip Ethernet header
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header->ip_hl * 4); // Skip IP header

    if (ip_header->ip_p == IPPROTO_TCP && (tcp_header->th_sport == htons(PROCESS_PORT))) {
        // Replace PROCESS_PORT with the source port used by the process
        // You can adjust this condition as needed to capture packets from a specific process.
        std::cout << "Source IP: " << inet_ntoa(ip_header->ip_src) << std::endl;
        std::cout << "Destination IP: " << inet_ntoa(ip_header->ip_dst) << std::endl;
        std::cout << "Source Port: " << ntohs(tcp_header->th_sport) << std::endl;
        std::cout << "Destination Port: " << ntohs(tcp_header->th_dport) << std::endl;
    }
}

int main() {
    const char *dev = "eth0"; // Replace with your network interface
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live(dev, 65536, 1, 0, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        return 1;
    }

    std::string filter = "tcp and src port PROCESS_PORT"; // Replace PROCESS_PORT with the process's source port
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
