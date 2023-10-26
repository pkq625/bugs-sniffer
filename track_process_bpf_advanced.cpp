//
// Created by neko on 2023/10/22.
//
#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <cstring>
#include <cerrno>

const int TARGET_PID = PID;

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14);
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header->ip_hl * 4);

    if (ip_header->ip_p == IPPROTO_TCP && (ip_header->ip_src.s_addr == htonl(TARGET_PID) || ip_header->ip_dst.s_addr == htonl(TARGET_PID))) {
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

    char filter_exp[50];
    std::snprintf(filter_exp, sizeof(filter_exp), "ip[12:4] = %d or ip[16:4] = %d", TARGET_PID, TARGET_PID);

    struct bpf_program fp;

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Error compiling filter" << std::endl;
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Error setting filter: " << pcap_geterr(handle) << std::endl;
        return 1;
    }

    pcap_loop(handle, 0, packet_handler, nullptr);

    pcap_close(handle);

    return 0;
}
