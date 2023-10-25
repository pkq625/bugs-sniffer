//
// Created by tery on 2023/10/22.
//
#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unordered_map>
#include <string>
#include <vector>
#include <cstring>

// A data structure to track TCP flows
struct FlowKey {
    in_addr src_ip;
    in_addr dst_ip;
    uint16_t src_port;
    uint16_t dst_port;

    bool operator==(const FlowKey& other) const {
        return src_ip.s_addr == other.src_ip.s_addr &&
               dst_ip.s_addr == other.dst_ip.s_addr &&
               src_port == other.src_port &&
               dst_port == other.dst_port;
    }
};

// Hash function for FlowKey to be used in unordered_map
struct FlowKeyHash {
    std::size_t operator()(const FlowKey& key) const {
        return std::hash<std::string>()(
                std::to_string(key.src_ip.s_addr) +
                std::to_string(key.dst_ip.s_addr) +
                std::to_string(key.src_port) +
                std::to_string(key.dst_port)
        );
    }
};

// Structure to hold flow statistics
struct FlowStats {
    int packets_sent = 0;
    int packets_received = 0;
    int bytes_sent = 0;
    int bytes_received = 0;
};

std::unordered_map<FlowKey, FlowStats, FlowKeyHash> flow_table;

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14); // Skip Ethernet header
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header->ip_hl * 4); // Skip IP header

    if (ip_header->ip_p == IPPROTO_TCP) {
        FlowKey flow_key;
        flow_key.src_ip = ip_header->ip_src;
        flow_key.dst_ip = ip_header->ip_dst;
        flow_key.src_port = ntohs(tcp_header->th_sport);
        flow_key.dst_port = ntohs(tcp_header->th_dport);

        // Update flow statistics
        FlowStats& flow_stats = flow_table[flow_key];
        flow_stats.packets_sent++;
        flow_stats.bytes_sent += pkthdr->len;

        // You can add logic to track received packets if needed
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <process_port>" << std::endl;
        return 1;
    }

    const uint16_t process_port = std::stoi(argv[1]);
    const char *dev = "eth0"; // Replace with your network interface
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live(dev, 65536, 1, 0, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        return 1;
    }

    std::string filter = "tcp port " + std::to_string(process_port);
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
