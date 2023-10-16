#include<pcap.h>
#include<cstdio>
#include<vector>
#include<iostream>
using namespace std;

int listAll(vector<char*>&results){
    pcap_if_t* all_devs;
    char err_buff[PCAP_ERRBUF_SIZE];
    if(pcap_findalldevs(&all_devs, err_buff) == -1){
        cout<<"Cannot find any device... Make sure you're running as root."<<endl;
        return 0;
    }
    while (all_devs){
        results.push_back(all_devs->name);
        all_devs = all_devs->next;
    }
    return results.size();
}
int getAddr(char* dev_name, char err_buff, vector<char*>&results){
    // 1 = ipv4, 2 = ipv4+ipv6
    
    pcap_t* pcap_handle = pcap_open_live(dev_name, 65535, 1, 0, err_buff);
    if (pcap_handle == NULL){
        printf("%s\n", err_buff);
        return 0;
    }
    struct in_addr addr;
    bpf_u_int32 ipaddress;
    char* dev_ip, *dev_mask;
    if(pcap_lookupnet(dev_name, &ipaddress, &ipmask, err_buff) == -1){
        printf("%s\n", err_buff);
        return 0;
    }
}
int pcap_protocal(pcap_dumper_t* args, const struct pcap_pkthdr* packet_header, const u_char* packet){
    pcap_dump((char*)args, packet_header, packet);
    printf("packet size: %u, data len: %u\n", packet_header->len, packet->caplen);
    struct ether_header* etherhdr = (struct ehter_header*) packet;
    unsigned char* src_mac = ehterhdr->src_mac;
    unsigned char* dst_mac = ehterhdr->dst_mac;
    printf("src mac: %x:%x:%x:%x:%x:%x\n", src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
    printf("src mac: %x:%x:%x:%x:%x:%x\n", dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
    printf("ehter type: %u\n", etherhdr->ether_type);

    int eth_len = sizeof(struct ether_header); 
    if (ntohs(etherhdr->ether_type) == ETHERTYPE_IPV4){
        // transfer 16 bit network bytes into host bytes
        printf("IPv4: ")
    }else if (ntohs(etherhdr->ether_type) == ETHERTYPE_IPV6){
        printf("IPv6!");
    }else{
        printf("Others");
    }
    
    return 0;
}

void test_listAll(){
    vector<char*>results;
    int n = listAll(results);
    for (int i = 0; i <n; i++){
        printf("%s\n", results[i]);
    }
}
int main(){
    test_listAll();
}