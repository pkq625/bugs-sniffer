#include<bugs_sniffer.h>
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
void func(){
    int i = 0;
    pcap_if_t* all_devs;
    pcap_if_t* cur_dev;
    char err_buff[PCAP_ERRBUF_SIZE];
    if(pcap_findalldevs(&all_devs, err_buff) == -1){
        printf("Cannot find any device... Make sure you're running as root.\n");
        return -1;
    }
    printf("List all availble devices...\n");
    for(cur_dev=all_devs; cur_dev; cur_dev=cur_dev->next){
        printf("[%d]. %s ", ++i, cur_dev->name);
        // printf("[%d]. %s. ", ++i, cur_dev->name);
        if(cur_dev->description){
            printf("%s", cur_dev->description);
        }
        printf("\n");
    }
    printf("The device you choose is: 1. wlan0\n"); // this is hard-coded will be modified later
    char* dev_name = all_devs->name;
    // sniff!
    pcap_t* pcap_handle = pcap_open_live(dev_name, 65535, 1, 0, err_buff);
    if (pcap_handle == NULL){
        printf("%s\n", err_buff);
        return 0;
    }
    // IP and mask
    struct in_addr addr;
    bpf_u_int32 ipaddress, ipmask;
    char* dev_ip, *dev_mask;
    if(pcap_lookupnet(dev_name, &ipaddress, &ipmask, err_buff) == -1){
        printf("%s\n", err_buff);
        return 0;
    }
    // print the ip_hdr and mask
    addr.s_addr = ipaddress;
    dev_ip =inet_ntoa(addr);
    addr.s_addr = ipmask;
    dev_mask = inet_ntoa(addr);
    printf("ip_hdr address: %s, netmask: %s\n", dev_ip, dev_mask);
    // capture packets and print them!
    int id = 0;
    if(pcap_loop(pcap_handle, 10, pcap_callback, (unsigned char*)&id) < 0){
        printf("error!\n");
        return 0;
    }
    pcap_close(pcap_handle);
    return 0;
}

void pcap_callback(unsigned char* arg, const struct pcap_pkthdr* packet_header, const unsigned char* packet_content){
    int* id = (int*)arg; // packet id
    printf("packet id = %d\n", ++(*id));
    printf("Packet Length: %d\n", packet_header->len);
    printf("Number of Bytes: %d\n", packet_header->caplen);
    printf("Received time: %s\n", ctime((const time_t*)&packet_header->ts.tv_sec));
    int i = 0;
    for (; i < packet_header->caplen; i++){
        printf(" %02x", packet_content[i]);
        if ((i+1)%16 == 0){
            printf("\n");
        }
    }
    printf("\n\n");
    u_int eth_len = sizeof(eth_header);
    u_int ip_len = sizeof(ip_header);
    u_int tcp_len = sizeof(tcp_header);
    u_int udp_len = sizeof(udp_header);
    printf("analyze information... \n\n");
    printf("------------- eth_hdr header information -------------");
    eth_hdr=(eth_header *)packet_content;
    printf("src_mac : %02x-%02x-%02x-%02x-%02x-%02x\n",eth_hdr->src_mac[0],eth_hdr->src_mac[1],eth_hdr->src_mac[2],eth_hdr->src_mac[3],eth_hdr->src_mac[4],eth_hdr->src_mac[5]);
    printf("dst_mac : %02x-%02x-%02x-%02x-%02x-%02x\n",eth_hdr->dst_mac[0],eth_hdr->dst_mac[1],eth_hdr->dst_mac[2],eth_hdr->dst_mac[3],eth_hdr->dst_mac[4],eth_hdr->dst_mac[5]);
    printf("eth_hdr type : %u\n",eth_hdr->eth_type);
    if(ntohs(eth_hdr->eth_type)==0x0800){
        printf("IPV4 is used\n");
        printf("IPV4 header information:\n");
        ip_hdr=(ip_header*)(packet_content+eth_len);
        printf("source ip_hdr : %d.%d.%d.%d\n",ip_hdr->sourceIP[0],ip_hdr->sourceIP[1],ip_hdr->sourceIP[2],ip_hdr->sourceIP[3]);
        printf("dest ip_hdr : %d.%d.%d.%d\n",ip_hdr->destIP[0],ip_hdr->destIP[1],ip_hdr->destIP[2],ip_hdr->destIP[3]);
        if(ip_hdr->protocol==6){
            printf("tcp is used:\n");
            tcp_hdr=(tcp_header*)(packet_content+eth_len+ip_len);
            printf("tcp source port : %u\n",tcp_hdr->sport);
            printf("tcp dest port : %u\n",tcp_hdr->dport);
        }
        else if(ip_hdr->protocol==17){
            printf("udp is used:\n");
            udp_hdr=(udp_header*)(packet_content+eth_len+ip_len);
            printf("udp source port : %u\n",udp_hdr->sport);
            printf("udp dest port : %u\n",udp_hdr->dport);
        }
        else {
            printf("other transport protocol is used\n");
        }
    }
    else {
        printf("ipv6 is used\n");
    }

    printf("------------------done-------------------\n");
    printf("\n\n");
}

int main(){
}