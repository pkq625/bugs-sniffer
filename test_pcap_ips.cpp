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
