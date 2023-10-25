#include "sniffer_windows.h"

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    // Open the capture device
    handle = pcap_open_live("wlo1", BUFSIZ, 0, 0, errbuf);
    bpf_u_int32 ipaddress, ipmask; // unsigned int
    pcap_lookupnet("wlo1", &ipaddress, &ipmask, ERROR_BUFFER);
    load_traffic("./2.pcap");

//    pcap_t* pcapOutput = pcap_open_dead(DLT_EN10MB, 65535);
//    pcap_dumper_t * t = open_pcap_dumper(pcapOutput, "./2.pcap");


//    struct bpf_program filter{};
//    if (pcap_compile(handle, &filter, "tcp and port 443", 0, ipaddress) != -1){
//        if (pcap_setfilter(handle, &filter) != -1)cout<<"filter set ok"<<endl;
//    }
//
//    struct pcap_pkthdr header{};
////    while (true) {
//        const u_char *packet = pcap_next(handle, &header);
//        int id = 0;
//        if (packet != nullptr) {
//            analyze_ether_packet((u_char *) &id, &header, packet);
//            packet_saver((u_char *) t, &header, packet);
//
////        }
//    }
//    close_dumper(t);
//    pcap_close(handle);
//    return 0;

//    get_all_dev_info();
//    initscr(); // initialize screen 初始化ncurses
//    // 启动颜色支持
//    start_color();
//    // 设置文本的颜色
//    init_pair(1, COLOR_RED, COLOR_BLACK);
//    init_pair(2, COLOR_GREEN, COLOR_BLACK);
//    cbreak();
//    noecho();
//    nodelay(stdscr, true); // 非阻塞输入
//    while (true){
//        clear();
//        attron(COLOR_PAIR(1));
//        mvprintw(0, 0, "CPU Usage: 50%%");
//        attron(COLOR_PAIR(2));
//        mvprintw(1, 0, "Memory Usage: 60%%");
//        refresh();
//        usleep(500000);
//    }
//    endwin();
//    for(auto it = dev_infos.begin(); it != dev_infos.end(); it++){
//        cout<<"["<<i++<<"]: "<<it->first<<endl;
//        for (int j = 0; j < it->second.size(); ++j) {
//            cout<<it->second[j]<<endl;
//        }
//    }

//    cout<<"please choose one dev: "<<endl;
//    int choice;
//    cin>>choice;
//    cout<<"Your choice is: "<<choice<<endl;
//    if (choice >= 0 && choice < dev_infos.size()){
//        char* dev_name;
//        struct dev_info devInfo{};
//        for (auto & dev_info : dev_infos) {
//            if (choice-- == 0) {
//                dev_name = dev_info.first;
//                devInfo.dev_ips = dev_info.second;
//                break;
//            }
//        }
//        pcap_t* dev_handle = open_dev(dev_name, 0);
//        devInfo.dev_name = dev_name;
//        devInfo.dev_handle = dev_handle;
//        vector<char*> ips;
//        get_dev_masked_ip(devInfo, ips);
//
//        vector<int>packets_per_second;
//        for (int j = 0; j < 10; ++j) {
//            get_dev_statistics(devInfo.dev_name, 1, j, packets_per_second, false);
//        }
//        close_dev(dev_handle);
//    } else{
//        cout<<"Cannot find this dev..."<<endl;
//    }
    return 0;
}
