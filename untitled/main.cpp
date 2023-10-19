#include "sniffer_windows.h"

int main() {
    start_sniffer();
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
//    map<char*, vector<string> > dev_infos;
//    list_all_dev(false, dev_infos);
//    cout<<"list all dev names: "<<endl;
//    int i = 0;
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
//        get_dev_statistics(devInfo, 1, 1000, packets_per_second, false);
//        close_dev(dev_handle);
//    } else{
//        cout<<"Cannot find this dev..."<<endl;
//    }
    return 0;
}
