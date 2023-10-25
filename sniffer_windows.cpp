//
// Created by neko on 23-10-18.
//
#include "globalvars.h"
#include "sniffer_windows.h"
// 初始化界面：是否使用颜色、颜色对、不回显等设置
pthread_t mainThread; // to draw the frontend in the terminal...

pthread_t countThread; // 计算每秒的每个设备的包的个数
pthread_t captureThreads[20]; // 这个thread纯统计，然后count thread才是计算的

pthread_t captureTrafficThreads[2]; // upload, download，纯统计的
pthread_t countTrafficThread; // upload, download，纯计算的
pthread_t capturePacketsThread; // 抓指定设备的包
pthread_t savePacketsThread; // 暂存这个，如果输入了save，那就把文件丢到制定地址，如果到结束前也没有save，那丢掉这个暂存的文件
pthread_t processPacketsMsgThread; // 用来把raw的包转为人类可读的
bool check_expression(){
    if (!used_expression.empty()){
        unsigned long tmp = used_expression.find("load");
        if (tmp != string::npos){
            // load the file, maybe it would be better to check the inputs...
            //load_traffic(used_expression.substr(tmp, used_expression.size()).c_str());

        }else{
            // it is filter!!! do check things...
        }
    }
}
void * sniffer_thread(void *pVoid){
    int c;
    init_window();
    // start background threads
    while (!quited) {
        print_error_size(); // 这个函数会首先判断页面的的大小是否合适，，，
        if (current_page == 0 && prev_page == 0) current_page = 1; // 如果是第一次进入
        else if (current_page == 0 && prev_page != 0) {
            current_page = prev_page; // 可能是从0>1,或者0>2
        }
        if (current_page == 1){
            print_startup();
        } else if (current_page == 2){
            print_details();
        }
        c = getch();
        if (current_cmd.find("input") != string::npos){
            if (legal_char.find((char)c) != legal_char.end()) {
                // 输入属于给定的范围内
                expression += (char)c;
            }else if (c == KEY_RIGHT){
                used_expression = expression;
                expression = "";
                current_cmd = "";
            }else if (c == KEY_LEFT){
                expression = "";
                current_cmd = "";
            }
        }else if (current_cmd == "get packet details"){
            if (c == KEY_LEFT){
                // 收缩这一项
                int tmp = find_number_in_vector(msg_stack_idxs[selected_msg_idx], selected_detail_idx);
                if (tmp != -1){
                    packet_detail_status &= ~(1<<cur_selected_item_idxs[tmp]);
                }
            }else if (c == KEY_RIGHT){
                // 展开这一项
                int tmp = find_number_in_vector(msg_stack_idxs[selected_msg_idx], selected_detail_idx);
                if (tmp != -1){
                    packet_detail_status |= (1<<cur_selected_item_idxs[tmp]);
                }
            }
        }else if(current_cmd == "choose dev" && current_page == 1){
            if (c == KEY_RIGHT){
                // goto the detail page, start all the thread related to this page (traffic calculating, packet transfer to human-readable)
                // and stop all the thread in the first page...
                // or you can just let them running in the back, it's not a big problem
                // there are two ways: pause these threads used in first page,
                // another way is to just stop them all (and restart them, after user push q to back to the first page again?)
                // but, for simplicity, I just close all of them and there is no restart for them!!!! :D
                // which means, the user would have to restart this whole program (sudo ./bugs_sniffer) <- the root priv matters
                // and choose a new one. pretty 'cool', right? +v_
                // because the main purpose is just to get (me) familier with the usage of libpcap and other staffs, such as multi-thread\process\coroutine ^w^
                if (!behere){
                    behere = true;
                    isRunning = false;
                    isRunning2 = true;
                    string dvn = menu[selected_dev_name]->dev_name;
                    string mac = get_mac_addr(dvn.c_str());
                    check_expression();
                    struct traffic_s t1 = {dvn.c_str(), mac, "download"};
                    struct traffic_s t2 = {dvn.c_str(), mac, "upload"};
                    pthread_create(&captureTrafficThreads[0], nullptr, cal_traffic_thread, (void*)&t1);
                    pthread_create(&captureTrafficThreads[1], nullptr, cal_traffic_thread, (void*)&t2);
                    pthread_create(&countTrafficThread, nullptr, (void* (*)(void*))update_traffic_count_per_sec, nullptr);
                    cur_dev curDev = {dvn.c_str(), used_expression, "./tmp.pcap"};
                    pthread_create(&savePacketsThread, nullptr, packet_save_thread, (void*)&curDev);
                    pthread_create(&capturePacketsThread, nullptr, capture_packets_thread, (void*)&curDev);
                    pthread_create(&processPacketsMsgThread, nullptr, (void* (*)(void*))update_msg_thread, nullptr);
                }
            }
        }else if (current_cmd == "save traffic" && current_page == 2){
            if (c == KEY_RIGHT){
                // save it!
                save_file("./tmp.pcap", destfile.c_str());
                destfile = "";
                current_cmd = "";
            }else{
                destfile += to_string(c);
            }
        }else if(current_cmd == "input expression" && current_page == 1){
            if (c == KEY_RIGHT) {
                unsigned long tmp = used_expression.find("load");
                if (tmp != string::npos) {
                    if (load_traffic(used_expression.substr(tmp, used_expression.size()).c_str())) {
                        process_msg(0, ethers.size());
                        current_page = 2; // goto the next page}
                    }
                }
                current_cmd = "";
            }
        }
        switch (char(c)) {
            case 'q':
                if (!current_cmd.empty()) {
                    if (current_cmd.find("input") == string::npos) {
                        current_cmd = "";
                        expression = "";
                    }
                }
                else {
                    if (current_page == 0 or current_page == 1) {
                        pthread_mutex_lock(&mutex);
                        isRunning = false;
                        pthread_cond_signal(&cond);
                        pthread_mutex_unlock(&mutex);
                        quited = true;
                    }
                    else if (current_page == 2) {
                        isRunning2 = false;
                        isRunning = false;
                        is_paused = false;
                        quited = true;// maybe I will change it in the future...
                        current_page = 1;
                        prev_page = 2;
                    }
                }
                break;
            case 'f':
                if (current_cmd.empty())
                    current_cmd = "input filter";
                break;
            case 's':
                if (current_cmd.empty()) {
                    current_cmd = "save traffic";
                }
                break;
            case 'i':
                if (current_cmd.empty()) {
                    if (current_page == 2) {
                        current_cmd = "input expression";
                    }
                }
                break;
            case 'd':
                if (current_cmd.empty()) {
                    if (current_page == 2) {
                        current_cmd = "get packet details";

                    } else if (current_page == 1) {
                        current_cmd = "choose dev";
                        selected_row = dev_name_lidx;
                    }
                } else if (current_cmd == "get packet details" && current_page == 2){
                    current_cmd = "";
                    packet_detail_status = 0;
                }
                break;
            case 'm':
                if (current_cmd.empty()) {
                    if (current_page == 1) {
                        current_cmd = "change mode";
                        selected_mode = 0;
                        selected_row = 0;
                    }
                }
                break;
            case ' ':
                if (!current_cmd.empty() && current_cmd.find("input") == string::npos) {
                    if (current_page == 2) {
                        is_paused = !is_paused;
                    } else if (current_page == 1) {
                        if (current_cmd == "change mode") {
                            checked_modes ^= (1 << selected_row);
                        }else if (current_cmd == "choose dev"){
                            //TODO: goto detail page
                        }
                    }
                }
                break;
        }
        switch (c) {
            case KEY_UP:
                if (current_cmd == "change mode" ||
                    current_cmd == "choose dev") {
                    selected_row--;
                    if (current_cmd == "choose dev") {
                        if (selected_dev_name <= dev_name_lidx) {
                            if (dev_name_lidx > 0) {
                                dev_name_ridx--;
                                dev_name_lidx--;
                            } else {
                                // 跳到最后一页
                                dev_name_lidx = tot_items - STARTUP_MAX_DEV_INFO;
                                dev_name_ridx = tot_items - 1;
                            }
                        }
                    }
                } else if (current_cmd.empty()){
                    if (current_page == 1) {
                        current_cmd = "choose dev";
                        selected_row = dev_name_ridx;
                    }else if(current_page == 2){
                        selected_msg_row_idx --;
                        // 不用担心小于0的情况，因为这个不是控制显示的，selected_msg_idx才是，不过selected_msg_idx是根据这个更新的
                        if (selected_msg_idx <= packets_lidx){
                            if (packets_lidx > 0){
                                packets_lidx -- ;
                                packets_ridx -- ;
                            }else{
                                // 跳到最后一页
                                packets_lidx = tot_packets - MAX_PACKETS_ITEM;
                                packets_ridx = tot_packets - 1;
                            }
                        }
                    }
                } else if(current_cmd == "get packet details" && current_page == 2){
                    selected_detail_row_idx -- ;
                    if (selected_detail_idx <= packet_detail_lidx){
                        if (packet_detail_lidx > 0){
                            packet_detail_lidx -- ;
                            packet_detail_ridx -- ;
                        }else{
                            // 跳到最后一页
                            packet_detail_lidx = tot_details - MAX_PACKET_DETAIL_ITEM;
                            packet_detail_ridx = tot_details - 1;
                        }
                    }
                }
                break;
            case KEY_DOWN:
                if (current_cmd == "change mode" ||
                    current_cmd == "choose dev") {
                    selected_row++;
                    if (current_cmd == "choose dev") {
                        if (selected_dev_name >= dev_name_ridx) {
                            if (dev_name_ridx < tot_items - 1) {
                                dev_name_ridx++;
                                dev_name_lidx++;
                            } else {
                                dev_name_lidx = 0;
                                dev_name_ridx = STARTUP_MAX_DEV_INFO - 1;
                            }
                        }
                    }
                } else if (current_cmd.empty()){
                    if (current_page == 1){
                        current_cmd = "choose dev";
                        selected_row = dev_name_lidx;
                    }else if(current_page == 2){
                        selected_msg_row_idx ++;
                        if (selected_msg_idx >= packets_ridx){
                            if (packets_ridx < tot_items - 1){
                                packets_lidx ++ ;
                                packets_ridx ++ ;
                            }else{
                                // 跳到第一页
                                packets_lidx = 0;
                                packets_ridx = MAX_PACKETS_ITEM - 1;
                            }
                        }
                    }
                }else if (current_cmd == "get packet details" && current_page == 2){
                    selected_detail_row_idx ++ ;
                    if (selected_detail_idx >= packet_detail_ridx){
                        if (packet_detail_ridx < tot_details - 1){
                            packet_detail_lidx ++ ;
                            packet_detail_ridx ++ ;
                        }else{
                            // 跳到第一页
                            packet_detail_lidx = 0;
                            packet_detail_ridx = MAX_PACKET_DETAIL_ITEM - 1;
                        }
                    }
                }
                break;
            case KEY_BACKSPACE:
                if (!expression.empty() && current_cmd.find("input") != string::npos) expression.pop_back();
                break;
        }
    }
    endwin();

    pthread_join(processPacketsMsgThread, nullptr);
    pthread_join(savePacketsThread, nullptr);
    pthread_join(capturePacketsThread, nullptr);
    pthread_join(countTrafficThread, nullptr);
    pthread_join(captureTrafficThreads[0], nullptr);
    pthread_join(captureTrafficThreads[1], nullptr);
    return nullptr;
}
void signalHandler(int signo) {
    if (signo == SIGINT) {
        printf("Received SIGINT, stopping the thread.\n");
        isRunning = false;
        for (auto & entry : get_statistic_handles) {
            if (entry.second != nullptr) {
                cout<<"sending signal to: " << entry.first << endl;
                pcap_breakloop(entry.second);
            }
        }
        // Wake up the thread if it's waiting
        pthread_mutex_lock(&mutex);
        pthread_cond_signal(&cond);
        pthread_mutex_unlock(&mutex);
    }
}
void start_sniffer(){
    get_all_dev_info();

    struct sigaction sa{};
    sa.sa_handler = signalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);



    for (size_t i = 0; i < interfaces.size(); i++) {
        pthread_create(&captureThreads[i], nullptr, capture_thread, (void*)interfaces[i]);
    }
    pthread_create(&countThread, nullptr, (void* (*)(void*))update_packet_count_per_sec, nullptr);

    pthread_create(&mainThread, nullptr, sniffer_thread, nullptr);

    for (size_t i = 0; i < interfaces.size(); i++) {
        pthread_join(captureThreads[i], nullptr);
    }
    pthread_join(countThread, nullptr);
    pthread_join(mainThread, nullptr);
    debug_fileout.close();
}
void init_window(){
    // 初始化参数
    checked_modes = 5; // 2 8
    selected_row = 0;
    current_cmd = "";
    // 开始页的初始化
    dev_name_lidx = 0; dev_name_ridx = STARTUP_MAX_DEV_INFO - 1;
    selected_dev_name = 0;
    // 详情页的列表初始化
    packets_lidx = 0; packets_ridx = MAX_PACKETS_ITEM - 1;
    selected_msg_idx = 0;
    // 详情页的选中包初始化
    packet_detail_lidx = 0; packet_detail_ridx = MAX_PACKET_DETAIL_ITEM - 1;
    selected_detail_idx = 0;
    // filter掉一些不合法的字符
    for (int i = 0; i < 10; ++i) {
        legal_char.insert('0'+i);
    }
    for (int i = 0; i < 26; ++i) {
        legal_char.insert('a'+i);
    }
    // 初始化屏幕
    setlocale(LC_ALL, "");
    initscr();
    get_current_size();
    winParameter->colored = COLORED;
    if (COLORED) {
        start_color();
        init_pair(1, COLOR_RED, COLOR_BLACK);
        init_pair(2, COLOR_YELLOW, COLOR_BLACK);
        init_pair(3, COLOR_GREEN, COLOR_BLACK);
        init_pair(4, COLOR_CYAN, COLOR_BLACK);
        init_pair(5, COLOR_BLUE, COLOR_BLACK);
        init_pair(6, COLOR_MAGENTA, COLOR_BLACK);
        init_pair(7, COLOR_WHITE, COLOR_BLACK);
        init_pair(8, COLOR_BLACK, COLOR_WHITE); // 被选中
    }
    cbreak();
    noecho();
    nodelay(stdscr, true); // 非阻塞输入
    keypad(stdscr, true); // 接收键盘的功能键
}
// 暂时只支持160x40
void print_error_size(){
    prev_page = current_page;
    while (!check_window_size()){
        current_page = 0;
        do_print_error_size();
    }
}
// 初始界面
void print_startup(){
    current_page = 1;
    clear();
    do_print_side();
    do_print_hello();
    do_print_startup_input_bar();
    do_print_checkbox();
    do_print_dev_name();
    do_print_statistics();
    refresh();
    usleep(500000);
}
void print_details(){
    current_page = 2;
    clear();
    do_print_side();
    do_print_details_input_bar();
    do_print_packets();
    do_print_traffic_info();
    do_print_packet_details();
    refresh();
    usleep(500000);
}
// 真正做事情的printer们
void do_print_details_input_bar(){
    // do save
}
void process_msg(int lidx, int ridx){
    // 把那些包处理后放进这里。。。captured_msg
    // maybe... there is a more elegant(优雅) way... x_x
    for (int i = lidx; i < ridx; ++i) {
        Msg cur_m{};
        display_ether e = ethers[i];
        if (e.nxt_type & 1){
            // ip
            display_ip tmp = ips[e.nxt_idx];
            if (tmp.nxt_type & 1){
                // tcp
                display_tcp displayTcp = tcps[tmp.nxt_type];
                if (displayTcp.nxt_type & 1){
                    cur_m.protocol = "TLS";
                    cur_m.info = tlss[displayTcp.nxt_idx].type;
                }else if((displayTcp.nxt_type >> 1) & 1){
                    cur_m.protocol = "HTTP";
                    cur_m.info = "暂无";
                }else{
                    cur_m.protocol = "TCP";
                    cur_m.info = "暂无";
                }
            }else if((tmp.nxt_type >> 1) & 1){
                // udp
                display_udp displayUdp = udps[tmp.nxt_type];
                if (displayUdp.nxt_type & 1){
                    cur_m.protocol = "DNS";
                    cur_m.info = dnss[displayUdp.nxt_idx].flags;
                }else if((displayUdp.nxt_type >> 1) & 1){
                    cur_m.protocol = "DHCP";
                    cur_m.info = "暂无";
                }else if((displayUdp.nxt_type >> 2) & 1){
                    cur_m.protocol = "SSDP";
                    cur_m.info = "暂无";
                }else if((displayUdp.nxt_type >> 3) & 1){
                    cur_m.protocol = "DTLS v1.2";
                    cur_m.info = dtlss[displayUdp.nxt_idx].type;
                }else if((displayUdp.nxt_type >> 4) & 1){
                    cur_m.protocol = "STUN";
                    cur_m.info = stuns[displayUdp.nxt_idx].type;
                }else if((displayUdp.nxt_type >> 5) & 1){
                    cur_m.protocol = "QUIC";
                    cur_m.info = "暂无";
                }else{
                    cur_m.protocol = "UDP";
                    cur_m.info = "暂无";
                }
            }else if((tmp.nxt_type >> 2) & 1){
                // icmp
                cur_m.protocol = "ICMP";
                cur_m.info = icmps[tmp.nxt_type].type;
            }
        }else if((e.nxt_type >> 1) & 1){
            // arp
            display_arp tmp = arps[e.nxt_idx];
            cur_m.protocol = "ARP";
            cur_m.info = tmp.opcode + " " + tmp.hardware_type + " " + tmp.protocol_type;
        }else if((e.nxt_type >> 2) & 1){
            // rarp
            display_arp tmp = rarps[e.nxt_idx];
            cur_m.protocol = "RARP";
            cur_m.info = tmp.opcode + " " + tmp.hardware_type + " " + tmp.protocol_type;
        }else if((e.nxt_type >> 3) & 1){
            // ip6
            display_ipv6 tmp = ip6s[e.nxt_idx];
            if (tmp.nxt_type == 1){
                // ICMPv6
                cur_m.protocol = "ICMPv6";
                cur_m.info = icmp6s[tmp.nxt_idx].type;
            }else{
                cur_m.protocol = "IPv6";
                cur_m.info = "暂无";
            }
        }else if((e.nxt_type >> 4) & 1){
            // TODO: vlan
        }else{
            cur_m.src = e.src_mac;
            cur_m.dst = e.dst_mac;
        }
        if (cur_m.protocol.size() <= 1){
            cur_m.protocol = e.type;
        }
        cur_m.num = captured_msg.size();
        cur_m.timestamp = e.timestamp;
        cur_m.len = e.tot_len;
        cur_m.ether_idx = i;
        captured_msg.emplace_back(cur_m);
    }
}
void do_print_captured_msg(int r, int c, int w){
    reshape_selected_row(selected_msg_row_idx, tot_packets);
    selected_msg_idx = selected_msg_row_idx;

    for (int i = packets_lidx; i <= packets_ridx; ++i) {
        if (selected_msg_idx == i)attron(COLOR_PAIR(8));
        else
            attron(COLOR_PAIR(4));
        mvprintw(r, c+1, "| %d", captured_msg[i].num);
        mvprintw(r, c+11, "| %s", captured_msg[i].timestamp.c_str());
        mvprintw(r, c+31, "| %s", captured_msg[i].src.c_str());
        mvprintw(r, c+61, "| %s", captured_msg[i].dst.c_str());
        mvprintw(r, c+91, "| %s", captured_msg[i].protocol.c_str());
        mvprintw(r, c+101, "| %d", captured_msg[i].len);
        mvprintw(r, c+111, "| %s", captured_msg[i].info.c_str());
        r++;
        for (int j = 1; j < w; ++j) {
            mvprintw(r, c+j, "-");
        }
        r ++;
    }
}
void do_print_packets(){
    int w = 150, h = 23;
    int r = 2, c = 5;
    int scroll_w = 2;
    do_print_banner(r++, c++, w, h);
//    do_print_scroll(w - scroll_w - 1, c, scroll_w, h, cur_page, tot_page);
    // 打印右下角的packet数量
    int cur_packet_num = 0;
    int tot_packet_num = 144;
    int num_off = 20;
    mvprintw(r+h, w - num_off, "%d / %d", cur_packet_num, tot_packet_num);
    //打印表头信息
    mvprintw(r, c+1, "| No.");
    mvprintw(r, c+11, "| Timestamp");
    mvprintw(r, c+31, "| src");
    mvprintw(r, c+61, "| dst");
    mvprintw(r, c+91, "| protocol");
    mvprintw(r, c+101, "| len");
    mvprintw(r, c+111, "| info");
    // 打印packet的普通信息，一个packet一行，一页共20行，可以放下10个？
    do_print_captured_msg(r+1, c+1, w);
}
void process_one_packet_idx(int msg_idx){
    process_detailed_one_packet(msg_idx);
    vector<int> idxs = msg_stack_idxs[msg_idx];
    if (packet_detail_status == 0){
        for (int & idx : idxs) {
            cur_selected_item_idxs.emplace_back(idx);
        }
    }else{
        int tmp = packet_detail_status;
        int i = 1, prev = 0;
        while (tmp){
            if (tmp & 1){
                for (int j = prev; j < idxs[i]; ++j) {
                    cur_selected_item_idxs.emplace_back(j);
                }
            }
            prev = idxs[i];
            i++;
            tmp /= 2;
        }
    }
}
void process_ip(vector<string>&v, const display_ip& displayIp){
    v.emplace_back("Internet Protocol Version 4");
    v.emplace_back("Total Length: "+to_string(displayIp.tot_len));
    v.emplace_back("Identification: "+displayIp.ident);
    v.emplace_back("Flags: "+displayIp.flags);
    v.emplace_back("TTL: "+to_string(displayIp.ttl));
    v.emplace_back("Protocol: "+displayIp.protocol);
    v.emplace_back("Header checksum: "+displayIp.checksum);
    v.emplace_back("Source Address: "+displayIp.src_ip);
    v.emplace_back("Destination Address: "+displayIp.dst_ip);
}
void process_tcp(vector<string>&v, const display_tcp& displayTcp){
    v.emplace_back("Transmission Control Protocol");
    v.emplace_back("Source Port: "+to_string(displayTcp.src_port));
    v.emplace_back("Destination Port: "+to_string(displayTcp.dst_port));
    v.emplace_back("Sequence Number: "+to_string(displayTcp.seq));
    v.emplace_back("Acknowledge Number: "+to_string(displayTcp.ack));
    v.emplace_back("Flags: "+displayTcp.flags);
    v.emplace_back("Window: "+to_string(displayTcp.window_size));
    v.emplace_back("Checksum: "+displayTcp.checksum);
    v.emplace_back("Urgent Pointer: "+to_string(displayTcp.urgent_pointer));
}
void process_udp(vector<string>&v, const display_udp& displayUdp){
    v.emplace_back("User Datagram Protocol");
    v.emplace_back("Source Port: "+to_string(displayUdp.src_port));
    v.emplace_back("Destination Port: "+to_string(displayUdp.dst_port));
    v.emplace_back("Length: "+to_string(displayUdp.len));
    v.emplace_back("Checksum: "+displayUdp.checksum);
}
void process_icmp(vector<string>&v, const display_icmp& displayIcmp){
    v.emplace_back("Internet Control Message Protocol");
    v.emplace_back("Type: "+displayIcmp.type);
    v.emplace_back("Code: "+displayIcmp.code);
    v.emplace_back("Checksum: "+displayIcmp.checksum);
    v.emplace_back("Sequence Number: "+displayIcmp.seq);
}
void process_icmp6(vector<string>&v, const display_icmp6& displayIcmp6){
    v.emplace_back("Internet Control Message Protocol v6");
    v.emplace_back("Type: "+displayIcmp6.type);
    v.emplace_back("Code: "+displayIcmp6.code);
    v.emplace_back("Checksum: "+displayIcmp6.checksum);
}
void process_arp(vector<string>&v, const display_arp& displayArp){
    v.emplace_back("Hardware type: "+displayArp.hardware_type);
    v.emplace_back("Protocol type: "+displayArp.protocol_type);
    v.emplace_back("Hardware size: "+to_string(displayArp.hardware_size));
    v.emplace_back("Protocol size: "+to_string(displayArp.protocol_size));
    v.emplace_back("Opcode: "+displayArp.opcode);
    v.emplace_back("Sender MAC: "+displayArp.sender_mac);
    v.emplace_back("Sender IP: "+displayArp.sender_ip);
    v.emplace_back("Target MAC: "+displayArp.target_mac);
    v.emplace_back("Target IP: "+displayArp.target_ip);
}
void process_ip6(vector<string>&v, const display_ipv6& displayIpv6){
    v.emplace_back("Internet Protocol Version 6");
    v.emplace_back("Payload Len: "+ to_string(displayIpv6.payload_len));
    v.emplace_back("Next Header: "+displayIpv6.nxt_header_protocol);
    v.emplace_back("Hop Limit: "+ to_string(displayIpv6.hop_limit));
    v.emplace_back("Source Address: "+displayIpv6.src_ip);
    v.emplace_back("Destination Address: "+displayIpv6.dst_ip);
}
void update_msg_thread(void*args){
    // 把新抓的包仍进来
    while (isRunning2) {
        this_thread::sleep_for(chrono::seconds(5));
        pthread_mutex_lock(&packetProcessMutex);
        while (is_paused){
            // TODO
        }
        int tmp = ethers.size();
        if (tot_items < tmp) {
            process_msg(tot_items, tmp);
            tot_items = tmp;
        }
        pthread_mutex_unlock(&packetProcessMutex);
    }
}
void process_detailed_one_packet(int msg_idx){
    Msg cur_m = captured_msg[msg_idx];
    display_ether e = ethers[cur_m.ether_idx];
    vector<string> items;
    vector<int> sk_idx;
    if (msg_items.find(msg_idx) == msg_items.end()){
        //ether->展开的话，ether+信息 = 4
        // ip -> 展开的话，ip+信息=13
        // arp -> 10
        // ip6 -> 7
        // tcp -> 10
        // udp -> 5
        // icmp -> 6
        // icmp6 -> 3
        // dns -> 4
        // tls -> 3
        // dtls -> 2
        // stun -> 2
        // 暂存入msg_items里面，以后方便读
        sk_idx.emplace_back(0);
        items.emplace_back("Ethernet");
        items.emplace_back("Source: " + e.src_mac);
        items.emplace_back("Destination: " + e.dst_mac);
        items.emplace_back("Type: " + e.type);
        sk_idx.emplace_back(items.size());
        if (cur_m.protocol == "HTTP"){
            process_ip(items, ips[e.nxt_idx]);
            sk_idx.emplace_back(items.size());
            process_tcp(items, tcps[ips[e.nxt_idx].nxt_idx]);
            sk_idx.emplace_back(items.size());
            items.emplace_back("HTTP");
        }else if (cur_m.protocol == "TCP"){
            process_ip(items, ips[e.nxt_idx]);
            sk_idx.emplace_back(items.size());
            process_tcp(items, tcps[ips[e.nxt_idx].nxt_idx]);
        }else if (cur_m.protocol == "TLS"){
            process_ip(items, ips[e.nxt_idx]);
            sk_idx.emplace_back(items.size());
            process_tcp(items, tcps[ips[e.nxt_idx].nxt_idx]);
            sk_idx.emplace_back(items.size());
            items.emplace_back("Transport Layer Security");
            items.emplace_back("Content Type: "+tlss[tcps[ips[e.nxt_idx].nxt_idx].nxt_type].type);
            items.emplace_back("Version: "+tlss[tcps[ips[e.nxt_idx].nxt_idx].nxt_type].version);
        }else if (cur_m.protocol == "DNS"){
            process_ip(items, ips[e.nxt_idx]);
            sk_idx.emplace_back(items.size());
            process_udp(items, udps[ips[e.nxt_idx].nxt_idx]);
            sk_idx.emplace_back(items.size());
            items.emplace_back("Domain Name System");
            items.emplace_back("Transaction ID: "+dnss[tcps[ips[e.nxt_idx].nxt_idx].nxt_type].transaction_id);
            items.emplace_back("Flags: "+dnss[tcps[ips[e.nxt_idx].nxt_idx].nxt_type].flags);
        }else if (cur_m.protocol == "DHCP"){
            process_ip(items, ips[e.nxt_idx]);
            sk_idx.emplace_back(items.size());
            process_udp(items, udps[ips[e.nxt_idx].nxt_idx]);
            sk_idx.emplace_back(items.size());
            items.emplace_back("DHCP");
        }else if (cur_m.protocol == "SSDP"){
            process_ip(items, ips[e.nxt_idx]);
            sk_idx.emplace_back(items.size());
            process_udp(items, udps[ips[e.nxt_idx].nxt_idx]);
            sk_idx.emplace_back(items.size());
            items.emplace_back("SSDP");
        }else if (cur_m.protocol == "DTLS v1.2"){
            process_ip(items, ips[e.nxt_idx]);
            sk_idx.emplace_back(items.size());
            process_udp(items, udps[ips[e.nxt_idx].nxt_idx]);
            sk_idx.emplace_back(items.size());
            items.emplace_back("DTLS v1.2");
            items.emplace_back("Type: "+dtlss[tcps[ips[e.nxt_idx].nxt_idx].nxt_type].type);
        }else if (cur_m.protocol == "STUN"){
            process_ip(items, ips[e.nxt_idx]);
            sk_idx.emplace_back(items.size());
            process_udp(items, udps[ips[e.nxt_idx].nxt_idx]);
            sk_idx.emplace_back(items.size());
            items.emplace_back("STUN");
            items.emplace_back("Type: "+stuns[tcps[ips[e.nxt_idx].nxt_idx].nxt_type].type);
        }else if (cur_m.protocol == "QUIC"){
            process_ip(items, ips[e.nxt_idx]);
            sk_idx.emplace_back(items.size());
            process_udp(items, udps[ips[e.nxt_idx].nxt_idx]);
            sk_idx.emplace_back(items.size());
            items.emplace_back("QUIC");
        }else if (cur_m.protocol == "UDP"){
            process_ip(items, ips[e.nxt_idx]);
            sk_idx.emplace_back(items.size());
            process_udp(items, udps[ips[e.nxt_idx].nxt_idx]);
        }else if (cur_m.protocol == "ICMP"){
            process_ip(items, ips[e.nxt_idx]);
            sk_idx.emplace_back(items.size());
            process_icmp(items, icmps[ips[e.nxt_idx].nxt_idx]);
        }else if (cur_m.protocol == "ARP"){
            items.emplace_back("Address Resolution Protocol");
            process_arp(items, arps[e.nxt_idx]);
        }else if (cur_m.protocol == "RARP"){
            items.emplace_back("Reversed Address Resolution Protocol");
            process_arp(items, rarps[e.nxt_idx]);
        }else if (cur_m.protocol == "ICMPv6"){
            process_ip6(items, ip6s[e.nxt_idx]);
            sk_idx.emplace_back(items.size());
            process_icmp6(items, icmp6s[ips[e.nxt_idx].nxt_idx]);
        }else if (cur_m.protocol == "IPv6"){
            process_ip6(items, ip6s[e.nxt_idx]);
        }else if(cur_m.protocol == "NIP"){
            // TODO
        }
        msg_items[msg_idx] = items;
        msg_stack_idxs[msg_idx] = sk_idx;
    }
}
void do_print_traffic_info(){
    int row = 30, col=5, w=20, h=6;
    do_print_banner(row++, col++, w, h);
    mvprintw(row++, col, "dev: %s", curDevInfo.dev_name);
    if (!curDevInfo.dev_ips.empty())
        mvprintw(row++, col, "addr: %s", curDevInfo.dev_ips[0].c_str());
    if (!download_traffic_per_second.empty())
        mvprintw(row++, col, "Download: %s", download_traffic_per_second.c_str());
    if (!upload_traffic_per_second.empty())
        mvprintw(row, col, "Upload: %s", upload_traffic_per_second.c_str());
}
void do_print_packet_details(){
    int r = 30,c = 45,w = 82,h = 9;
    do_print_banner(r,c,w,h);
    tot_details = (int)cur_selected_item_idxs.size();
    reshape_selected_row(selected_detail_row_idx, tot_details);
    selected_detail_idx = selected_detail_row_idx;
    process_one_packet_idx(selected_detail_idx);
    for (int i = packet_detail_lidx; i <= packet_detail_ridx; ++i) {
        if (i == selected_detail_idx && current_cmd == "get packet details") attron(COLOR_PAIR(8));
        else
            attron(COLOR_PAIR(4));
        mvprintw(r++,c, "%s", msg_items[selected_msg_idx][cur_selected_item_idxs[i]].c_str());
        for (int j = 0; j < w; ++j) {
            mvprintw(r,c+j, "-");
        }
        r++;
    }
}
void do_print_side(){
    // 打印四角
    attron(COLOR_PAIR(4));
    mvprintw(0, 0, "┌");
    mvprintw(winParameter->height-1, 0, "└");
    mvprintw(0, winParameter->width-1, "┐");
    mvprintw(winParameter->height-1, winParameter->width-1, "┘");
    // 打印上面
    // 有字的部分 16, 8, 3+2+4+5,
    get_system_info();
    int tmp_idx = 1;
    for (int i = 1; i < 10; ++i) {
        mvprintw(0, tmp_idx++, "-");
    }
    mvprintw(0, tmp_idx++, "┐");
    mvprintw(0, tmp_idx, "Bugs-neko"); tmp_idx += (int)strlen("Bugs-neko");
    mvprintw(0, tmp_idx++, "┌");
    mvprintw(0, tmp_idx++, "┐");
    mvprintw(0, tmp_idx, "sniffer");   tmp_idx+= (int)strlen("sniffer");
    mvprintw(0, tmp_idx++, "┌");
    // tmp_idx = 27, 27+43 = 70
    for (int i = 0; i < 47; ++i) {
        mvprintw(0, tmp_idx++, "-");
    }
    mvprintw(0, tmp_idx++, "┐");
    mvprintw(0, tmp_idx++, "%s", current_time.c_str());
    tmp_idx += (int)current_time.size();
    mvprintw(0, tmp_idx++, "┌");

    // tmp_idx = 80
    for (int i = 0; i < 45; ++i) {
        mvprintw(0, tmp_idx++, "-");
    }
    mvprintw(0, tmp_idx++, "┐"); // 81
    mvprintw(0, tmp_idx, "BAT:"); tmp_idx += 4;
    mvprintw(0, tmp_idx, "%d%% ", current_battery_percentage); tmp_idx += 5;
    for (int i = 0; i < current_battery_percentage/20; ++i) {
        attron(COLOR_PAIR(i));
        mvprintw(0, tmp_idx++, "█");
    }
    for (int i = current_battery_percentage/20; i <= 5; ++i) {
        attron(COLOR_PAIR(7));
        mvprintw(0, tmp_idx++, "□");
    }
    attron(COLOR_PAIR(4));
    mvprintw(0, tmp_idx++, "┌");
    for (int i = tmp_idx; i < winParameter->width-1; ++i) {
        mvprintw(0, tmp_idx++, "-");
    }
    // 打印左右两边
    for (int i = 1; i < winParameter->height - 1; ++i) {
        mvprintw(i, 0, "|");
        mvprintw(i, winParameter->width-1, "|");
    }
    // 打印下面
    for (int i = 1; i < winParameter->width - 1; ++i) {
        mvprintw(winParameter->height-1, i, "-");
    }
    // 恢复cursor
}
void do_print_hello(){
    attron(COLOR_PAIR(4));
    mvprintw(3, 6, "Welcome and having fun here...");
    attroff(COLOR_PAIR(4));
}
void do_print_startup_input_bar(){
    int row = 8, col = 45;
    if (bar_startup_filter == nullptr)bar_startup_filter = new input_bar{row+1, col+1};
    // 打印边框
    attron(COLOR_PAIR(4));
    mvprintw(row+1, col-9, "过滤器：");
    int w = 80;
    do_print_banner(row, col, w, 2);
    // 打印里面的内容
    if (current_cmd.find("input") != string::npos){
        attron(COLOR_PAIR(8));
        mvprintw(row+1, col + 1, "%s", expression.c_str());
        attron(COLOR_PAIR(7));
        for (int i = 1+(int)expression.size(); i < w; ++i) {
            mvprintw(row+1, col + i, "█");
        }
    }else{
        attron(COLOR_PAIR(7));
        for (int i = 1; i < w; ++i) {
            mvprintw(row+1, col + i, "█");
        }
    }
}
void do_print_checkbox(){
    int row = 3, col = 140;
    int w = 12, h = 5;
    // 外框
    do_print_banner(row, col, w, h);
    if (current_cmd == "change mode") {
        reshape_selected_row(4);
        selected_mode = selected_row;
    }
    int tmp = 1;
    int m = 0;
    for (int i = 0; i < 4; ++i) {
        if (checked_modes & (tmp)){
            if (current_cmd == "change mode") {
                if (selected_mode == i)
                    m = COLOR_PAIR(8) | A_BOLD;
                else
                    m = COLOR_PAIR(3) | A_DIM;
            }else m = COLOR_PAIR(3);
            attron(m);
            mvprintw(row+i+1, col+1, "☑ %s",modes[i].c_str());
            attroff(m);
        }else{
            if (current_cmd == "change mode") {
                if (selected_mode == i)
                    m = COLOR_PAIR(8) | A_BOLD;
                else
                    m = COLOR_PAIR(1) | A_DIM;
            }
            else m = COLOR_PAIR(1);
            attron(m);
            mvprintw(row+i+1, col+1, "☐ %s",modes[i].c_str());
            attroff(m);
        }
        tmp*=2;
    }
}
void reshape_selected_row(int m){
        if (selected_row < 0) {
            selected_row = (-selected_row) % m;
            selected_row = m - selected_row;
        }
        selected_row %=m;
}
void reshape_selected_row(int& r, int m){
        if (r < 0) {
            r = (-r) % m;
            r = m - r;
        }
        r %=m;
}
void do_print_dev_name(){
    if (!dev_interval){
        startup_dev_info_height = STARTUP_DEV_INFO_HEIGHT_OFFSET + get_all_dev_info();
    }
    if(++dev_interval > MAX_DEV_INTERVAL) dev_interval = 0;
    // print frame
    do_print_banner(STARTUP_DEV_INFO_ROW, STARTUP_DEV_INFO_COL, STARTUP_DEV_INFO_WIDTH, startup_dev_info_height);
    // print all the dev
    attron(COLOR_PAIR(7));
    int row_off = 0, off;
    if (current_cmd == "choose dev"){
        reshape_selected_row(selected_row, tot_items);
//        reshape_selected_row(tot_items);
        selected_dev_name = selected_row;
    }
    for (int i = dev_name_lidx; i <= dev_name_ridx; ++i) {
        if (selected_dev_name == i && current_cmd == "choose dev") attron(COLOR_PAIR(8));
        else
            attron(COLOR_PAIR(4));
        mvprintw(STARTUP_DEV_INFO_ROW+row_off+1, STARTUP_DEV_INFO_COL+1, "%s: ", menu[i]->dev_name.c_str());
        off = (int)menu[i]->dev_name.size() + 2;
        attron(COLOR_PAIR(4));
        for (int j = 0; j < menu[i]->ips.size(); ++j) {
            if (menu[i]->ips[j].size() >= 2) {
                mvprintw(STARTUP_DEV_INFO_ROW + row_off + j + 1, off + STARTUP_DEV_INFO_COL + 1, "%s",
                         menu[i]->ips[j].c_str());
            }
        }
        row_off += 3;
    }
}
// 打印一个长方形的哐
void do_print_banner(int row, int col, int w, int h){
    attron(COLOR_PAIR(4));
    mvprintw(row, col, "┌");
    mvprintw(row+h, col, "└");
    mvprintw(row, col + w, "┐");
    mvprintw(row+h, col + w, "┘");
    for (int i = 0; i < w; ++i) {
        mvprintw(row, col+i, "-");
        mvprintw(row+h, col+i, "-");
    }
    for (int i = 0; i < h; ++i) {
        mvprintw(row+i, col, "|");
        mvprintw(row+i, col+w, "|");
    }
}
// 打印旁边的滚轮
void do_print_scroll(int row, int col, int w, int h, int cur_page, int tot_page){
    // w是scroll的宽度，scroll所在的当前行和长度是根据h/cur_page/tot_page决定的
    int scroll_h = h/tot_page;
    int scroll_row = scroll_h*cur_page;
    for (int i = 0; i < h; ++i) {
        mvprintw(row+i, col, "|");
    }
    attron(COLOR_PAIR(8) | A_BOLD);
    for (int j = 0; j < w; ++j) {
        for (int i = 0; i < scroll_h; ++i) {
            mvprintw(scroll_row+i, col+1, "|");
        }
    }
    attroff(COLOR_PAIR(8) | A_BOLD);
}
// 当终端大小不是160x40的时候，进入这个页面
void do_print_error_size(){
    clear();
    attron(COLOR_PAIR(1));
    int r = winParameter->height;
    int c = winParameter->width;
    mvprintw(r/2-1, 0, "current width: %d, supported width: %d", winParameter->width, WINDOW_WIDTH);
    mvprintw(r/2, 0, "current height: %d, supported height: %d", winParameter->height, WINDOW_HEIGHT);
    mvprintw(r/2+1, 0, "Try resizing your window");
    refresh();
    usleep(500000);
}
// 获得数据的地方
// dev_name + ip
int get_all_dev_info(){
    map<char*,vector<string> >results;
    int n = list_all_dev(false, results);
    if (n <= 0) return 0;
    int i = 0;
    int tmp = 0;
    for (auto & result : results) {
        if (strlen(result.first) >= 3
        && strstr(result.first, "bluetooth") == nullptr
        && strstr(result.first, "dbus") == nullptr
        && strstr(result.first, "nf") == nullptr) {
            // nflog需要制定组，nfqueue是主动搜集信息的，不在这里列出
            vector<string> ips;
            for (const auto & j : result.second) {
                if (!j.empty())
                    ips.push_back(j);
            }
            if (ips.empty()) ips.emplace_back("无地址信息");
            auto *m = new menu_item{i, result.first, ips};
            tmp += (int)ips.size();
            interfaces.push_back(result.first);
            interface2idx[result.first] = i;
            menu[i++] = m;
        }
    }
    for (const char* dev : interfaces) {
        packetCounts[dev] = 0;
    }
    tot_items = i;
    return tmp;
}
// 根据每秒包的多少分级
int packet_num_to_level(int num){
    if (num > 0 && num <= 10)
        return 1;
    else if (num > 10 && num < 50){
        return 2;
    }else if (num > 50){
        return 3;
    }else{
        return 0;
    }
}
// 打印开始页每个设备每秒的包数
void do_print_statistics(){
    int row_off = STARTUP_DEV_INFO_ROW+1, col_off, prev = -1, cur;
    for (int i = dev_name_lidx; i < dev_name_ridx; ++i) {
        col_off = 80;
        for (int & it : data_per_interface[menu[i]->dev_name]) {
            if (prev == -1) {
                prev = packet_num_to_level(it);
                continue;
            }
            cur = packet_num_to_level(it);
            if (it > 0 && it <= 10)
                mvprintw(row_off+2, col_off++, "█");
            else if (it > 10 && it < 50){
                mvprintw(row_off+1, col_off, "█");
                mvprintw(row_off+2, col_off++, "█");
            }else if (it > 50){
                mvprintw(row_off, col_off++, "█");
                mvprintw(row_off+1, col_off, "█");
                mvprintw(row_off+2, col_off, "█");
            }
        }
        row_off += 3;
    }
}
// 计算当前设备的每秒的流量
void update_traffic_count_per_sec() {
    while (isRunning2) {
        this_thread::sleep_for(chrono::seconds(5));
        pthread_mutex_lock(&trafficCountMutex);
        while (is_paused){
            // TODO
        }
        for (const auto& entry : traffics) {
            if (entry.first == "download"){
                if (entry.second <= 1024)
                    download_traffic_per_second = to_string(entry.second) + "Bytes/s";
                else if (entry.second <= 1024*1024)
                    download_traffic_per_second = to_string(entry.second / 1024) + "KB/s";
            }else if(entry.first == "upload"){
                if (entry.second <= 1024)
                    upload_traffic_per_second = to_string(entry.second) + "Bytes/s";
                else if (entry.second <= 1024*1024)
                    upload_traffic_per_second = to_string(entry.second / 1024) + "KB/s";
            }
        }
        traffics.clear();
        pthread_mutex_unlock(&trafficCountMutex);
    }
}
// 计算每个设备每秒的包数量
void update_packet_count_per_sec() {
    while (isRunning) {
//        debug_fileout << time(nullptr) << ": update"<<endl;
        this_thread::sleep_for(chrono::seconds(5));

        pthread_mutex_lock(&packetCountMutex);
        int tmp = 0;
//        cout<<interfaces.size()<<" "<<packetCounts.size()<<endl;
        for (const auto& entry : packetCounts) {
            data_per_interface[entry.first].push_back(entry.second);
            if (data_per_interface[entry.first].size() >= MAX_DATA_SIZE_PER_ITEM)
                data_per_interface[entry.first].pop_front();
            tmp |= (1<<interface2idx[entry.first]);
            //std::cout <<"[" <<time(nullptr) <<"] " << entry.first << " Packets per second on " << ": " << entry.second << std::endl;
            debug_fileout<< entry.first << ": "<<entry.second<<endl;
        }
        for (int j = 0; j < interfaces.size(); ++j) {
            if (!(tmp & (1<<j))){
                data_per_interface[interfaces[j]].push_back(0);
                if (data_per_interface[interfaces[j]].size() >= MAX_DATA_SIZE_PER_ITEM)
                    data_per_interface[interfaces[j]].pop_front();
                debug_fileout<< interfaces[j] << ": "<<0<<endl;
                //std::cout <<"[" <<time(nullptr) <<"] " << interfaces[j] << " Packets per second on " << ": " << 0 << std::endl;
            }
        }
        packetCounts.clear();
        pthread_mutex_unlock(&packetCountMutex);
    }
}
// 判断是否是160x40
bool check_window_size(){
    get_current_size();
    return winParameter->height == WINDOW_HEIGHT && winParameter->width == WINDOW_WIDTH;
}
// 当前窗口大小
void get_current_size(){
    if (winParameter == nullptr){
        winParameter = new win_parameter{getmaxx(stdscr), getmaxy(stdscr)};
    }else{
        winParameter->width = getmaxx(stdscr);
        winParameter->height = getmaxy(stdscr);
    }
}
// 获得当前时间和电池量
void get_system_info(){
    time_t tt;
    time(&tt);
    struct tm* p = localtime(&tt);
    current_time = "";
    if (p->tm_hour < 10) current_time += "0";
    current_time+=to_string(p->tm_hour);
    current_time += ":";
    if (p->tm_min < 10) current_time += "0";
    current_time+=to_string(p->tm_min);
    current_time += ":";
    if (p->tm_sec < 10) current_time += "0";
    current_time+=to_string(p->tm_sec);
    // 读文件很慢，所以battery隔很久再读
    if (!battery_interval){
        battery_interval = 0;
        ifstream in(battery_file);
        if (!in.is_open()) current_battery_percentage = 0;
        char buf[256];
        in.getline(buf, 100);
        current_battery_percentage = stoi(buf);
    }
    if (++battery_interval >= MAX_BATTERY_INTERVAL){
    }
}
// 找到一个vector里是否有这个数字，如果有数字的话，返回下标，没有就返回-1
int find_number_in_vector(const std::vector<int>& numbers, int target) {
    auto it = std::lower_bound(numbers.begin(), numbers.end(), target);
    if (it != numbers.end() && *it == target) {
        int index = std::distance(numbers.begin(), it);
        return index;
    }

    return -1; // Return -1 if the number is not found
}
void save_file(const char* sourceFilePath, const char* destinationFilePath) {
    // Just copy...
    std::ifstream sourceFile(sourceFilePath, ios::binary);
    if (!sourceFile) {
        return;
    }

    std::ofstream destinationFile(destinationFilePath, ios::binary);
    if (!destinationFile) {
        return;
    }

    destinationFile << sourceFile.rdbuf();

    sourceFile.close();
    destinationFile.close();
}