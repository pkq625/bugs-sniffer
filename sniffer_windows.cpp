//
// Created by neko on 23-10-18.
//
#include "globalvars.h"
#include "sniffer_windows.h"
// 初始化界面：是否使用颜色、颜色对、不回显等设置
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
            //print_details();
        }
        c = getch();
        if (current_cmd.find("input") != string::npos){
            if (legal_char.find((char)c) != legal_char.end()) {
                // 输入属于给定的范围内
                expression += (char)c;
            }else if (c == KEY_RIGHT){
                expression = "";
                current_cmd = "";
                // TODO: call the function
            }else if (c == KEY_LEFT){
                expression = "";
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
                        current_page = 1;
                        quited = false;
                        prev_page = 2;
                    }
                }
                break;
            case 'f':
                if (current_cmd.empty())
                    current_cmd = "input filter";
                break;
            case 's':
                if (current_cmd.empty())
                    current_cmd = "save traffic";
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
                    current_cmd == "choose dev" || current_cmd == "get packet details") {
                    selected_row--;
                    if (current_cmd == "choose dev") {
                        if (selected_dev_name <= dev_name_lidx) {
                            if (dev_name_lidx > 0) {
                                dev_name_ridx--;
                                dev_name_lidx--;
                            } else {
                                dev_name_lidx = tot_items - STARTUP_MAX_DEV_INFO;
                                dev_name_ridx = tot_items - 1;
                            }
                        }
                    }
                } else if (current_cmd.empty()){
                    current_cmd = "choose dev";
                    selected_row = dev_name_ridx;
                }
                break;
            case KEY_DOWN:
                if (current_cmd == "change mode" ||
                    current_cmd == "choose dev" || current_cmd == "get packet details") {
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
                    current_cmd = "choose dev";
                    selected_row = dev_name_lidx;
                }
                break;
            case KEY_BACKSPACE:
                if (!expression.empty() && current_cmd.find("input") != string::npos) expression.pop_back();
                break;
        }
    }
    endwin();
    return nullptr;
}
void signalHandler(int signo) {
    if (signo == SIGINT) {
        printf("Received SIGINT, stopping the thread.\n");
        isRunning = false;
        int i = 0;
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

    pthread_t countThread;
    pthread_t mainThread;
    pthread_t captureThreads[interfaces.size()];
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
    dev_name_lidx = 0; dev_name_ridx = STARTUP_MAX_DEV_INFO - 1;
    selected_dev_name = 0;
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
// 真正做事情的printer们
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
        reshape_selected_row(tot_items);
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
// 总包
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
void update_packet_count_per_sec() {
    while (isRunning) {
        debug_fileout << time(nullptr) << ": update"<<endl;
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
//
bool check_window_size(){
    get_current_size();
    return winParameter->height == WINDOW_HEIGHT && winParameter->width == WINDOW_WIDTH;
}
//
void get_current_size(){
    if (winParameter == nullptr){
        winParameter = new win_parameter{getmaxx(stdscr), getmaxy(stdscr)};
    }else{
        winParameter->width = getmaxx(stdscr);
        winParameter->height = getmaxy(stdscr);
    }
}
void get_system_info(){
    // 获得当前时间
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