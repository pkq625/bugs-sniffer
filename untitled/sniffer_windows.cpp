//
// Created by neko on 23-10-18.
//
#include "sniffer_windows.h"
// 初始化界面：是否使用颜色、颜色对、不回显等设置
void start_sniffer(){
    int c;
    init_window();
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
                    if (current_page == 0 or current_page == 1) quited = true;
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
                    }
                }
                break;
            case 'm':
                if (current_cmd.empty()) {
                    if (current_page == 1) {
                        current_cmd = "change mode";
                        selected_mode = 0;
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
                }
                break;
            case KEY_DOWN:
                if (current_cmd == "change mode" ||
                    current_cmd == "choose dev" || current_cmd == "get packet details") {
                    selected_row++;
                }
                break;
            case KEY_BACKSPACE:
                if (!expression.empty() && current_cmd.find("input") != string::npos) expression.pop_back();
                break;
        }
    }
    endwin();
}
void init_window(){
    // 初始化参数
    checked_modes = 15;
    selected_row = 0;
    current_cmd = "";
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
//    do_print_statistics();
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
    mvprintw(0, tmp_idx, "Bugs-neko"); tmp_idx += strlen("Bugs-neko");
    mvprintw(0, tmp_idx++, "┌");
    mvprintw(0, tmp_idx++, "┐");
    mvprintw(0, tmp_idx, "sniffer");   tmp_idx+= strlen("sniffer");
    mvprintw(0, tmp_idx++, "┌");
    // tmp_idx = 27, 27+43 = 70
    for (int i = 0; i < 47; ++i) {
        mvprintw(0, tmp_idx++, "-");
    }
    mvprintw(0, tmp_idx++, "┐");
    mvprintw(0, tmp_idx++, "%s", current_time.c_str());
    tmp_idx += current_time.size();
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
}
void do_print_startup_input_bar(){
    int row = 8, col = 45;
    if (bar_startup_filter == nullptr)bar_startup_filter = new input_bar{row+1, col+1};
    // 打印边框
    attron(COLOR_PAIR(4));
    mvprintw(row+1, col-9, "过滤器：");
    int w = 80;
    mvprintw(row, col, "┌");
    mvprintw(row+2, col, "└");
    mvprintw(row, col + w, "┐");
    mvprintw(row+2, col + w, "┘");
    for (int i = 1; i < w; ++i) {
        mvprintw(row, col + i, "-");
        mvprintw(row+2, col + i, "-");
    }
    mvprintw(row+1, col, "|");
    mvprintw(row+1, col + w, "|");
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
    attron(COLOR_PAIR(4));
    mvprintw(row, col, "┌");
    mvprintw(row+h, col, "└");
    mvprintw(row, col + w, "┐");
    mvprintw(row+h, col + w, "┘");
    for (int i = 1; i < w; ++i) {
        mvprintw(row, col+i, "-");
        mvprintw(row+h, col+i, "-");
    }
    for (int i = 1; i < h; ++i) {
        mvprintw(row+i, col, "|");
        mvprintw(row+i, col + w, "|");
    }
    int tmp = 1;
    if (current_cmd == "change mode"){
        if (selected_row < 0) {
            selected_row = (-selected_row) % 4;
            selected_row += 2;
        }
        selected_row %=4;
        selected_mode = selected_row;
    }

    for (int i = 0; i < 4; ++i) {
        if (checked_modes & (tmp)){
            if (selected_mode == i && current_cmd == "change mode") attron(COLOR_PAIR(8));
            else attron(COLOR_PAIR(3));
            mvprintw(row+i+1, col+1, "☑ %s",modes[i].c_str());
        }else{
            if (selected_mode == i && current_cmd == "change mode") attron(COLOR_PAIR(8));
            else attron(COLOR_PAIR(1));
            mvprintw(row+i+1, col+1, "☐ %s",modes[i].c_str());
        }
        tmp*=2;
    }
}
void do_print_dev_name(){
    if (!dev_interval){
        startup_dev_info_height = STARTUP_DEV_INFO_HEIGHT_OFFSET + get_all_dev_info();
    }
    if(++dev_interval > MAX_DEV_INTERVAL) dev_interval = 0;
    // print frame
    do_print_banner(STARTUP_DEV_INFO_ROW, STARTUP_DEV_INFO_COL, STARTUP_DEV_INFO_WIDTH, startup_dev_info_height);
    // print all the dev
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
int get_all_dev_info(){
    map<char*,vector<string> >results;
    int n = list_all_dev(false, results);
    if (n <= 0) return 0;
    int i = 0;
    for (auto & result : results) {
        vector<string> ips;
        for (int j = 0; j < result.second.size(); ++j) {
            ips.push_back(result.second[j]);
        }
        if (ips.empty()) ips.emplace_back("无地址信息");
        menu_item* m = new menu_item{i, result.first, ips, {0}};
        menu[i++] = m;
    }
    if (DEBUG_MODE) {
        for (int j = 0; j < i; ++j) {
            cout << menu[j]->dev_name << " " << menu[j]->ips[0] << endl;
        }
    }
    tot_items = i;
    return i;
}

void get_all_statistics(){
    for (int i = 0; i < tot_items; ++i) {
        do_get_one_item_stati(i);
    }
}
void do_get_one_item_stati(int i){
    if (i >= tot_items) return;
    // 这里用多线程。。。
    // 这里等函数返回，如果没有返回，则杀掉函数，然后返回0
    // TODO
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