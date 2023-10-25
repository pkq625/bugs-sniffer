//
// Created by neko on 23-10-18.
//

#ifndef UNTITLED_SNIFFER_WINDOWS_H
#define UNTITLED_SNIFFER_WINDOWS_H
#include "bugs_sniffer.h"
#include <ncurses.h>
#include "globalvars.h"
// #include <coroutine> // 使用携程来获得这些数据
// 固定的常量
static const int MAX_DATA_SIZE_PER_ITEM = 60;
static const int MAX_MENU_SIZE = 10;
static const int WINDOW_WIDTH = 160;
static const int WINDOW_HEIGHT = 40;
static const bool COLORED = true;
static const int MAX_TRAFFIC_SIZE = 30;
static const int MAX_BATTERY_INTERVAL = 1000;
static const int MAX_DEV_INTERVAL = 1000;
static const int STARTUP_PAGE_INPUT_BAR_ROW = 10;
static const int STARTUP_PAGE_INPUT_BAR_COL = 10;
static const int STARTUP_CHECK_BOX_ROW = 10;
static const int STARTUP_CHECK_BOX_COL = 10;
static const int STARTUP_MAX_DEV_INFO = 2;
static const int MAX_SHOWN_PACKETS = 2000;
// 开始页的设备信息框
static const int STARTUP_DEV_INFO_ROW = 15;
static const int STARTUP_DEV_INFO_COL = 20;
static const int STARTUP_DEV_INFO_WIDTH = 120;
static const int STARTUP_DEV_INFO_HEIGHT_OFFSET = 2;
static const unsigned int MAX_ALARM_TIME = 5;
// 详情页信息
static const int MAX_PACKET_DETAIL_ITEM = 4;
static const int MAX_PACKETS_ITEM = 10;
// 定义结构体
struct win_parameter{
    int width;
    int height;
    bool colored;
};
struct input_bar{
    int x;
    int y;
};
struct cursor_status{
    int row;
    int col;
};
struct menu_item{
    int num;
    string dev_name;
    vector<string> ips;
};
static unordered_map<string, list<int> > data_per_interface;
static unordered_map<string, int> interface2idx;
struct detailed_info_item{
    int num;
    int timestamp;
    char* src;
    char* dst;
    char* protocol;
    int len;
    char* info;
};
struct dev_detailed_info{
    char* dev_name;
    char* ip_addr;
    struct detailed_info_item* items[];
};
struct Msg{
    int num;
    string timestamp;
    string src,dst;
    string protocol;
    int len;
    string info;
    int ether_idx;
};
// 公用的常量
static win_parameter* winParameter;
static cursor_status* cursorStatus;
static menu_item* menu[MAX_MENU_SIZE];
static int tot_items;
static bool quited = false;
static string current_time;
static int battery_interval = 0;
static int dev_interval = 0;
static int current_battery_percentage;
static string battery_file = "/sys/class/power_supply/BAT0/capacity"; // 自己改，现在是hard coded
static string current_cmd;
static float uploads_total, downloads_total;
static float uploads_max, downloads_max;
static int selected_packet_num;
static int selected_dev_name;
static int dev_name_lidx;
static int dev_name_ridx;
static int selected_mode;
static int selected_row;
static int checked_modes; // 0000->都没选中,0001->wired,0010->bluetooth
static input_bar* bar_startup_filter;
static input_bar* bar_detail_filepath;
static string expression;
static string used_expression;
static string modes[5] = {"wired", "bluetooth", "wireless", "extern"};
static int behere = false;
//static vector<packet>packets;
//static vector<packet>filtered_packets;
// q->退出或者返回上一页，f->filter, 空格->暂停or开始，i->输入【load path】，s保存当前的所有, d->当前选中的packket的detailed info
static char current_inputted_char;
static int current_page = 0, prev_page = 0; // 0-> size error page, 1 -> 首页, 2-> detail页
static set<char>legal_char{' ', '/', '.', '&', '|', ':'};
static int startup_dev_info_height;
static vector<Msg> captured_msg; // 村的是所有转化【变成屏幕显示的格式】过的包
static int selected_msg_idx; // 当前选中msg的idx
static int selected_detail_idx; // 当前选中msg的idx
static int selected_detail_row_idx; // 当前选中msg detail的行的idx
static int selected_msg_row_idx; // 当前选中msg的行的idx,之后根据这个改变selected_msg_idx
static int tot_packets, tot_details;
static unordered_map<int, vector<string> > msg_items; // 缓存所有被打开过的包，如果没选中过，也没必要存入吧 ：。
static unordered_map<int, vector<int> > msg_stack_idxs; // 村的是当前选中的包的对应各层包头的信息
static vector<int> cur_selected_item_idxs; // 村的是当前选中的包的哪些可以打印的index，根据status来更新 ：。
static int packet_detail_lidx, packet_detail_ridx, packet_detail_status; // status存的是展开的项，默认是0【都不展开：）】
static int packets_lidx, packets_ridx; // 当前表格里显示的包的index
static string download_traffic_per_second, upload_traffic_per_second;
static dev_info curDevInfo{};
static string destfile;
// functions
void start_sniffer();
void update_msg_thread(void*args);
void init_window();
void * sniffer_thread(void *pVoid);
WINDOW* init_window(struct win_parameter* winParameter); // 初始化窗口
// 共三个界面：初始界面，详细信息界面，界面的size不对
void print_startup();
void print_details();
void print_error_size();
// 公用的模块
void do_print_side(); //
void do_print_hello();
void do_print_startup_input_bar();
void do_print_checkbox(); // 打印开始页的设备类型选择
void do_print_dev_name(); // 打印开始页的设备名称信息
void do_print_statistics(); // 打印开始页每个设备每秒的包数
void do_print_details_input_bar();
void do_print_packets();
void do_print_packet_details();
void do_print_traffic_info();
void do_print_error_size(); // 当终端大小不是160x40的时候，进入这个页面
void do_print_banner(int row, int col, int w, int h); // 打印一个长方形的哐
void do_print_scroll(int row, int col, int w, int h, int cur_page, int tot_page); // 打印旁边的滚轮
void do_print_captured_msg(int lidx, int ridx, int r, int c);
// 判断函数
bool check_window_size(); // 判断窗口大小是否是160x40
void reshape_selected_row(int m);
void reshape_selected_row(int& r, int m); //
int packet_num_to_level(int num); // 根据每秒包的多少分级
bool check_expression();
// 获取数据的函数
int get_all_dev_info(); // 获取当前机器上的设备信息：name+ip
void get_all_statistics();
void do_get_one_item(int i) ;
void get_system_info(); // 获得当前时间和电池量
void get_current_size(); // 当前窗口大小
void update_packet_count_per_sec(); // 计算每个设备每秒的包数量
void update_traffic_count_per_sec(); // 计算当前设备的每秒的流量
void process_msg(int lidx, int ridx); //
void process_ip(vector<string>&v, const display_ip& displayIp);
void process_tcp(vector<string>&v, const display_tcp& displayTcp);
void process_udp(vector<string>&v, const display_udp& displayUdp);
void process_icmp(vector<string>&v, const display_icmp& displayIcmp);
void process_icmp6(vector<string>&v, const display_icmp6& displayIcmp6);
void process_arp(vector<string>&v, const display_arp& displayArp);
void process_ip6(vector<string>&v, const display_ipv6& displayIpv6);
void process_detailed_one_packet(int msg_idx);
void save_file(const char* sourceFilePath, const char* destinationFilePath);
void process_one_packet_idx(int msg_idx); /*当packet_detail_status改变的时候调用，初始化的时候也需要调用一次*/
int find_number_in_vector(const std::vector<int>& numbers, int target); // 找到一个vector里是否有这个数字，如果有数字的话，返回下标，没有就返回-1
#endif //UNTITLED_SNIFFER_WINDOWS_H
