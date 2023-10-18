//
// Created by neko on 23-10-18.
//

#ifndef UNTITLED_SNIFFER_WINDOWS_H
#define UNTITLED_SNIFFER_WINDOWS_H
#include "bugs_sniffer.h"
#include <ncurses.h>
// #include <coroutine> // 使用携程来获得这些数据
// 固定的常量
static const int MAX_DATA_SIZE_PER_ITEM = 30;
static const int MAX_MENU_SIZE = 10;
struct win_parameter{
    int width;
    int height;
};
struct menu_item{
    int num;
    string dev_name;
    string ips;
    int data[MAX_DATA_SIZE_PER_ITEM];
};
// 公用的常量
static menu_item* menu[MAX_MENU_SIZE];
static int tot_items;
WINDOW* init_window(struct win_parameter* winParameter); // 初始化窗口
// 共两个界面：初始界面，详细信息界面
void print_startup();
void print_details();
// 公用的模块
void do_print_side(); //
void do_print_statistics();
void do_print_dev_name();
void do_print_packets();
void do_print_packet_details();
void do_print_traffic_info();
// 获取数据的函数
int get_all_dev_info();
void get_all_statistics();
void do_get_one_item_stati(int i);
void get_system_info(vector<int>&results);
#endif //UNTITLED_SNIFFER_WINDOWS_H
