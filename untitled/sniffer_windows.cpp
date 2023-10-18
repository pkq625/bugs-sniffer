//
// Created by neko on 23-10-18.
//
#include "sniffer_windows.h"
int get_all_dev_info(){
    map<char*,vector<string> >results;
    int n = list_all_dev(false, results);
    if (n <= 0) return 0;
    int i = 0;
    for (auto & result : results) {
        string ips;
        for (int j = 0; j < result.second.size(); ++j) {
            ips += result.second[j];
            ips += ";";
        }

        menu_item* m = new menu_item{i, result.first, ips, {0}};
        menu[i++] = m;
    }
    if (DEBUG_MODE) {
        for (int j = 0; j < i; ++j) {
            cout << menu[j]->dev_name << " " << menu[j]->ips << endl;
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
}