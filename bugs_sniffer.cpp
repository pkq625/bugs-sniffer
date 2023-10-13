#include<pcap.h>
#include<cstdio>
int main(int ac, char*av[]){
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
        printf("[%d]. %s. ", ++i, cur_dev->name);
        if(cur_dev->description){
            printf("%s", cur_dev->description);
        }
        printf("\n");
    }
    return 0;
}