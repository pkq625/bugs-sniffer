// it's just a test...
#include <stdio.h>
#include <pcap.h>
int main(int ac,char *av[]){
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i = 0;
    pcap_t *ahandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    // get all the device
    if (pcap_findalldevs(&alldevs, errbuf) == -1){
        printf("Erro in pcapfindalldevs");
        return(-1);
    }
    // print all the devices
    for (d=alldevs; d; d=d->next){
        printf("[%d]: %s",++i, d->name);
        if (d->description){
            printf("%s\n", d->description);
        }else{
            printf("\n");
        }
    }
    if (i == 0){
        printf("No interface found!");
    }
    return(0);
  }
