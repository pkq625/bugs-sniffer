#include "bugs_sniffer.h"
using namespace std;
int main() {
    vector<char*>v;
    cout<<list_all_dev(true, v);
    return 0;
}
