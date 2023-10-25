//
// Created by tery on 2023/10/22.
//
#include <iostream>
#include <cstdlib>
#include <cstring>

int main() {
    int pid = YOUR_PROCESS_PID; // Replace with the PID of the process you want to inspect

    // Build the netstat command
    char cmd[100];
    std::strcpy(cmd, "netstat -tuln | grep ");
    std::strcat(cmd, std::to_string(pid).c_str());

    // Execute the command and capture the output
    FILE* pipe = popen(cmd, "r");
    if (!pipe) {
        std::cerr << "Command execution failed." << std::endl;
        return 1;
    }

    // Read and print the output
    char buffer[128];
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        std::cout << buffer;
    }

    pclose(pipe);

    return 0;
}
