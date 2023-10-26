cmake_minimum_required(VERSION 3.26)
project(untitled)

set(CMAKE_CXX_STANDARD 17)

add_executable(untitled main.cpp
        globalvars.h
        bugs_sniffer.h
        sniffer_windows.h
        bugs_sniffer.cpp
        sniffer_windows.cpp
        globalvars.cpp)
target_link_libraries(untitled -lpcap -lncursesw -lpthread)