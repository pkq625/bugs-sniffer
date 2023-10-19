cmake_minimum_required(VERSION 3.26)
project(untitled)

set(CMAKE_CXX_STANDARD 17)

add_executable(untitled main.cpp
        bugs_sniffer.h
        bugs_sniffer.cpp
        sniffer_windows.cpp
        sniffer_windows.h)
target_link_libraries(untitled -lpcap -lncursesw)