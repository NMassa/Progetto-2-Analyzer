cmake_minimum_required(VERSION 3.6)
project(Progetto_2___Analyzer)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
        analyzer.c
        bpf.h
        general.conf
        glob.c
        liv2.c
        liv3.c
        liv4.c
        liv7.c
        log
        Makefile
        my.h
        util.c)

add_executable(Progetto_2___Analyzer ${SOURCE_FILES})
target_link_libraries(Progetto_2___Analyzer /usr/lib/x86_64-linux-gnu/libpcap.a)
