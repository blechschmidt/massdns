cmake_minimum_required(VERSION 3.8)
project(massdns)

set(CMAKE_C_STANDARD 11)

set(SOURCE_FILES main.c module.h list.h hashmap.h massdns.h security.h mixed_list.h net.h string.h buffers.h dns.h
        timed_ring.h random.h cmd.h flow.h)
add_executable(massdns ${SOURCE_FILES})