cmake_minimum_required(VERSION 3.8)
project(massdns)

set(CMAKE_C_STANDARD 11)

set(SOURCE_FILES src/main.c src/module.h src/list.h src/hashmap.h src/massdns.h src/security.h src/net.h src/string.h src/buffers.h src/dns.h
        src/timed_ring.h src/random.h src/cmd.h src/flow.h)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
add_executable(massdns ${SOURCE_FILES})
