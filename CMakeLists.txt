cmake_minimum_required(VERSION 3.8)
project(massdns)

set(CMAKE_C_STANDARD 11)

# platform checks
include(CheckIncludeFiles)

CHECK_INCLUDE_FILES("sys/epoll.h" HAVE_EPOLL)
CHECK_INCLUDE_FILES("sys/ioctl.h" HAVE_IOCTL)

if (HAVE_EPOLL)
    add_definitions(-DHAVE_EPOLL)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    if(HAVE_IOCTL)
        add_definitions(-DPCAP_SUPPORT)
    endif()
endif()

set(SOURCE_FILES src/main.c src/list.h src/hashmap.h src/massdns.h src/security.h src/net.h src/string.h src/buffers.h src/dns.h
        src/timed_ring.h src/random.h src/cmd.h src/flow.h src/auto_concurrency.h src/tcp.h)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
add_executable(massdns ${SOURCE_FILES})

install(TARGETS massdns RUNTIME DESTINATION bin)
