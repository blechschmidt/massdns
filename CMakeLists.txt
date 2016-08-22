cmake_minimum_required(VERSION 3.2)
project(massdns)

link_directories(/usr/lib)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c11")

set(SOURCE_FILES main.c
        buffers.h
        hashmap.h
        list.h
        security.h
        string.h)

link_libraries(libldns.so)

set(LDNS_DIR /usr/include/ldns)

set(LDNS_FILES
        ${LDNS_DIR}/host2str.h
        ${LDNS_DIR}/host2wire.h
        ${LDNS_DIR}/wire2host.h
        ${LDNS_DIR}/dnssec.h)

set (CMAKE_RUNTIME_OUTPUT_DIRECTORY bin)

add_executable(massdns ${SOURCE_FILES} ${LDNS_FILES})
