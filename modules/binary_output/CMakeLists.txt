cmake_minimum_required(VERSION 3.2)
project(massdns_binary_output)

link_directories(/usr/lib)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c11")

link_libraries(libldns.so)

set(LDNS_DIR /usr/include/ldns)

set(LDNS_FILES
        ${LDNS_DIR}/packet.h)

set(SOURCE_FILES main.c)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ../../bin)

add_library(mod_binary_output SHARED ${SOURCE_FILES} ${LDNS_FILES})