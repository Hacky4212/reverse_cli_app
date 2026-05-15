cmake_minimum_required(VERSION 3.16)

project(reverse_tools_perf_scan LANGUAGES CXX)

add_executable(perf_scan main.cpp)
set_target_properties(perf_scan PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)

if(MSVC)
    target_compile_options(perf_scan PRIVATE /W4 /permissive-)
else()
    target_compile_options(perf_scan PRIVATE -Wall -Wextra -Wpedantic -O2)
endif()
