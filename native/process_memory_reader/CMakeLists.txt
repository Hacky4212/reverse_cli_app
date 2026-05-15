cmake_minimum_required(VERSION 3.16)

project(reverse_tools_process_memory_reader LANGUAGES C)

add_executable(process_memory_reader main.c)
set_target_properties(process_memory_reader PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED YES)

if(MSVC)
    target_compile_options(process_memory_reader PRIVATE /W4)
else()
    target_compile_options(process_memory_reader PRIVATE -Wall -Wextra -Wpedantic)
endif()
