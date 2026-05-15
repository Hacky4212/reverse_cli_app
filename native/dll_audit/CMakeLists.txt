cmake_minimum_required(VERSION 3.16)

project(reverse_tools_dll_audit LANGUAGES C)

add_executable(dll_audit main.c)
set_target_properties(dll_audit PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED YES)

if(MSVC)
    target_compile_options(dll_audit PRIVATE /W4 /permissive-)
else()
    target_compile_options(dll_audit PRIVATE -Wall -Wextra -Wpedantic)
endif()
