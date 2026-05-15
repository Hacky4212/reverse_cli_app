cmake_minimum_required(VERSION 3.16)

project(reverse_tools_native_probe LANGUAGES C)

add_executable(native_probe main.c)
set_target_properties(native_probe PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED YES)

if(MSVC)
    target_compile_options(native_probe PRIVATE /W4 /permissive-)
else()
    target_compile_options(native_probe PRIVATE -Wall -Wextra -Wpedantic)
endif()
