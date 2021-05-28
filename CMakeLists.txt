cmake_minimum_required(VERSION 3.10)

#set project name
project(interwake)

#add executables
add_executable(interwake interwake.c)
add_executable(interwaked interwaked.c)

target_link_libraries(interwake PRIVATE sodium)
target_link_libraries(interwaked PRIVATE sodium)
