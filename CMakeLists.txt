cmake_minimum_required(VERSION 3.10)

#set project name
project(interwake)

add_subdirectory(hacl hacl)

#add executables
add_executable(interwake interwake.c)
add_executable(interwaked interwaked.c)

target_link_libraries(interwake PRIVATE hacl)
target_link_libraries(interwaked PRIVATE hacl)

include_directories(hacl)
add_compile_definitions("KRML_VERIFIED_UINT128")
