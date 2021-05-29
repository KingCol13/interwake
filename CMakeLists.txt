cmake_minimum_required(VERSION 3.10)

#set project name
project(interwake)

#add executables
add_executable(interwake interwake.c)
add_executable(interwaked interwaked.c)

#link libsodium
target_link_libraries(interwake PRIVATE sodium)
target_link_libraries(interwaked PRIVATE sodium)

#install instructions
install(TARGETS interwake DESTINATION bin)
install(TARGETS interwaked DESTINATION sbin)
#don't overwrite the config
