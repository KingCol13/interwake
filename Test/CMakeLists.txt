cmake_minimum_required(VERSION 3.10)

#set project name
project(Test)

#add executable
add_executable(Test "")

#add hacl
add_subdirectory(../hacl hacl)
#link to hacl
target_link_libraries(Test PRIVATE hacl)
#include hacl headers
target_include_directories(Test PRIVATE
	"$(PROJECT_SOURCE_DIR}"
	"../hacl"
)

#add Test sources
target_sources(Test PRIVATE
	main.c
	crypt.h
	host2ip.h
)

#compiler defines
target_compile_definitions(Test PRIVATE "KRML_VERIFIED_UINT128")
