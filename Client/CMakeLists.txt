cmake_minimum_required(VERSION 3.10)

#set project name
project(rpiwolClient)

#add executable
add_executable(rpiwolClient "")

#add hacl
add_subdirectory(../hacl hacl)
#link to hacl
target_link_libraries(rpiwolClient PRIVATE hacl)
#include hacl headers
target_include_directories(rpiwolClient PRIVATE
	"$(PROJECT_SOURCE_DIR}"
	"../hacl"
)

#add Test sources
target_sources(rpiwolClient PRIVATE
	main.c
)

#compiler defines
target_compile_definitions(rpiwolClient PRIVATE "KRML_VERIFIED_UINT128")
