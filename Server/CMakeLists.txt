cmake_minimum_required(VERSION 3.10)

#set project name
project(rpiwolServer)

#add executable
add_executable(rpiwolServer "")

#add hacl
add_subdirectory(../hacl hacl)
#link to hacl
target_link_libraries(rpiwolServer PRIVATE hacl)
#include hacl headers
target_include_directories(rpiwolServer PRIVATE
	"$(PROJECT_SOURCE_DIR}"
	"../hacl"
)

#add Test sources
target_sources(rpiwolServer PRIVATE
	main.c
)

#compiler defines
target_compile_definitions(rpiwolServer PRIVATE "KRML_VERIFIED_UINT128")
