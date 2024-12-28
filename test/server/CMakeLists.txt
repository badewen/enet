project(serverTest)

set(SOURCE_FILES 
	main.c
)
include_directories(../../include)
add_executable(serverTest ${SOURCE_FILES})

target_link_libraries(serverTest enet)