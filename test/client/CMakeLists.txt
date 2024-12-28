project(socks5ClientTest)

set(SOURCE_FILES 
	main.c
)
include_directories(../../include)
add_executable(socks5ClientTest ${SOURCE_FILES})
set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT socks5ClientTest)

target_link_libraries(socks5ClientTest enet)