set(HEV_ROOT ${CMAKE_CURRENT_LIST_DIR}/../third_party/hev-socks5-tunnel)
set(HEV_TASK ${HEV_ROOT}/third-part/hev-task-system)
set(HEV_LWIP ${HEV_ROOT}/third-part/lwip)

enable_language(ASM)
file(GLOB_RECURSE HEV_TASK_SOURCES CONFIGURE_DEPENDS ${HEV_TASK}/src/*.c ${HEV_TASK}/src/*.S)
# macOS globbing also matches .s; the single .S dispatcher includes the right architecture.
list(FILTER HEV_TASK_SOURCES EXCLUDE REGEX "\\.s$")
add_library(clahsos_tasks STATIC ${HEV_TASK_SOURCES})
target_include_directories(clahsos_tasks PUBLIC ${HEV_TASK}/include PRIVATE ${HEV_TASK}/src)
target_compile_definitions(clahsos_tasks PRIVATE _GNU_SOURCE ENABLE_STACK_OVERFLOW_DETECTION
    CONFIG_STACK_BACKEND=STACK_MMAP CONFIG_STACK_OVERFLOW_DETECTION=1
    CONFIG_SCHED_CLOCK=CLOCK_NONE CONFIG_MEMALLOC_SLICE_ALIGN=16
    CONFIG_MEMALLOC_SLICE_MAX_SIZE=4096 CONFIG_MEMALLOC_SLICE_MAX_COUNT=1000)

file(GLOB_RECURSE HEV_LWIP_SOURCES CONFIGURE_DEPENDS ${HEV_LWIP}/src/*.c)
add_library(clahsos_lwip STATIC ${HEV_LWIP_SOURCES})
target_include_directories(clahsos_lwip PUBLIC ${HEV_LWIP}/src/include ${HEV_LWIP}/src/ports/include)
target_compile_definitions(clahsos_lwip PUBLIC FD_SET_DEFINED SOCKLEN_T_DEFINED)

file(GLOB_RECURSE HEV_TUNNEL_SOURCES CONFIGURE_DEPENDS ${HEV_ROOT}/src/*.c)
list(FILTER HEV_TUNNEL_SOURCES EXCLUDE REGEX "/hev-tunnel-(linux|macos|windows|freebsd|netbsd)\\.c$")
add_library(clahsos_tunnel_engine STATIC ${HEV_TUNNEL_SOURCES} clahsos_tun_device.c)
target_include_directories(clahsos_tunnel_engine PUBLIC ${HEV_ROOT}/src PRIVATE ${HEV_ROOT}/src/misc ${HEV_ROOT}/src/core/include)
target_compile_definitions(clahsos_tunnel_engine PRIVATE _GNU_SOURCE ENABLE_LIBRARY CLAHSOS_TUN_FD)
target_link_libraries(clahsos_tunnel_engine PUBLIC clahsos_tasks clahsos_lwip clahsos_yaml)
if(CLAHSOS_TUN_HOST_TEST)
    # Replace only the transport socket in tests; packet processing, DNS and SOCKS remain production code.
    set_source_files_properties(${HEV_ROOT}/src/core/src/hev-socks5-client.c ${HEV_ROOT}/src/core/src/hev-socks5-client-udp.c PROPERTIES
        COMPILE_DEFINITIONS "hev_socks5_socket=clahsos_test_socket;hev_task_io_socket_connect=clahsos_test_connect")
endif()

foreach(TARGET clahsos_tasks clahsos_lwip clahsos_tunnel_engine)
    set_target_properties(${TARGET} PROPERTIES POSITION_INDEPENDENT_CODE ON C_STANDARD 11)
    target_compile_options(${TARGET} PRIVATE -fvisibility=hidden)
    if(NOT APPLE)
        target_compile_options(${TARGET} PRIVATE -fno-stack-clash-protection)
    endif()
endforeach()

if(NOT CLAHSOS_TUN_HOST_TEST)
    add_library(clahsos_tun SHARED clahsos_tun_napi.cpp clahsos_tun.cpp)
    target_compile_features(clahsos_tun PRIVATE cxx_std_17)
    target_compile_options(clahsos_tun PRIVATE -fvisibility=hidden)
    target_link_libraries(clahsos_tun PRIVATE clahsos_tunnel_engine libace_napi.z.so)
endif()
