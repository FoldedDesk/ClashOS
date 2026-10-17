cmake_minimum_required(VERSION 3.16)
# Fixed upstream 1.14.1 sources; build only the reader, without tools or install rules.
set(MMDB_UINT128_USING_MODE 0)
set(MMDB_UINT128_IS_BYTE_ARRAY 1)
configure_file(include/maxminddb_config.h.cmake.in generated/maxminddb_config.h)
add_library(clahsos_maxminddb STATIC src/maxminddb.c src/data-pool.c)
set_target_properties(clahsos_maxminddb PROPERTIES POSITION_INDEPENDENT_CODE ON C_STANDARD 99)
target_include_directories(clahsos_maxminddb PUBLIC include ${CMAKE_CURRENT_BINARY_DIR}/generated)
target_compile_definitions(clahsos_maxminddb PRIVATE PACKAGE_VERSION="1.14.1" MMDB_LITTLE_ENDIAN=1)
