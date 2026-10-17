cmake_minimum_required(VERSION 3.5.0)
set(QUICKJS_ROOT "${CMAKE_CURRENT_LIST_DIR}/../third_party/quickjs")
add_library(clashos_quickjs STATIC
    ${QUICKJS_ROOT}/quickjs.c ${QUICKJS_ROOT}/dtoa.c
    ${QUICKJS_ROOT}/libregexp.c ${QUICKJS_ROOT}/libunicode.c ${QUICKJS_ROOT}/cutils.c)
set_target_properties(clashos_quickjs PROPERTIES POSITION_INDEPENDENT_CODE ON C_STANDARD 11)
target_include_directories(clashos_quickjs PRIVATE ${QUICKJS_ROOT})
target_compile_definitions(clashos_quickjs PRIVATE _GNU_SOURCE CONFIG_VERSION="2026-06-04")
target_compile_options(clashos_quickjs PRIVATE -fwrapv -fno-strict-aliasing -fvisibility=hidden)
target_link_libraries(clashos_quickjs PUBLIC m)
