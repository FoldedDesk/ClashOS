cmake_minimum_required(VERSION 3.5.0)
project(clash_core)

add_library(clahsos_yaml STATIC
    third_party/libyaml/api.c third_party/libyaml/reader.c
    third_party/libyaml/scanner.c third_party/libyaml/parser.c
    third_party/libyaml/loader.c third_party/libyaml/writer.c
    third_party/libyaml/emitter.c third_party/libyaml/dumper.c)
set_target_properties(clahsos_yaml PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(clahsos_yaml PUBLIC third_party/libyaml)
target_compile_definitions(clahsos_yaml PRIVATE YAML_VERSION_MAJOR=0 YAML_VERSION_MINOR=2
    YAML_VERSION_PATCH=5 YAML_VERSION_STRING="0.2.5" YAML_DECLARE_STATIC)

add_subdirectory(crypto)
add_subdirectory(third_party/zstd)
add_subdirectory(third_party/libmaxminddb)
add_subdirectory(regex)
add_subdirectory(script)

add_library(clash_core SHARED clash_core.cpp)

target_compile_features(clash_core PRIVATE cxx_std_17)
target_compile_options(clash_core PRIVATE -fvisibility=hidden)
target_link_libraries(clash_core PUBLIC libace_napi.z.so libz.so clahsos_yaml clahsos_crypto clahsos_zstd clahsos_maxminddb re2::re2 clashos_quickjs)

add_subdirectory(tun)
