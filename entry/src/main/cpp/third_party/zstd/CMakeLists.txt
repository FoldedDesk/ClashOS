add_library(clahsos_zstd STATIC
    lib/common/debug.c lib/common/entropy_common.c lib/common/error_private.c
    lib/common/fse_decompress.c lib/common/xxhash.c lib/common/zstd_common.c
    lib/decompress/huf_decompress.c lib/decompress/zstd_ddict.c
    lib/decompress/zstd_decompress.c lib/decompress/zstd_decompress_block.c)
set_target_properties(clahsos_zstd PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(clahsos_zstd PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/lib)
target_compile_definitions(clahsos_zstd PRIVATE ZSTD_DISABLE_ASM ZSTD_LEGACY_SUPPORT=0)
