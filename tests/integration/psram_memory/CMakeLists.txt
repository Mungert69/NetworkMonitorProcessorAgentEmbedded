cmake_minimum_required(VERSION 3.16)
set(EXTRA_COMPONENT_DIRS
    "${CMAKE_CURRENT_LIST_DIR}/../../../firmware/managed_components/espressif__brotli")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(psram_memory_test)
include(../../../cmake/brotli-quality-zero.cmake)
nm_brotli_quality_zero(brotlienc
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../firmware/managed_components/espressif__brotli/brotli"
    "${PYTHON}")
