cmake_minimum_required(VERSION 3.16)

# lwIP uses the upper FD range for sockets. Reserve 16 descriptors for the
# console and other VFS users in addition to 64 socket slots (IDF requires >=6).
add_compile_definitions(FD_SETSIZE=80)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(networkmonitor_processor_esp32)
if(NOT CONFIG_LIBC_PICOLIBC)
    message(FATAL_ERROR
        "Release firmware requires Picolibc. Select it in sdkconfig.production.")
endif()
if(CONFIG_LIBC_PICOLIBC_NEWLIB_COMPATIBILITY)
    message(FATAL_ERROR
        "Release firmware must not enable Picolibc Newlib compatibility in sdkconfig.production.")
endif()
# esp-mqtt's mqtt_utils.c uses intptr_t without including stdint.h. Newlib's
# transitive headers masked this. Keep the managed component untouched and
# supply the missing standard header only for that library's compilation.
if(TARGET mqtt_utils_lib)
    target_compile_options(mqtt_utils_lib PRIVATE -include stdint.h)
endif()
if(NOT CONFIG_MBEDTLS_THREADING_C OR NOT CONFIG_MBEDTLS_THREADING_PTHREAD)
    message(FATAL_ERROR
        "Concurrent crypto requires MBEDTLS_THREADING_C and MBEDTLS_THREADING_PTHREAD. Enable both in the selected sdkconfig; existing configs retain old values.")
endif()
include(../cmake/brotli-quality-zero.cmake)
nm_brotli_quality_zero(brotlienc
    "${CMAKE_CURRENT_SOURCE_DIR}/managed_components/espressif__brotli/brotli" "${PYTHON}")
