get_filename_component(ROOT "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
set(WOLF "${ROOT}/third_party/wolfssl")
if(NOT EXISTS "${WOLF}/wolfssl/ssl.h")
    message(FATAL_ERROR "Initialize the pinned wolfSSL submodule before building.")
endif()
set(SOURCES)
foreach(NAME hmac hash cpuid kdf random sha256 rsa sp_int aes sha sha512 sha3
        logging wc_port error wc_encrypt signature wolfmath memory asn coding
        ecc curve25519 fe_operations fe_low_mem ge_operations wc_mldsa wc_mlkem wc_mlkem_poly)
    list(APPEND SOURCES "${WOLF}/wolfcrypt/src/${NAME}.c")
endforeach()
foreach(NAME internal wolfio keys ssl tls tls13)
    list(APPEND SOURCES "${WOLF}/src/${NAME}.c")
endforeach()
idf_component_register(SRCS ${SOURCES}
    INCLUDE_DIRS "${WOLF}" "${CMAKE_CURRENT_LIST_DIR}/include" "${ROOT}/firmware/main"
    REQUIRES esp_hw_support esp_psram pthread lwip)
target_compile_definitions(${COMPONENT_LIB} PUBLIC WOLFSSL_USER_SETTINGS)
# Retain upstream's visible constant-time advisory; never patch vendor code.
target_compile_options(${COMPONENT_LIB} PUBLIC -Wno-error=cpp)
# ML-DSA's upstream Montgomery reduction deliberately uses modulo-2^32 signed
# multiplication. Define that arithmetic for the optimizer; do not patch vendor code.
target_compile_options(${COMPONENT_LIB} PRIVATE -fwrapv)
