#ifndef NM_TEST_MBEDTLS_BASE64_H
#define NM_TEST_MBEDTLS_BASE64_H
#include <stddef.h>
int mbedtls_base64_decode(unsigned char *, size_t, size_t *, const unsigned char *, size_t);
#endif
