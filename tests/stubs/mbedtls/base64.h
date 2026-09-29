#ifndef NM_TEST_MBEDTLS_BASE64_H
#define NM_TEST_MBEDTLS_BASE64_H
#include <limits.h>
#include <stddef.h>
#include <openssl/evp.h>
#define MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL -0x002A
/* Real RFC 4648 encoding; mbedTLS reports required capacity including NUL
 * on short buffers, and output length excluding NUL on success. */
static inline int mbedtls_base64_encode(unsigned char *dst, size_t capacity,
    size_t *written, const unsigned char *src, size_t length)
{
    if (!length) { *written = 0; return 0; }
    if (length > (size_t)INT_MAX / 4 * 3) {
        *written = (size_t)-1;
        return MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL;
    }
    size_t required = 4 * ((length + 2) / 3) + 1;
    if (!dst || capacity < required) {
        *written = required;
        return MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL;
    }
    int result = EVP_EncodeBlock(dst, src, (int)length);
    if (result < 0) return -1;
    *written = (size_t)result;
    return 0;
}
#endif
