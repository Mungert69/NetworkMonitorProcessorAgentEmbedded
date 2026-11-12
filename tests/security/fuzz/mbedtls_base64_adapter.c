#include "mbedtls/base64.h"
#include <limits.h>
#include <openssl/evp.h>

int mbedtls_base64_encode(unsigned char *dst, size_t dlen, size_t *olen,
                          const unsigned char *src, size_t slen)
{
    if (!dst || !olen || !src || slen > INT_MAX || dlen > INT_MAX)
        return -1;
    int written = EVP_EncodeBlock(dst, src, (int)slen);
    if (written < 0 || (size_t)written > dlen)
        return -1;
    *olen = (size_t)written;
    return 0;
}
