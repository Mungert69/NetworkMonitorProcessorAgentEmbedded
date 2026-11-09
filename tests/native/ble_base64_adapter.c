#include <stddef.h>
#include <openssl/evp.h>
int mbedtls_base64_decode(unsigned char *out, size_t capacity, size_t *used,
                          const unsigned char *input, size_t length)
{
    if (length % 4 || length / 4 * 3 > capacity)
        return -1;
    int decoded = EVP_DecodeBlock(out, input, (int)length);
    if (decoded < 0)
        return -1;
    while (length && input[length - 1] == '=') {
        --length;
        --decoded;
    }
    *used = (size_t)decoded;
    return 0;
}
