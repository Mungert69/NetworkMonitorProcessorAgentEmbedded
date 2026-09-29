#ifndef NM_TEST_MBEDTLS_AES_H
#define NM_TEST_MBEDTLS_AES_H
#include <stddef.h>
#include <stdint.h>
#define MBEDTLS_AES_ENCRYPT 1
typedef struct { uint8_t key[32]; unsigned bits; } mbedtls_aes_context;
void mbedtls_aes_init(mbedtls_aes_context *);
int mbedtls_aes_setkey_enc(mbedtls_aes_context *, const unsigned char *, unsigned);
int mbedtls_aes_crypt_ecb(mbedtls_aes_context *, int, const unsigned char[16], unsigned char[16]);
void mbedtls_aes_free(mbedtls_aes_context *);
#endif
