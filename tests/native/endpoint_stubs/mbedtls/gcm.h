#ifndef NM_TEST_MBEDTLS_GCM_H
#define NM_TEST_MBEDTLS_GCM_H
#include <stddef.h>
#include <stdint.h>
#define MBEDTLS_CIPHER_ID_AES 1
typedef struct { uint8_t key[32]; unsigned bits; } mbedtls_gcm_context;
void mbedtls_gcm_init(mbedtls_gcm_context *);
int mbedtls_gcm_setkey(mbedtls_gcm_context *, int, const unsigned char *, unsigned);
int mbedtls_gcm_auth_decrypt(mbedtls_gcm_context *, size_t, const unsigned char *, size_t,
                             const unsigned char *, size_t, const unsigned char *, size_t,
                             const unsigned char *, unsigned char *);
void mbedtls_gcm_free(mbedtls_gcm_context *);
#endif
