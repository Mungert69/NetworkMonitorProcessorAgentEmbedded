#ifndef NM_TEST_PSA_CRYPTO_H
#define NM_TEST_PSA_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

typedef uint32_t mbedtls_svc_key_id_t;
typedef int32_t psa_status_t;
typedef uint32_t psa_algorithm_t;
typedef struct {
    uint32_t type;
    uint32_t bits;
    uint32_t usage;
    uint32_t alg;
} psa_key_attributes_t;

#define PSA_KEY_ATTRIBUTES_INIT ((psa_key_attributes_t){0})
#define PSA_KEY_ID_NULL ((mbedtls_svc_key_id_t)0)
#define PSA_KEY_TYPE_AES 1
#define PSA_KEY_USAGE_ENCRYPT 1
#define PSA_KEY_USAGE_DECRYPT 2
#define PSA_ALG_ECB_NO_PADDING 1
#define PSA_ALG_GCM 2
#define PSA_ALG_CCM 3
#define PSA_ALG_AEAD_WITH_SHORTENED_TAG(alg, length) ((alg) | ((length) << 8))
#define PSA_SUCCESS 0

void psa_set_key_type(psa_key_attributes_t *, uint32_t);
void psa_set_key_bits(psa_key_attributes_t *, uint32_t);
void psa_set_key_usage_flags(psa_key_attributes_t *, uint32_t);
void psa_set_key_algorithm(psa_key_attributes_t *, uint32_t);
void psa_reset_key_attributes(psa_key_attributes_t *);
psa_status_t psa_import_key(const psa_key_attributes_t *, const uint8_t *, size_t,
                            mbedtls_svc_key_id_t *);
psa_status_t psa_cipher_encrypt(mbedtls_svc_key_id_t, uint32_t, const uint8_t *, size_t,
                                uint8_t *, size_t, size_t *);
psa_status_t psa_aead_decrypt(mbedtls_svc_key_id_t, uint32_t, const uint8_t *, size_t,
                              const uint8_t *, size_t, const uint8_t *, size_t,
                              uint8_t *, size_t, size_t *);
psa_status_t psa_destroy_key(mbedtls_svc_key_id_t);

#endif
