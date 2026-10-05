#include "psa/crypto.h"
#include <openssl/evp.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
typedef struct {
    uint8_t key[32];
    size_t length;
    uint32_t usage, alg;
} test_key;
static test_key imported_key;

void psa_set_key_type(psa_key_attributes_t *a, uint32_t value)
{
    a->type = value;
}
void psa_set_key_bits(psa_key_attributes_t *a, uint32_t value)
{
    a->bits = value;
}
void psa_set_key_usage_flags(psa_key_attributes_t *a, uint32_t value)
{
    a->usage = value;
}
void psa_set_key_algorithm(psa_key_attributes_t *a, uint32_t value)
{
    a->alg = value;
}
void psa_reset_key_attributes(psa_key_attributes_t *a)
{
    memset(a, 0, sizeof(*a));
}
psa_status_t psa_import_key(const psa_key_attributes_t *a, const uint8_t *key, size_t length,
                            mbedtls_svc_key_id_t *handle)
{
    if (!a || !key || !handle || a->type != PSA_KEY_TYPE_AES ||
        (length != 16 && length != 24 && length != 32) || a->bits != length * 8)
        return -1;
    memcpy(imported_key.key, key, length);
    imported_key.length = length;
    imported_key.usage = a->usage;
    imported_key.alg = a->alg;
    *handle = 1;
    return PSA_SUCCESS;
}
psa_status_t psa_cipher_encrypt(mbedtls_svc_key_id_t handle, uint32_t alg, const uint8_t *input,
                                size_t input_length, uint8_t *output, size_t output_size,
                                size_t *output_length)
{
    if (handle != 1 || alg != PSA_ALG_ECB_NO_PADDING || !input || !output || !output_length ||
        input_length != 16 || output_size < 16 || imported_key.usage != PSA_KEY_USAGE_ENCRYPT)
        return -1;
    const EVP_CIPHER *cipher = imported_key.length == 16   ? EVP_aes_128_ecb()
                               : imported_key.length == 24 ? EVP_aes_192_ecb()
                                                           : EVP_aes_256_ecb();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;
    int used = 0, final = 0;
    bool ok = EVP_EncryptInit_ex(ctx, cipher, NULL, imported_key.key, NULL) == 1 &&
              EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
              EVP_EncryptUpdate(ctx, output, &used, input, 16) == 1 &&
              EVP_EncryptFinal_ex(ctx, output + used, &final) == 1 && used + final == 16;
    EVP_CIPHER_CTX_free(ctx);
    if (ok)
        *output_length = (size_t)(used + final);
    return ok ? PSA_SUCCESS : -1;
}
psa_status_t psa_aead_decrypt(mbedtls_svc_key_id_t handle, uint32_t alg, const uint8_t *nonce,
                              size_t nonce_length, const uint8_t *aad, size_t aad_length,
                              const uint8_t *input, size_t input_length, uint8_t *output,
                              size_t output_size, size_t *output_length)
{
    (void)aad;
    size_t tag_length = alg >> 8;
    if (handle != 1 || ((alg & 255) != PSA_ALG_GCM && (alg & 255) != PSA_ALG_CCM) ||
        alg != imported_key.alg ||
        ((alg & 255) == PSA_ALG_GCM ? (tag_length < 12 || tag_length > 16) : tag_length != 4) ||
        !nonce || !input || !output || !output_length || input_length < tag_length ||
        input_length > INT_MAX || nonce_length > INT_MAX ||
        output_size < input_length - tag_length || imported_key.usage != PSA_KEY_USAGE_DECRYPT)
        return -1;
    if ((alg & 255) == PSA_ALG_CCM) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
            return -1;
        int used = 0;
        size_t length = input_length - tag_length;
        bool ok =
            EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, (int)nonce_length, NULL) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 4, (void *)(input + length)) == 1 &&
            EVP_DecryptInit_ex(ctx, NULL, NULL, imported_key.key, nonce) == 1 &&
            EVP_DecryptUpdate(ctx, NULL, &used, NULL, (int)length) == 1 &&
            (!aad_length || EVP_DecryptUpdate(ctx, NULL, &used, aad, (int)aad_length) == 1) &&
            EVP_DecryptUpdate(ctx, output, &used, input, (int)length) == 1;
        EVP_CIPHER_CTX_free(ctx);
        if (ok)
            *output_length = (size_t)used;
        return ok ? PSA_SUCCESS : -1;
    }
    const EVP_CIPHER *cipher = imported_key.length == 16   ? EVP_aes_128_gcm()
                               : imported_key.length == 24 ? EVP_aes_192_gcm()
                                                           : EVP_aes_256_gcm();
    size_t ciphertext_length = input_length - tag_length;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;
    int written = 0, final = 0;
    bool ok = EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_length, NULL) == 1 &&
              EVP_DecryptInit_ex(ctx, NULL, NULL, imported_key.key, nonce) == 1 &&
              (!aad_length || EVP_DecryptUpdate(ctx, NULL, &written, aad, (int)aad_length) == 1) &&
              EVP_DecryptUpdate(ctx, output, &written, input, (int)ciphertext_length) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_length,
                                  (void *)(input + ciphertext_length)) == 1 &&
              EVP_DecryptFinal_ex(ctx, output + written, &final) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (ok)
        *output_length = (size_t)(written + final);
    return ok ? PSA_SUCCESS : -1;
}
psa_status_t psa_destroy_key(mbedtls_svc_key_id_t handle)
{
    if (handle != 1)
        return -1;
    memset(&imported_key, 0, sizeof(imported_key));
    return PSA_SUCCESS;
}
