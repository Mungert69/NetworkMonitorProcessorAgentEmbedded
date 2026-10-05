#include "ble_crypto.h"
#include "psa/crypto.h"
bool nm_ble_aes_block(const uint8_t *key, size_t n, const uint8_t in[16], uint8_t out[16])
{
    if (!key || (n != 16 && n != 24 && n != 32))
        return false;
    psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&a, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&a, n * 8);
    psa_set_key_usage_flags(&a, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&a, PSA_ALG_ECB_NO_PADDING);
    mbedtls_svc_key_id_t handle = PSA_KEY_ID_NULL;
    size_t used = 0;
    psa_status_t status = psa_import_key(&a, key, n, &handle);
    psa_reset_key_attributes(&a);
    if (status == PSA_SUCCESS)
        status = psa_cipher_encrypt(handle, PSA_ALG_ECB_NO_PADDING, in, 16, out, 16, &used);
    if (handle != PSA_KEY_ID_NULL)
        psa_destroy_key(handle);
    return status == PSA_SUCCESS && used == 16;
}
bool nm_ble_ccm_decrypt(const uint8_t key[16], const uint8_t nonce[13], nm_ble_bytes in,
                        uint8_t *out, size_t capacity)
{
    psa_algorithm_t alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 4);
    psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&a, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&a, 128);
    psa_set_key_usage_flags(&a, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&a, alg);
    mbedtls_svc_key_id_t handle = PSA_KEY_ID_NULL;
    size_t used = 0;
    psa_status_t status = psa_import_key(&a, key, 16, &handle);
    psa_reset_key_attributes(&a);
    if (status == PSA_SUCCESS)
        status = psa_aead_decrypt(handle, alg, nonce, 13, NULL, 0, in.bytes, in.length, out,
                                  capacity, &used);
    if (handle != PSA_KEY_ID_NULL)
        psa_destroy_key(handle);
    return in.length >= 4 && status == PSA_SUCCESS && used == in.length - 4;
}
