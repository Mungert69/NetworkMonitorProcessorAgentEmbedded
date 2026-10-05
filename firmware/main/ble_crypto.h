#ifndef NM_BLE_CRYPTO_H
#define NM_BLE_CRYPTO_H
#include "ble_decoder.h"
/* Borrowed input/key, caller-owned output. No retained PSA key handles. CCM
 * returns true only after verifying the four-byte authentication tag. */
bool nm_ble_aes_block(const uint8_t *key, size_t key_length, const uint8_t input[16],
                      uint8_t output[16]);
bool nm_ble_ccm_decrypt(const uint8_t key[16], const uint8_t nonce[13], nm_ble_bytes ciphertext_tag,
                        uint8_t *output, size_t capacity);
#endif
