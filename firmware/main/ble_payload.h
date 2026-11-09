#ifndef NM_BLE_PAYLOAD_H
#define NM_BLE_PAYLOAD_H
#include "ble_scanner.h"
/* Synchronous shared parsers and crypto. Inputs are borrowed; caller owns output.
 * Selected spans borrow advertisement bytes; decrypted spans borrow output (raw
 * spans borrow input). On failure output must not be consumed. Key capacity 32. */
bool nm_ble_payload_normalize_address(const char *input, char out[NM_BLE_ADDRESS_TEXT_SIZE]);
bool nm_ble_payload_parse_key(const char *text, uint8_t *key, size_t *key_length);
bool nm_ble_payload_parse_hex_payload(const char *text, uint8_t out[NM_BLE_ADVERTISEMENT_MAX],
                                      size_t *length);
bool nm_ble_payload_parse_service_uuid(const char *text, uint8_t out[16], size_t *length);
nm_ble_bytes nm_ble_payload_advertisement_payload(const nm_ble_advertisement *advertisement,
                                                  const char **payload_type, int company,
                                                  const char *mode, const uint8_t *service_uuid,
                                                  size_t service_uuid_length);
bool nm_ble_payload_decrypt_payload(const char *format, nm_ble_bytes payload, const uint8_t *key,
                                    size_t key_length, unsigned nonce_len, unsigned tag_len,
                                    bool nonce_at_end, uint8_t output[NM_BLE_ADVERTISEMENT_MAX],
                                    nm_ble_bytes *plaintext);
#endif
