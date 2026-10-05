#include "ble_crypto.h"
#ifndef NM_BLE_DECODER_INTERNAL_H
#define NM_BLE_DECODER_INTERNAL_H
#include "ble_decoder.h"
const char *nm_ble_aes128_key_error(size_t length);
const char *nm_ble_no_key_error(size_t length);
extern const nm_ble_decoder nm_ble_victron_decoder;
extern const nm_ble_decoder nm_ble_ruuvi_decoder;
extern const nm_ble_decoder nm_ble_bthome_decoder;
bool nm_ble_victron_record_supported(uint8_t type);
bool nm_ble_victron_record_decode(uint8_t type, nm_ble_bytes plain, nm_ble_output *output);
#endif
