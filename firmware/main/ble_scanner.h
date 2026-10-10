#ifndef NM_BLE_SCANNER_H
#define NM_BLE_SCANNER_H

#include "ble_decoder.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum { NM_BLE_ADDRESS_TEXT_SIZE = 18, NM_BLE_ADVERTISEMENT_MAX = 255 };

typedef struct {
    char address[NM_BLE_ADDRESS_TEXT_SIZE];
    int8_t rssi;
    uint64_t capture_id; /* Diagnostic ID assigned once at the discovery callback. */
    uint8_t data[NM_BLE_ADVERTISEMENT_MAX];
    size_t data_length;
} nm_ble_advertisement;

typedef struct {
    char address[NM_BLE_ADDRESS_TEXT_SIZE]; /* Empty means any advertiser. */
    int company;                            /* -1 means no manufacturer filter. */
    const nm_ble_decoder *decoder;          /* Borrowed immutable registry entry. */
    bool has_key;
    uint8_t key_check;
} nm_ble_filter;

/* Starts NimBLE once and keeps one passive scan active for all BLE monitors. */
bool nm_ble_scanner_start(void);

#endif
