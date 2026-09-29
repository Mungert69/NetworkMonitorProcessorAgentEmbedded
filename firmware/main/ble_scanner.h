#ifndef NM_BLE_SCANNER_H
#define NM_BLE_SCANNER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum { NM_BLE_ADDRESS_TEXT_SIZE = 18, NM_BLE_ADVERTISEMENT_MAX = 255 };

typedef struct {
    char address[NM_BLE_ADDRESS_TEXT_SIZE];
    int8_t rssi;
    uint8_t data[NM_BLE_ADVERTISEMENT_MAX];
    size_t data_length;
} nm_ble_advertisement;

typedef struct {
    char address[NM_BLE_ADDRESS_TEXT_SIZE]; /* Empty means any advertiser. */
    int company; /* -1 means no manufacturer filter. */
    bool victron_instant;
    uint8_t key_check;
} nm_ble_filter;

typedef enum {
    NM_BLE_WAIT_FOUND,
    NM_BLE_WAIT_TIMEOUT,
    NM_BLE_WAIT_UNAVAILABLE,
    NM_BLE_WAIT_CAPACITY
} nm_ble_wait_result;

/* Starts NimBLE once and keeps one passive scan active for all BLE monitors. */
bool nm_ble_scanner_start(void);

/* Wait for an advertisement from this address. Each concurrent caller gets
 * its own bounded waiter; the scanner itself is shared. */
nm_ble_wait_result nm_ble_scanner_wait(const nm_ble_filter *filter, unsigned timeout_ms,
                                       nm_ble_advertisement *advertisement);

#endif
