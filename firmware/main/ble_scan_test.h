#ifndef NM_BLE_SCAN_TEST_H
#define NM_BLE_SCAN_TEST_H

#include <stdbool.h>

/* Start the optional NimBLE passive-advertising coexistence test. In normal
 * firmware builds, where NimBLE is disabled, this is an inexpensive no-op. */
bool nm_ble_scan_test_start(void);

#endif
