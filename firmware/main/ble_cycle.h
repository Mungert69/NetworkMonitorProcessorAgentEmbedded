#ifndef NM_BLE_CYCLE_H
#define NM_BLE_CYCLE_H
#include "monitor_model.h"

/* Processor-task coordinator. Borrows configured records only during begin;
 * the buffer copies address/window requirements. Includes skipped monitors.
 * Complete runs only after all accepted probe jobs drain. Published immutable
 * snapshots are acquired/released by BLE endpoints, never owned by the model. */
bool nm_ble_cycle_begin(const nm_records *configured);
bool nm_ble_cycle_complete(void);
#endif
