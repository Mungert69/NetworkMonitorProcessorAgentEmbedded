#ifndef NM_BLE_BUFFER_H
#define NM_BLE_BUFFER_H
#include "ble_scanner.h"
#include <stdint.h>

/* Internal service: PSRAM packets and immutable reference-counted snapshots.
 * All APIs synchronize internally. Caller owns acquired snapshots and must
 * release them on every path. Read copies one packet; no mutable bytes escape.
 * No capacity caps: allocation failure preserves history and marks a gap. */
typedef struct nm_ble_snapshot nm_ble_snapshot;
bool nm_ble_buffer_init(void);
void nm_ble_buffer_set_available(bool available);
bool nm_ble_buffer_available(void);
void nm_ble_buffer_rules_begin(void);
bool nm_ble_buffer_protect(const char *address, uint64_t window_ms);
/* Success includes an identical same-address repeat suppressed within 1000 ms
 * of the last retained reception. Changed bytes always pass. */
bool nm_ble_buffer_receive(const nm_ble_advertisement *packet, int64_t received_us);
bool nm_ble_buffer_complete_cycle(int64_t now_us);
nm_ble_snapshot *nm_ble_buffer_acquire(void);
void nm_ble_snapshot_release(nm_ble_snapshot *snapshot);
size_t nm_ble_snapshot_count(const nm_ble_snapshot *snapshot);
int64_t nm_ble_snapshot_time(const nm_ble_snapshot *snapshot);
uint64_t nm_ble_snapshot_previous(const nm_ble_snapshot *snapshot);
bool nm_ble_snapshot_incomplete(const nm_ble_snapshot *snapshot);
bool nm_ble_snapshot_read(const nm_ble_snapshot *snapshot, size_t index, nm_ble_advertisement *out,
                          int64_t *received_us, uint64_t *sequence);
typedef struct {
    size_t bytes, packets, snapshots;
    uint64_t dropped;
    size_t payloads; /* Unique stored payload allocations; packets counts receptions. */
} nm_ble_buffer_stats;
nm_ble_buffer_stats nm_ble_buffer_get_stats(void);
/* Reset is for shutdown/tests only; outstanding snapshots remain valid. */
void nm_ble_buffer_reset(void);
int64_t nm_ble_buffer_now_us(void);
#endif
