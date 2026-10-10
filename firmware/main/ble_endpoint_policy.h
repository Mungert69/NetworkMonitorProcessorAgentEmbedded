#ifndef NM_BLE_ENDPOINT_POLICY_H
#define NM_BLE_ENDPOINT_POLICY_H
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* BLE-owned defaults. Configured values remain unchanged in monitor records.
 * Borrowed type; no allocation. Raw listen consumes one cycle, not a window. */
enum { NM_BLE_DEFAULT_TIMEOUT_MS = 7000, NM_BLE_WINDOW_MULTIPLIER = 10 };
static inline bool nm_ble_endpoint_supported(const char *type)
{
    return type && (!strcmp(type, "blebroadcast") || !strcmp(type, "blebroadcastlisten"));
}
static inline uint64_t nm_ble_endpoint_window_ms(int32_t configured_timeout)
{
    uint64_t base =
        configured_timeout > 0 ? (uint64_t)configured_timeout : NM_BLE_DEFAULT_TIMEOUT_MS;
    return base * NM_BLE_WINDOW_MULTIPLIER;
}
#endif
