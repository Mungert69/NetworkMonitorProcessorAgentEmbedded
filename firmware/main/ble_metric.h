#ifndef NM_BLE_METRIC_H
#define NM_BLE_METRIC_H
#include "ble_decoder.h"
typedef struct {
    const char *format, *metric, *unit;
    double scale, offset, minimum, maximum;
} nm_ble_metric_encoding;
/* All descriptors are borrowed immutable data, generated from the .NET v2 catalogue. */
const nm_ble_metric_encoding *nm_ble_metric_find(const char *format, const char *metric);
bool nm_ble_metric_encode(const nm_ble_metric_encoding *encoding, double value, uint16_t *sample);
const char *nm_ble_metric_canonical(const char *metric);
#endif
