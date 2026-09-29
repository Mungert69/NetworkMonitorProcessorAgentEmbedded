#ifndef NM_BLE_FILTER_H
#define NM_BLE_FILTER_H

#include "ble_scanner.h"
#include <string.h>

/* Pure, bounded AD parser shared by the NimBLE callback and host tests. */
static inline bool nm_ble_ad_field(const uint8_t *data, size_t length, uint8_t type,
                                   int company, const uint8_t **value, size_t *value_length)
{
    if (!data || !value || !value_length) return false;
    for (size_t offset = 0; offset < length;) {
        size_t field = data[offset];
        if (!field || field > length - offset - 1) return false;
        if (data[offset + 1] == type &&
            (company < 0 || (field >= 3 && data[offset + 2] == (uint8_t)company &&
                              data[offset + 3] == (uint8_t)(company >> 8)))) {
            *value = data + offset + 2;
            *value_length = field - 1;
            return true;
        }
        offset += field + 1;
    }
    return false;
}

static inline bool nm_ble_advertisement_matches(const nm_ble_advertisement *item,
                                                  const nm_ble_filter *filter)
{
    if (!item || !filter || !item->data_length ||
        item->data_length > NM_BLE_ADVERTISEMENT_MAX) return false;
    if (filter->address[0] && strcmp(item->address, filter->address)) return false;
    if (filter->company < 0 && !filter->victron_instant) return true;
    const uint8_t *value = NULL;
    size_t length = 0;
    if (!nm_ble_ad_field(item->data, item->data_length, 0xff,
                         filter->victron_instant ? 0x02e1 : filter->company,
                         &value, &length)) return false;
    if (!filter->victron_instant) return true;
    if (length < 6 || value[0] != 0xe1 || value[1] != 0x02) return false;
    value += 2;
    length -= 2;
    size_t offset = value[0] == 0x10 ? 4 : 0;
    return length >= offset + 5 && value[offset] == 0x01 &&
           value[offset + 3] == filter->key_check &&
           length - offset - 4 <= 16;
}
#endif
