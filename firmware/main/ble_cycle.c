#include "ble_cycle.h"
#include "ble_buffer.h"
#include "ble_endpoint_policy.h"

bool nm_ble_cycle_begin(const nm_records *configured)
{
    nm_ble_buffer_rules_begin();
    bool ok = true;
    for (size_t i = 0; i < configured->count; ++i) {
        const nm_monitor_record *info = (const nm_monitor_record *)configured->items[i];
        if (info->Enabled && info->EndPointType && !strcmp(info->EndPointType, "blebroadcast")) {
            if (!nm_ble_buffer_protect(info->Address, nm_ble_endpoint_window_ms(info->Timeout)))
                ok = false;
        }
    }
    return ok;
}

bool nm_ble_cycle_complete(void)
{
    return nm_ble_buffer_complete_cycle(nm_ble_buffer_now_us());
}
