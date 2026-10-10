#include "ble_cycle.h"
#include "ble_buffer.h"
#include "ble_endpoint_policy.h"
#include "endpoint_measurement.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    assert(nm_ble_buffer_init());
    assert(nm_ble_endpoint_window_ms(0) == 70000);
    assert(nm_ble_endpoint_window_ms(9000) == 90000);
    assert(nm_endpoint_configured_timeout("blebroadcast", 0, 59000) == 0);
    assert(nm_endpoint_configured_timeout("blebroadcastlisten", 0, 59000) == 0);
    assert(nm_endpoint_configured_timeout("http", 0, 59000) == 59000);
    assert(nm_endpoint_configured_timeout("http", 1234, 59000) == 1234);

    nm_monitor_record default_window = {
        .Enabled = true, .Address = "AA:BB:CC:DD:EE:FF", .EndPointType = "blebroadcast"};
    nm_monitor_record longer_window = default_window;
    longer_window.Timeout = 9000;
    nm_monitor_record disabled = {.Enabled = false,
                                  .Address = "11:22:33:44:55:66",
                                  .EndPointType = "blebroadcast",
                                  .Timeout = 100000};
    nm_monitor_record raw = {.Enabled = true, .EndPointType = "blebroadcastlisten"};
    nm_record *items[] = {&default_window.base, &longer_window.base, &disabled.base, &raw.base};
    nm_records configured = {.items = items, .count = 4};
    assert(nm_ble_cycle_begin(&configured));
    assert(default_window.Timeout == 0 && longer_window.Timeout == 9000);
    nm_ble_advertisement packet = {
        .address = "AA:BB:CC:DD:EE:FF", .data_length = 3, .data = {2, 1, 6}};
    assert(nm_ble_buffer_receive(&packet, 0));
    strcpy(packet.address, disabled.Address);
    assert(nm_ble_buffer_receive(&packet, 0));
    assert(nm_ble_buffer_complete_cycle(150000000));
    nm_ble_snapshot *first = nm_ble_buffer_acquire();
    assert(nm_ble_snapshot_count(first) == 2);
    assert(nm_ble_buffer_complete_cycle(150000001));
    nm_ble_snapshot *next = nm_ble_buffer_acquire();
    assert(nm_ble_snapshot_count(next) == 1); /* longest window wins; disabled is unprotected */
    assert(nm_ble_snapshot_read(next, 0, &packet, NULL, NULL));
    assert(!strcmp(packet.address, default_window.Address));
    configured.count = 0;
    assert(nm_ble_cycle_begin(&configured));
    assert(nm_ble_cycle_complete());
    assert(nm_ble_cycle_complete());
    nm_ble_snapshot *empty = nm_ble_buffer_acquire();
    assert(nm_ble_snapshot_count(empty) == 0);
    assert(nm_ble_snapshot_count(first) == 2); /* eviction cannot invalidate borrowed snapshots */
    nm_ble_snapshot_release(first);
    nm_ble_snapshot_release(next);
    nm_ble_snapshot_release(empty);
    nm_ble_buffer_reset();
    assert(nm_ble_buffer_get_stats().bytes == 0);
    puts("BLE cycle coordination passed");
    return 0;
}
