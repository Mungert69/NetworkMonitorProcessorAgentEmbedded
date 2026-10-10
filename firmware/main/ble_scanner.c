#include "ble_scanner.h"
#include "ble_filter.h"
#include "ble_buffer.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#if defined(CONFIG_BT_NIMBLE_ENABLED) && CONFIG_BT_NIMBLE_ENABLED
#include "host/ble_gap.h"
#include "host/ble_hs.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include <ctype.h>
#include <stdio.h>
#include <string.h>

static const char *TAG = "nm_ble_scanner";
enum { BLE_READY_BIT = 1U, BLE_FAILED_BIT = 2U };

static EventGroupHandle_t scanner_events;
static uint8_t own_address_type;
static int64_t next_advertisement_log_us;
/* NimBLE host task is the sole writer of these callback diagnostics. */
static uint64_t callback_arrivals, callback_accepted, callback_failed;
static void address_text(const ble_addr_t *address, char out[NM_BLE_ADDRESS_TEXT_SIZE])
{
    /* NimBLE stores address bytes in host order (least significant first). */
    snprintf(out, NM_BLE_ADDRESS_TEXT_SIZE, "%02X:%02X:%02X:%02X:%02X:%02X", address->val[5],
             address->val[4], address->val[3], address->val[2], address->val[1], address->val[0]);
}

static int scan_event(struct ble_gap_event *event, void *argument)
{
    (void)argument;
    if (event->type == BLE_GAP_EVENT_DISC) {
        const struct ble_gap_disc_desc *found = &event->disc;
        /* NimBLE's length_data is uint8_t, so it cannot exceed our 255-byte buffer. */
        if (found->length_data && !found->data)
            return 0;

        nm_ble_advertisement item = {.rssi = found->rssi, .data_length = found->length_data};
        address_text(&found->addr, item.address);
        if (item.data_length)
            memcpy(item.data, found->data, item.data_length);

        int64_t now_us = esp_timer_get_time();
        item.capture_id = ++callback_arrivals;
        bool accepted = nm_ble_buffer_receive(&item, now_us);
        if (accepted)
            ++callback_accepted;
        else
            ++callback_failed;
        if (now_us >= next_advertisement_log_us) {
            /* Keep general discovery diagnostics bounded in busy RF areas. */
            next_advertisement_log_us = now_us + 10000000;
            ESP_LOGD(TAG,
                     "callback_totals arrivals=%llu accepted=%llu failed=%llu "
                     "last_capture_id=%llu arrival_us=%lld",
                     (unsigned long long)callback_arrivals, (unsigned long long)callback_accepted,
                     (unsigned long long)callback_failed, (unsigned long long)item.capture_id,
                     (long long)now_us);
        }

        return 0;
    }

    if (event->type == BLE_GAP_EVENT_DISC_COMPLETE) {
        /* An unexpected completion should not permanently disable BLE probes. */
        const struct ble_gap_disc_params parameters = {
            .filter_duplicates = 0,
            .passive = 1,
            /* Diagnostic trial: 50 ms listening every 100 ms (50% duty). */
            .itvl = 0x00A0,
            .window = 0x0050,
        };
        int error = ble_gap_disc(own_address_type, BLE_HS_FOREVER, &parameters, scan_event, NULL);
        if (error == 0 || error == BLE_HS_EALREADY) {
            xEventGroupSetBits(scanner_events, BLE_READY_BIT);
            nm_ble_buffer_set_available(true);
        } else {
            ESP_LOGE(TAG, "could not restart passive discovery: %d", error);
            xEventGroupClearBits(scanner_events, BLE_READY_BIT);
            xEventGroupSetBits(scanner_events, BLE_FAILED_BIT);
            nm_ble_buffer_set_available(false);
        }
    }
    return 0;
}

static void start_discovery(void)
{
    int error = ble_hs_id_infer_auto(0, &own_address_type);
    if (error != 0) {
        ESP_LOGE(TAG, "cannot infer BLE address type: %d", error);
        xEventGroupSetBits(scanner_events, BLE_FAILED_BIT);
        nm_ble_buffer_set_available(false);
        return;
    }

    const struct ble_gap_disc_params parameters = {
        .filter_duplicates = 0,
        .passive = 1,
        /* Diagnostic trial: 50 ms listening every 100 ms (50% duty).
         * Values are in 0.625 ms units. */
        .itvl = 0x00A0,
        .window = 0x0050,
    };
    error = ble_gap_disc(own_address_type, BLE_HS_FOREVER, &parameters, scan_event, NULL);
    if (error != 0 && error != BLE_HS_EALREADY) {
        ESP_LOGE(TAG, "could not start passive discovery: %d", error);
        xEventGroupSetBits(scanner_events, BLE_FAILED_BIT);
        nm_ble_buffer_set_available(false);
        return;
    }

    xEventGroupClearBits(scanner_events, BLE_FAILED_BIT);
    xEventGroupSetBits(scanner_events, BLE_READY_BIT);
    nm_ble_buffer_set_available(true);
    ESP_LOGI(TAG,
             "shared passive BLE scan active; interval=100ms window=50ms duplicate_filter=off");
}

static void nimble_synced(void)
{
    start_discovery();
}

static void nimble_reset(int reason)
{
    nm_ble_buffer_set_available(false);
    xEventGroupClearBits(scanner_events, BLE_READY_BIT);
    ESP_LOGW(TAG, "NimBLE host reset reason=%d", reason);
}

static void nimble_host_task(void *argument)
{
    (void)argument;
    nimble_port_run();
    nimble_port_freertos_deinit();
}

bool nm_ble_scanner_start(void)
{
    if (scanner_events && (xEventGroupGetBits(scanner_events) & BLE_READY_BIT))
        return true;
    if (scanner_events)
        return false;

    scanner_events = xEventGroupCreate();
    if (!nm_ble_buffer_init() || !scanner_events) {
        ESP_LOGE(TAG, "unable to allocate BLE scanner synchronization");
        return false;
    }
    esp_err_t error = nimble_port_init();
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "NimBLE initialization failed: %s", esp_err_to_name(error));
        xEventGroupSetBits(scanner_events, BLE_FAILED_BIT);
        nm_ble_buffer_set_available(false);
        return false;
    }

    ble_hs_cfg.sync_cb = nimble_synced;
    ble_hs_cfg.reset_cb = nimble_reset;
    nimble_port_freertos_init(nimble_host_task);
    EventBits_t bits = xEventGroupWaitBits(scanner_events, BLE_READY_BIT | BLE_FAILED_BIT, pdFALSE,
                                           pdFALSE, pdMS_TO_TICKS(10000));
    if (!(bits & BLE_READY_BIT)) {
        ESP_LOGE(TAG, "BLE scanner did not become ready");
        return false;
    }
    return true;
}

#else
bool nm_ble_scanner_start(void)
{
    nm_ble_buffer_init();
    nm_ble_buffer_set_available(false);
    return false;
}
#endif
