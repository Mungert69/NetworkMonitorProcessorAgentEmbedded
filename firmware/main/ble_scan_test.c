#include "ble_scan_test.h"

#include "esp_log.h"

#if defined(CONFIG_BT_NIMBLE_ENABLED) && CONFIG_BT_NIMBLE_ENABLED

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "host/ble_gap.h"
#include "host/ble_hs.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include <stdatomic.h>

static const char *TAG = "nm_ble_scan_test";
enum { BLE_READY_BIT = 1U, BLE_SCAN_COMPLETE_BIT = 2U };
enum { BLE_SCAN_WINDOW_MS = 10000, BLE_SCAN_PAUSE_MS = 20000, BLE_SAMPLE_LOG_LIMIT = 10 };

static EventGroupHandle_t scan_events;
static atomic_uint advertisements_seen;
static atomic_uint scan_errors;
static uint8_t own_address_type;

static int scan_gap_event(struct ble_gap_event *event, void *argument)
{
    (void)argument;
    switch (event->type) {
    case BLE_GAP_EVENT_DISC: {
        unsigned index = atomic_fetch_add_explicit(&advertisements_seen, 1, memory_order_relaxed);
        if (index < BLE_SAMPLE_LOG_LIMIT) {
            const struct ble_gap_disc_desc *advertisement = &event->disc;
            ESP_LOGI(TAG, "advertisement sample=%u rssi=%d addr_type=%u payload_bytes=%u",
                     index + 1U, advertisement->rssi, advertisement->addr.type,
                     (unsigned)advertisement->length_data);
        }
        return 0;
    }
    case BLE_GAP_EVENT_DISC_COMPLETE:
        xEventGroupSetBits(scan_events, BLE_SCAN_COMPLETE_BIT);
        return 0;
    default:
        return 0;
    }
}

static void nimble_synced(void)
{
    int error = ble_hs_id_infer_auto(0, &own_address_type);
    if (error != 0) {
        ESP_LOGE(TAG, "cannot infer BLE address type: %d", error);
        atomic_fetch_add_explicit(&scan_errors, 1, memory_order_relaxed);
        return;
    }
    xEventGroupSetBits(scan_events, BLE_READY_BIT);
}

static void nimble_reset(int reason)
{
    ESP_LOGW(TAG, "NimBLE host reset reason=%d", reason);
    atomic_fetch_add_explicit(&scan_errors, 1, memory_order_relaxed);
    xEventGroupClearBits(scan_events, BLE_READY_BIT);
}

static void nimble_host_task(void *argument)
{
    (void)argument;
    nimble_port_run();
    nimble_port_freertos_deinit();
}

static void passive_scan_task(void *argument)
{
    (void)argument;
    const struct ble_gap_disc_params parameters = {
        .filter_duplicates = 1,
        .passive = 1,
    };

    for (;;) {
        (void)xEventGroupWaitBits(scan_events, BLE_READY_BIT, pdFALSE, pdTRUE, portMAX_DELAY);
        atomic_store_explicit(&advertisements_seen, 0, memory_order_relaxed);
        atomic_store_explicit(&scan_errors, 0, memory_order_relaxed);

        int error = ble_gap_disc(own_address_type, BLE_SCAN_WINDOW_MS, &parameters,
                                 scan_gap_event, NULL);
        if (error != 0) {
            ESP_LOGW(TAG, "passive scan start failed: %d", error);
            atomic_fetch_add_explicit(&scan_errors, 1, memory_order_relaxed);
        } else {
            (void)xEventGroupWaitBits(scan_events, BLE_SCAN_COMPLETE_BIT, pdTRUE, pdFALSE,
                                      pdMS_TO_TICKS(BLE_SCAN_WINDOW_MS + 2000));
        }

        ESP_LOGI(TAG, "passive scan window complete advertisements=%u errors=%u duration_ms=%u",
                 atomic_load_explicit(&advertisements_seen, memory_order_relaxed),
                 atomic_load_explicit(&scan_errors, memory_order_relaxed),
                 (unsigned)BLE_SCAN_WINDOW_MS);
        vTaskDelay(pdMS_TO_TICKS(BLE_SCAN_PAUSE_MS));
    }
}

bool nm_ble_scan_test_start(void)
{
    scan_events = xEventGroupCreate();
    if (!scan_events) {
        ESP_LOGE(TAG, "could not allocate scan event group");
        return false;
    }

    atomic_init(&advertisements_seen, 0);
    atomic_init(&scan_errors, 0);
    esp_err_t error = nimble_port_init();
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "NimBLE initialization failed: %s", esp_err_to_name(error));
        vEventGroupDelete(scan_events);
        scan_events = NULL;
        return false;
    }

    ble_hs_cfg.sync_cb = nimble_synced;
    ble_hs_cfg.reset_cb = nimble_reset;
    nimble_port_freertos_init(nimble_host_task);

    if (xTaskCreate(passive_scan_task, "ble_scan_test", 4096, NULL, 4, NULL) != pdPASS) {
        ESP_LOGE(TAG, "could not create passive scan control task");
        return false;
    }
    ESP_LOGI(TAG, "NimBLE passive broadcast listener started; scan=10s pause=20s duplicate_filter=on");
    return true;
}

#else

bool nm_ble_scan_test_start(void)
{
    return true;
}

#endif
