#include "ble_scanner.h"
#include "ble_filter.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/queue.h"
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

#include "probe_config.h"

static const char *TAG = "nm_ble_scanner";
enum { BLE_READY_BIT = 1U, BLE_FAILED_BIT = 2U };

typedef struct {
    bool active;
    nm_ble_filter filter;
    QueueHandle_t result;
    StaticQueue_t queue_control;
    uint8_t queue_storage[sizeof(nm_ble_advertisement)];
} ble_waiter;

static ble_waiter waiters[NM_PROBE_MAX_WORKERS];
static SemaphoreHandle_t waiters_lock;
static EventGroupHandle_t scanner_events;
static uint8_t own_address_type;
static int64_t next_advertisement_log_us;
static int64_t next_victron_log_us;

static void address_text(const ble_addr_t *address, char out[NM_BLE_ADDRESS_TEXT_SIZE])
{
    /* NimBLE stores address bytes in host order (least significant first). */
    snprintf(out, NM_BLE_ADDRESS_TEXT_SIZE, "%02X:%02X:%02X:%02X:%02X:%02X",
             address->val[5], address->val[4], address->val[3], address->val[2],
             address->val[1], address->val[0]);
}

static int scan_event(struct ble_gap_event *event, void *argument)
{
    (void)argument;
    if (event->type == BLE_GAP_EVENT_DISC) {
        const struct ble_gap_disc_desc *found = &event->disc;
        /* NimBLE's length_data is uint8_t, so it cannot exceed our 255-byte buffer. */
        if (found->length_data && !found->data)
            return 0;

        nm_ble_advertisement item = {.rssi = found->rssi,
                                     .data_length = found->length_data};
        address_text(&found->addr, item.address);
        if (item.data_length)
            memcpy(item.data, found->data, item.data_length);

        int64_t now_us = esp_timer_get_time();
        unsigned company = 0;
        for (size_t offset = 0; offset + 3 <= item.data_length;) {
            size_t field_length = item.data[offset];
            if (!field_length || field_length > item.data_length - offset - 1)
                break;
            if (item.data[offset + 1] == 0xFF && field_length >= 3) {
                company = (unsigned)item.data[offset + 2] |
                          ((unsigned)item.data[offset + 3] << 8);
                break;
            }
            offset += field_length + 1;
        }

        /* Victron broadcasts are the target of this bench test. Log receipt
         * without exposing the encrypted manufacturer payload. */
        if (company == 0x02E1 && now_us >= next_victron_log_us) {
            next_victron_log_us = now_us + 10000000;
            ESP_LOGI(TAG, "Victron advertisement received address=%s rssi=%d bytes=%u",
                     item.address, item.rssi, (unsigned)item.data_length);
        } else if (now_us >= next_advertisement_log_us) {
            /* Keep general discovery diagnostics bounded in busy RF areas. */
            next_advertisement_log_us = now_us + 10000000;
            ESP_LOGI(TAG, "advertisement sample address=%s rssi=%d company=0x%04x bytes=%u",
                     item.address, item.rssi, company, (unsigned)item.data_length);
        }

        if (xSemaphoreTake(waiters_lock, 0) != pdTRUE)
            return 0;

        for (size_t i = 0; i < NM_PROBE_MAX_WORKERS; ++i) {
            ble_waiter *waiter = &waiters[i];
            if (waiter->active && nm_ble_advertisement_matches(&item, &waiter->filter) &&
                xQueueSend(waiter->result, &item, 0) == pdTRUE) {
                /* Keep the slot owned until its waiting task consumes the
                 * result and unregisters it under waiters_lock. */
            }
        }
        xSemaphoreGive(waiters_lock);
        return 0;
    }

    if (event->type == BLE_GAP_EVENT_DISC_COMPLETE) {
        /* An unexpected completion should not permanently disable BLE probes. */
        const struct ble_gap_disc_params parameters = {
            .filter_duplicates = 0,
            .passive = 1,
            /* Espressif recommends interval == window for better BLE scan
             * reliability when Wi-Fi coexistence can interrupt scan windows. */
            .itvl = 0x0050,
            .window = 0x0050,
        };
        int error = ble_gap_disc(own_address_type, BLE_HS_FOREVER, &parameters,
                                 scan_event, NULL);
        if (error == 0 || error == BLE_HS_EALREADY) {
            xEventGroupSetBits(scanner_events, BLE_READY_BIT);
        } else {
            ESP_LOGE(TAG, "could not restart passive discovery: %d", error);
            xEventGroupClearBits(scanner_events, BLE_READY_BIT);
            xEventGroupSetBits(scanner_events, BLE_FAILED_BIT);
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
        return;
    }

    const struct ble_gap_disc_params parameters = {
        .filter_duplicates = 0,
        .passive = 1,
        /* Continuous passive scan opportunities. Wi-Fi coexistence still
         * arbitrates actual shared-radio access dynamically. */
        .itvl = 0x0050,
        .window = 0x0050,
    };
    error = ble_gap_disc(own_address_type, BLE_HS_FOREVER, &parameters,
                         scan_event, NULL);
    if (error != 0 && error != BLE_HS_EALREADY) {
        ESP_LOGE(TAG, "could not start passive discovery: %d", error);
        xEventGroupSetBits(scanner_events, BLE_FAILED_BIT);
        return;
    }

    xEventGroupClearBits(scanner_events, BLE_FAILED_BIT);
    xEventGroupSetBits(scanner_events, BLE_READY_BIT);
    ESP_LOGI(TAG, "shared passive BLE scan active; interval=50ms window=50ms duplicate_filter=off");
}

static void nimble_synced(void)
{
    start_discovery();
}

static void nimble_reset(int reason)
{
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
    if (scanner_events &&
        (xEventGroupGetBits(scanner_events) & BLE_READY_BIT))
        return true;
    if (waiters_lock || scanner_events)
        return false;

    waiters_lock = xSemaphoreCreateMutex();
    scanner_events = xEventGroupCreate();
    if (!waiters_lock || !scanner_events) {
        ESP_LOGE(TAG, "unable to allocate BLE scanner synchronization");
        return false;
    }
    for (size_t i = 0; i < NM_PROBE_MAX_WORKERS; ++i) {
        waiters[i].result = xQueueCreateStatic(1, sizeof(nm_ble_advertisement),
                                                waiters[i].queue_storage,
                                                &waiters[i].queue_control);
        if (!waiters[i].result) {
            ESP_LOGE(TAG, "unable to allocate BLE waiter queue");
            return false;
        }
    }

    esp_err_t error = nimble_port_init();
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "NimBLE initialization failed: %s", esp_err_to_name(error));
        xEventGroupSetBits(scanner_events, BLE_FAILED_BIT);
        return false;
    }

    ble_hs_cfg.sync_cb = nimble_synced;
    ble_hs_cfg.reset_cb = nimble_reset;
    nimble_port_freertos_init(nimble_host_task);
    EventBits_t bits = xEventGroupWaitBits(scanner_events, BLE_READY_BIT | BLE_FAILED_BIT,
                                           pdFALSE, pdFALSE, pdMS_TO_TICKS(10000));
    if (!(bits & BLE_READY_BIT)) {
        ESP_LOGE(TAG, "BLE scanner did not become ready");
        return false;
    }
    return true;
}

nm_ble_wait_result nm_ble_scanner_wait(const nm_ble_filter *filter, unsigned timeout_ms,
                                       nm_ble_advertisement *advertisement)
{
    if (!filter || !advertisement || !waiters_lock || !scanner_events ||
        !(xEventGroupGetBits(scanner_events) & BLE_READY_BIT))
        return NM_BLE_WAIT_UNAVAILABLE;

    if (xSemaphoreTake(waiters_lock, pdMS_TO_TICKS(1000)) != pdTRUE)
        return NM_BLE_WAIT_CAPACITY;
    ble_waiter *available = NULL;
    for (size_t i = 0; i < NM_PROBE_MAX_WORKERS; ++i) {
        if (!waiters[i].active) {
            available = &waiters[i];
            break;
        }
    }
    if (!available) {
        xSemaphoreGive(waiters_lock);
        return NM_BLE_WAIT_CAPACITY;
    }
    nm_ble_advertisement discarded;
    while (xQueueReceive(available->result, &discarded, 0) == pdTRUE) {
    }
    available->filter = *filter;
    available->active = true;
    QueueHandle_t result_queue = available->result;
    xSemaphoreGive(waiters_lock);

    TickType_t ticks = pdMS_TO_TICKS(timeout_ms);
    if (timeout_ms && !ticks)
        ticks = 1;
    bool received = xQueueReceive(result_queue, advertisement, ticks) == pdTRUE;

    if (xSemaphoreTake(waiters_lock, portMAX_DELAY) == pdTRUE) {
        available->active = false;
        xSemaphoreGive(waiters_lock);
    }
    if (received) return NM_BLE_WAIT_FOUND;
    return (xEventGroupGetBits(scanner_events) & BLE_READY_BIT)
               ? NM_BLE_WAIT_TIMEOUT : NM_BLE_WAIT_UNAVAILABLE;
}

#else

bool nm_ble_scanner_start(void)
{
    return false;
}

nm_ble_wait_result nm_ble_scanner_wait(const nm_ble_filter *filter, unsigned timeout_ms,
                                       nm_ble_advertisement *advertisement)
{
    (void)filter;
    (void)timeout_ms;
    (void)advertisement;
    return NM_BLE_WAIT_UNAVAILABLE;
}

#endif
