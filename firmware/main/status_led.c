#include "status_led.h"
#include "driver/rmt_encoder.h"
#include "driver/rmt_tx.h"
#include "esp_attr.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <stdatomic.h>
#include <time.h>

/* Plain YD-ESP32-S3 recorder board; Hal9000's display board uses GPIO40.
 * Override to -1 when building for a board without this indicator. */
#ifndef NM_STATUS_LED_GPIO
#define NM_STATUS_LED_GPIO 48
#endif
static DRAM_ATTR atomic_uint stage = NM_LED_BOOT;
static DRAM_ATTR atomic_bool wifi, mqtt, probe, sent, clock_synced, correcting;
static rmt_channel_handle_t channel;
static rmt_encoder_handle_t encoder;
/* Static/internal: valid even if a failed transmission is still in flight. */
static rmt_symbol_word_t symbols[25];
static const char *TAG = "nm_led";

void nm_status_led_stage(nm_led_stage value)
{
    atomic_store(&stage, value);
}
void nm_status_led_wifi(bool value)
{
    atomic_store(&wifi, value);
}
void nm_status_led_mqtt(bool value)
{
    atomic_store(&mqtt, value);
}
void nm_status_led_clock(bool value)
{
    atomic_store(&clock_synced, value);
}
void nm_status_led_correcting(bool value)
{
    atomic_store(&correcting, value);
}
void nm_status_led_probe(void)
{
    atomic_store(&probe, true);
}

void nm_status_led_sent(void)
{
    atomic_store(&sent, true);
}

static esp_err_t set_color(uint32_t grb)
{
    for (unsigned bit = 0; bit < 24; ++bit) {
        bool one = grb & (1u << (23 - bit));
        symbols[bit] = (rmt_symbol_word_t){
            .level0 = 1, .duration0 = one ? 8 : 4, .level1 = 0, .duration1 = one ? 4 : 8};
    }
    symbols[24] = (rmt_symbol_word_t){.duration0 = 500, .duration1 = 500};
    rmt_transmit_config_t config = {.flags.queue_nonblocking = true};
    esp_err_t err = rmt_transmit(channel, encoder, symbols, sizeof(symbols), &config);
    return err == ESP_OK ? rmt_tx_wait_all_done(channel, 20) : err;
}

static void indicator_task(void *arg)
{
    (void)arg;
    rmt_tx_channel_config_t config = {.gpio_num = NM_STATUS_LED_GPIO,
                                      .clk_src = RMT_CLK_SRC_DEFAULT,
                                      .resolution_hz = 10000000,
                                      .mem_block_symbols = 64,
                                      .trans_queue_depth = 1};
    rmt_copy_encoder_config_t copy = {};
    esp_err_t err = rmt_new_tx_channel(&config, &channel);
    if (err == ESP_OK)
        err = rmt_new_copy_encoder(&copy, &encoder);
    bool enabled = false;
    if (err == ESP_OK) {
        err = rmt_enable(channel);
        enabled = err == ESP_OK;
    }
    if (err == ESP_OK)
        ESP_LOGI(TAG, "RGB ready GPIO%d: boot/wifi/clock/enrollment/storage/backend; green=probe",
                 NM_STATUS_LED_GPIO);
    uint32_t previous = UINT32_MAX;
    bool green_last = false;
    uint64_t blue_until = 0;
    while (err == ESP_OK) {
        unsigned current = atomic_load(&stage);
        uint64_t ms = (uint64_t)esp_timer_get_time() / 1000;
        uint32_t color = 0;
        /* GRB, subdued 8/255 brightness. Slow flashes keep waits recognizable. */
        if (current == NM_LED_ERROR)
            color = 8u << 8;
        else if (current == NM_LED_BOOT)
            color = 8;
        else if (current == NM_LED_ENROLLMENT)
            color = (8u << 8) | 8u;
        else if (current == NM_LED_STORAGE)
            color = (8u << 16) | (8u << 8) | 8u;
        else if (current == NM_LED_RUNNING &&
                 (!atomic_load(&wifi) || (atomic_load(&clock_synced) && !atomic_load(&mqtt))))
            color = (2u << 16) | (8u << 8);
        else if (current == NM_LED_WIFI || !atomic_load(&wifi))
            color = (8u << 16) | (8u << 8);
        else if (current == NM_LED_CLOCK || !atomic_load(&clock_synced))
            color = (8u << 16) | 8u;
        else if (!atomic_load(&mqtt))
            color = (2u << 16) | (8u << 8);
        if (ms % 1000 >= 160)
            color = 0;
        bool event = atomic_exchange(&probe, false);
        bool green = current == NM_LED_RUNNING && event && !green_last;
        if (green)
            color = 8u << 16;
        bool send_event = atomic_exchange(&sent, false);
        if (current == NM_LED_RUNNING && atomic_load(&wifi) && atomic_load(&mqtt)) {
            if (send_event)
                blue_until = ms + 120;
            if (ms < blue_until)
                color = 8u;
        } else {
            blue_until = 0;
        }
        if (current == NM_LED_RUNNING && atomic_load(&correcting))
            color = ms % 200 < 100 ? (8u << 16) | 8u : 0;
        green_last = green;
        if (color != previous) {
            err = set_color(color);
            previous = color;
        }
        vTaskDelay(pdMS_TO_TICKS(40));
    }
    ESP_LOGW(TAG, "RGB disabled after driver error: %s; monitoring continues",
             esp_err_to_name(err));
    if (enabled)
        rmt_disable(channel);
    /* A timed-out transaction may still borrow symbols/encoder: keep those
     * static resources rather than freeing an in-flight transmission. */
    vTaskDelete(NULL);
}

void nm_status_led_start(void)
{
    if (NM_STATUS_LED_GPIO < 0)
        return;
    if (xTaskCreate(indicator_task, "nm_led", 3072, NULL, tskIDLE_PRIORITY + 1, NULL) != pdPASS)
        ESP_LOGW(TAG, "RGB task unavailable; monitoring continues");
}
