#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_netif_sntp.h"
#include "esp_sntp.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "network.h"
#include "nm_esp.h"
#include "nvs_flash.h"
#include "status_led.h"
#include <inttypes.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

static const char *TAG = "nm_network";
static atomic_bool online, fresh_request, correction_available, correction_applied;
static int64_t boot_us, boot_utc, correction_offset;
static bool recording_started; /* Written before task/callback creation. */
static atomic_uint sync_generation;
/* Network task owns all retries and SNTP lifecycle; callbacks only signal. */
static unsigned retry_index;
static int64_t wifi_due, ntp_due;
static bool ntp_active;
static unsigned attempt_generation;
static int64_t ntp_deadline, reference_us;
static time_t reference_utc;
static const unsigned retry_seconds[] = {5, 15, 30, 60};

bool nm_network_time_synced(void)
{
    return atomic_load(&sync_generation) != 0;
}
bool nm_network_ready(void)
{
    return atomic_load(&online) && atomic_load(&correction_applied);
}
time_t nm_network_recording_time(void)
{
    if (!recording_started || atomic_load(&correction_applied))
        return time(NULL);
    return (time_t)(boot_utc + (esp_timer_get_time() - boot_us) / 1000000);
}
bool nm_network_correction(int64_t *offset)
{
    if (!atomic_load(&correction_available))
        return false;
    if (offset)
        *offset = correction_offset;
    return true;
}
void nm_network_accept_correction(void)
{
    if (!atomic_load(&correction_available))
        return;
    atomic_store(&correction_applied, true);
    nm_status_led_clock(true);
}
static void time_synced(struct timeval *tv)
{
    if (tv && tv->tv_sec >= INT64_C(1640995200)) {
        if (!atomic_load(&correction_available)) {
            correction_offset = (int64_t)tv->tv_sec - (int64_t)nm_network_recording_time();
            atomic_store(&correction_available, true);
        }
        atomic_fetch_add(&sync_generation, 1);
    }
}
static void wifi_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        atomic_store(&online, false);
        nm_status_led_wifi(false);
        const wifi_event_sta_disconnected_t *event = data;
        ESP_LOGW(TAG, "Wi-Fi disconnected reason=%u; network task will retry",
                 event ? (unsigned)event->reason : 0u);
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        atomic_store(&online, true);
        nm_status_led_wifi(true);
        ESP_LOGI(TAG, "Wi-Fi connected and IP assigned");
    }
}
/* One nonblocking service step; also exercised directly by native tests. */
static void network_step(int64_t now)
{
    bool connected = atomic_load(&online);
    if (!connected && now >= wifi_due) {
        esp_err_t error = esp_wifi_connect();
        unsigned delay = retry_seconds[retry_index];
        if (retry_index + 1 < sizeof(retry_seconds) / sizeof(retry_seconds[0]))
            ++retry_index;
        wifi_due = now + (int64_t)delay * 1000000;
        ESP_LOGI(TAG, "Wi-Fi attempt: %s; next retry in %u s", esp_err_to_name(error), delay);
    }
    if (connected) {
        retry_index = 0;
        /* A later loss gets one prompt attempt, then the normal backoff. */
        wifi_due = now;
    }
    if (ntp_active) {
        unsigned generation = atomic_load(&sync_generation);
        if (generation != attempt_generation || now >= ntp_deadline || !connected) {
            /* Deinit stops SDK retransmissions too; the task owns retry timing. */
            esp_netif_sntp_deinit();
            ntp_active = false;
            ntp_due = now + INT64_C(60000000);
            if (generation != attempt_generation) {
                int64_t correction =
                    (int64_t)time(NULL) - ((int64_t)reference_utc + (now - reference_us) / 1000000);

                ESP_LOGI(TAG,
                         "NTP synchronized; clock correction=%" PRId64
                         " s; data awaits processor correction",
                         correction);
            } else {
                ESP_LOGW(TAG, "NTP unavailable; collecting with %s time, retry in 60 s",
                         nm_network_time_synced() ? "previously synchronized" : "unverified");
            }
        }
    }
    bool requested = atomic_exchange(&fresh_request, false);
    if (connected && !ntp_active && ((!nm_network_time_synced() && now >= ntp_due) || requested)) {
        reference_us = now;
        reference_utc = time(NULL);
        attempt_generation = atomic_load(&sync_generation);
        esp_sntp_config_t config = ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");
        config.sync_cb = time_synced;
        config.wait_for_sync = false;
        esp_err_t error = esp_netif_sntp_init(&config);
        ntp_active = error == ESP_OK;
        ntp_deadline = now + INT64_C(15000000);
        ntp_due = now + INT64_C(60000000);
        if (!ntp_active)
            ESP_LOGW(TAG, "NTP startup failed: %s; retry in 60 s", esp_err_to_name(error));
    }
}
static void network_task(void *arg)
{
    (void)arg;
    for (;;) {
        network_step(esp_timer_get_time());
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
/* OTA explicitly requests a NEW reply, never trusts the restored clock. Only
 * this caller waits; monitoring startup and cycles never use this function. */
bool nm_esp_clock_sync(void)
{
    if (!atomic_load(&online))
        return false;
    unsigned generation = atomic_load(&sync_generation);
    atomic_store(&fresh_request, true);
    int64_t deadline = esp_timer_get_time() + INT64_C(18000000);
    while (esp_timer_get_time() < deadline) {
        if (atomic_load(&sync_generation) != generation)
            return true;
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    ESP_LOGW(TAG, "Fresh time synchronization failed; refusing OTA command");
    return false;
}
bool nm_esp_wifi_connect(const nm_esp_config *config)
{
    int64_t saved = nm_esp_storage_clock_load();
    time_t current = time(NULL);
    /* The existing wire date is seconds since 2022; never underflow it on a
     * first offline boot. The fallback is deliberately provisional. */
    if (current < 1640995200 || saved > (int64_t)current) {
        struct timeval tv = {.tv_sec = saved >= 1640995200 ? saved : 1640995200};
        if (settimeofday(&tv, NULL) != 0)
            return false;
    }
    boot_us = esp_timer_get_time();
    boot_utc = (int64_t)time(NULL);
    recording_started = true;
    ESP_LOGW(TAG,
             "Boot clock=%" PRId64 " (%s); unverified until NTP and persisted timestamp correction",
             (int64_t)time(NULL), saved >= 1640995200 ? "saved checkpoint" : "no checkpoint");
    if (nvs_flash_init() != ESP_OK || esp_netif_init() != ESP_OK ||
        esp_event_loop_create_default() != ESP_OK || !esp_netif_create_default_wifi_sta())
        return false;
    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    if (esp_wifi_init(&init) != ESP_OK)
        return false;
    if (esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event, NULL) != ESP_OK ||
        esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event, NULL) != ESP_OK)
        return false;
    wifi_config_t wifi = {0};
    memcpy(wifi.sta.ssid, config->wifi_ssid, strlen(config->wifi_ssid));
    memcpy(wifi.sta.password, config->wifi_password, strlen(config->wifi_password));
    wifi.sta.threshold.authmode = *config->wifi_password ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
    if (esp_wifi_set_mode(WIFI_MODE_STA) != ESP_OK ||
        esp_wifi_set_config(WIFI_IF_STA, &wifi) != ESP_OK || esp_wifi_start() != ESP_OK)
        return false;
    if (xTaskCreate(network_task, "nm_network", 4096, NULL, 2, NULL) != pdPASS)
        return false;
    if (config->wifi_setup) {
        /* Interactive provisioning still needs a bounded connectivity check. */
        int64_t deadline = esp_timer_get_time() + INT64_C(30000000);
        while (!atomic_load(&online) && esp_timer_get_time() < deadline)
            vTaskDelay(pdMS_TO_TICKS(100));
        return atomic_load(&online);
    }
    return true;
}
