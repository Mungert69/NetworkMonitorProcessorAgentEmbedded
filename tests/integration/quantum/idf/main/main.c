#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "board_config.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_netif_sntp.h"
#include "esp_wifi.h"
#include "nvs_flash.h"
#include <stdio.h>
#include <string.h>

int nm_quantum_trial_probe(int argc, char **argv);
static EventGroupHandle_t wifi_events;

static void wifi_event(void *unused, esp_event_base_t base, int32_t id, void *data)
{
    (void)unused;
    (void)data;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START)
        esp_wifi_connect();
    if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP)
        xEventGroupSetBits(wifi_events, BIT0);
}

static bool connect_wifi(void)
{
    if (nvs_flash_init() != ESP_OK || esp_netif_init() != ESP_OK ||
        esp_event_loop_create_default() != ESP_OK)
        return false;
    wifi_events = xEventGroupCreate();
    if (!wifi_events || !esp_netif_create_default_wifi_sta())
        return false;
    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    if (esp_wifi_init(&init) != ESP_OK ||
        esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event, NULL) != ESP_OK ||
        esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event, NULL) != ESP_OK)
        return false;
    wifi_config_t wifi = {0};
    memcpy(wifi.sta.ssid, BOARD_WIFI_SSID, sizeof(BOARD_WIFI_SSID) - 1);
    memcpy(wifi.sta.password, BOARD_WIFI_PASSWORD, sizeof(BOARD_WIFI_PASSWORD) - 1);
    wifi.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    if (esp_wifi_set_mode(WIFI_MODE_STA) != ESP_OK ||
        esp_wifi_set_config(WIFI_IF_STA, &wifi) != ESP_OK || esp_wifi_start() != ESP_OK)
        return false;
    if (!(xEventGroupWaitBits(wifi_events, BIT0, pdFALSE, pdFALSE, pdMS_TO_TICKS(30000)) & BIT0))
        return false;
    esp_sntp_config_t clock_config = ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");
    return esp_netif_sntp_init(&clock_config) == ESP_OK &&
           esp_netif_sntp_sync_wait(pdMS_TO_TICKS(15000)) == ESP_OK;
}

static void trial(void *unused)
{
    (void)unused;
    unsigned passed = 0;
    for (unsigned i = 0; i < sizeof(board_cases) / sizeof(board_cases[0]); ++i) {
        char *args[] = {"quantum-probe", (char *)board_cases[i].mode,
                        "localhost",     (char *)board_cases[i].port,
                        "embedded",      BOARD_CONNECT_HOST};
        int64_t start = esp_timer_get_time();
        int result = nm_quantum_trial_probe(6, args);
        printf("BOARD_CASE index=%u result=%d expected=%d elapsed_us=%lld\n", i, result,
               board_cases[i].expected, (long long)(esp_timer_get_time() - start));
        passed += result == board_cases[i].expected;
        printf("BOARD_MEMORY internal_free=%u internal_min=%u psram_free=%u psram_min=%u "
               "stack_free=%u\n",
               (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
               (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL),
               (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),
               (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_SPIRAM),
               (unsigned)uxTaskGetStackHighWaterMark(NULL));
    }
    printf("QUANTUM_BOARD_RESULT passed=%u total=%u\n", passed,
           (unsigned)(sizeof(board_cases) / sizeof(board_cases[0])));
    /* Owner deletes WithCaps task, never self-delete. */
    for (;;)
        vTaskDelay(pdMS_TO_TICKS(10000));
}

void app_main(void)
{
    if (!connect_wifi()) {
        printf("QUANTUM_BOARD_NETWORK_FAILED\n");
        return;
    }
    TaskHandle_t worker = NULL;
    if (xTaskCreatePinnedToCoreWithCaps(trial, "quantum_trial", 16384, NULL, tskIDLE_PRIORITY,
                                        &worker, 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT) != pdPASS)
        printf("QUANTUM_BOARD_TASK_FAILED\n");
}
