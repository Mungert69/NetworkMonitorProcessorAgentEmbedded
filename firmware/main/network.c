#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_netif_sntp.h"
#include "esp_sntp.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "nm_esp.h"
#include "nvs_flash.h"
#include <string.h>

static const char *TAG = "nm_network";
static EventGroupHandle_t wifi_events;
enum { WIFI_CONNECTED = BIT0 };

bool nm_esp_clock_sync(void)
{
    /* Consume any previous notification; require a fresh reply for OTA. */
    (void)esp_netif_sntp_sync_wait(0);
    if (esp_netif_sntp_start() != ESP_OK ||
        esp_netif_sntp_sync_wait(pdMS_TO_TICKS(15000)) != ESP_OK) {
        ESP_LOGW(TAG, "Fresh time synchronization failed; refusing OTA command");
        return false;
    }
    return true;
}

static void wifi_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    (void)data;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        xEventGroupClearBits(wifi_events, WIFI_CONNECTED);
        esp_wifi_connect();
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        xEventGroupSetBits(wifi_events, WIFI_CONNECTED);
        ESP_LOGI(TAG, "Wi-Fi connected and IP assigned");
    }
}

bool nm_esp_wifi_connect(const nm_esp_config *config)
{
    if (nvs_flash_init() != ESP_OK || esp_netif_init() != ESP_OK ||
        esp_event_loop_create_default() != ESP_OK)
        return false;
    wifi_events = xEventGroupCreate();
    if (!wifi_events || !esp_netif_create_default_wifi_sta())
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
        esp_wifi_set_config(WIFI_IF_STA, &wifi) != ESP_OK || esp_wifi_start() != ESP_OK ||
        esp_wifi_connect() != ESP_OK)
        return false;
    ESP_LOGI(TAG, "connecting to Wi-Fi SSID %s", config->wifi_ssid);
    if (!(xEventGroupWaitBits(wifi_events, WIFI_CONNECTED, pdFALSE, pdFALSE, pdMS_TO_TICKS(30000)) &
          WIFI_CONNECTED))
        return false;
    /* Emulator time can drift significantly relative to wall time. Keep the
     * clock fresh without relaxing OTA command expiration checks. */
    esp_sntp_set_sync_interval(60000);
    esp_sntp_config_t clock_config = ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");
    if (esp_netif_sntp_init(&clock_config) == ESP_OK &&
        esp_netif_sntp_sync_wait(pdMS_TO_TICKS(15000)) != ESP_OK)
        ESP_LOGW(TAG, "NTP not synchronized; data cycles will wait for time");
    return true;
}
