#ifndef NM_NETWORK_PLATFORM_H
#define NM_NETWORK_PLATFORM_H
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
typedef int esp_err_t;
typedef const char *esp_event_base_t;
typedef unsigned EventBits_t;
typedef unsigned *EventGroupHandle_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define BIT0 1u
#define pdFALSE 0
#define pdMS_TO_TICKS(ms) (ms)
#define WIFI_EVENT ((esp_event_base_t)1)
#define IP_EVENT ((esp_event_base_t)2)
#define ESP_EVENT_ANY_ID -1
#define WIFI_EVENT_STA_DISCONNECTED 1
#define IP_EVENT_STA_GOT_IP 2
#define WIFI_AUTH_WPA2_PSK 3
#define WIFI_AUTH_OPEN 0
#define WIFI_MODE_STA 1
#define WIFI_IF_STA 1
typedef struct {
    unsigned reason;
} wifi_event_sta_disconnected_t;
typedef struct {
    int unused;
} wifi_init_config_t;
typedef struct {
    bool wait_for_sync;
    void (*sync_cb)(struct timeval *);
} esp_sntp_config_t;
#define WIFI_INIT_CONFIG_DEFAULT() ((wifi_init_config_t){0})
#define ESP_NETIF_SNTP_DEFAULT_CONFIG(server) ((esp_sntp_config_t){0})
typedef struct {
    struct {
        char ssid[32], password[64];
        struct {
            int authmode;
        } threshold;
    } sta;
} wifi_config_t;
int nvs_flash_init(void);
int esp_netif_init(void);
int esp_event_loop_create_default(void);
EventGroupHandle_t xEventGroupCreate(void);
void *esp_netif_create_default_wifi_sta(void);
int esp_wifi_init(const wifi_init_config_t *);
int esp_event_handler_register(esp_event_base_t, int,
                               void (*)(void *, esp_event_base_t, int32_t, void *), void *);
int esp_wifi_set_mode(int);
int esp_wifi_set_config(int, const wifi_config_t *);
int esp_wifi_start(void);
int esp_wifi_connect(void);
unsigned xEventGroupClearBits(EventGroupHandle_t, unsigned);
unsigned xEventGroupSetBits(EventGroupHandle_t, unsigned);
unsigned xEventGroupWaitBits(EventGroupHandle_t, unsigned, int, int, unsigned);
void esp_sntp_set_sync_interval(unsigned);
int esp_netif_sntp_init(const esp_sntp_config_t *);
int esp_netif_sntp_start(void);
int esp_netif_sntp_sync_wait(unsigned);
const char *esp_err_to_name(int);
#define pdPASS 1
int xTaskCreate(void (*fn)(void *), const char *, unsigned, void *, unsigned, void *);
void vTaskDelay(unsigned);
int64_t esp_timer_get_time(void);
void esp_netif_sntp_deinit(void);
int64_t nm_esp_storage_clock_load(void);
int test_settimeofday(const struct timeval *, const void *);
time_t test_time(time_t *);
#endif
