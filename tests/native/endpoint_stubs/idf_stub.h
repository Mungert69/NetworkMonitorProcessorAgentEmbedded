#ifndef NM_ENDPOINT_TEST_SDK_H
#define NM_ENDPOINT_TEST_SDK_H
/* Minimal ESP-IDF API stand-ins for offline endpoint syntax/lifetime tests.
 * These are not a firmware ABI or a substitute for an ESP-IDF build. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <arpa/inet.h>
typedef int esp_err_t;
typedef void *esp_mqtt_client_handle_t;
typedef void *SemaphoreHandle_t;
typedef uint32_t TickType_t;
#define ESP_OK 0
#define ESP_ERR_NO_MEM 0x101
#define ESP_ERR_TIMEOUT 0x107
#define ESP_FAIL -1
#define ESP_ERR_HTTP_EAGAIN 0x7007
#define ESP_ERR_HTTP_READ_TIMEOUT 0x700b
#define pdTRUE 1
#define pdPASS 1
#define portMAX_DELAY UINT32_MAX
#define pdMS_TO_TICKS(ms) ((TickType_t)(ms))
#define HTTP_METHOD_GET 0
#ifndef LWIP_IPV6
#define LWIP_IPV6 1
#endif
typedef struct {
    const char *url;
    int method, timeout_ms, max_redirection_count;
    int (*crt_bundle_attach)(void *);
    void *transport;
} esp_http_client_config_t;
typedef void *esp_http_client_handle_t;
typedef enum {
    HTTP_TRANSPORT_UNKNOWN,
    HTTP_TRANSPORT_OVER_TCP,
    HTTP_TRANSPORT_OVER_SSL
} esp_http_client_transport_t;
esp_http_client_transport_t esp_http_client_get_transport_type(esp_http_client_handle_t);
void vTaskDelay(TickType_t ticks);
int esp_crt_bundle_attach(void *);
const char *esp_err_to_name(esp_err_t);
int64_t esp_timer_get_time(void);
esp_http_client_handle_t esp_http_client_init(const esp_http_client_config_t *);
esp_err_t esp_http_client_perform(esp_http_client_handle_t);
int esp_http_client_get_status_code(esp_http_client_handle_t);
int esp_http_client_get_errno(esp_http_client_handle_t);
int64_t esp_http_client_get_content_length(esp_http_client_handle_t);
esp_err_t esp_http_client_cleanup(esp_http_client_handle_t);
SemaphoreHandle_t xSemaphoreCreateBinary(void);
int xSemaphoreGive(SemaphoreHandle_t);
int xSemaphoreTake(SemaphoreHandle_t, TickType_t);
void vSemaphoreDelete(SemaphoreHandle_t);
int xTaskCreate(void (*)(void *), const char *, unsigned, void *, unsigned, void *);
void vTaskDelete(void *);
typedef struct {
    int family;
    unsigned char bytes[16];
} ip_addr_t;
int ipaddr_aton(const char *, ip_addr_t *);
typedef void *esp_ping_handle_t;
typedef struct {
    unsigned count, interval_ms, timeout_ms;
    ip_addr_t target_addr;
} esp_ping_config_t;
#define ESP_PING_DEFAULT_CONFIG() {.count = 5, .interval_ms = 1000, .timeout_ms = 1000}
#define ESP_PING_PROF_TIMEGAP 1
typedef struct {
    void *cb_args;
    void (*on_ping_success)(esp_ping_handle_t, void *);
    void (*on_ping_end)(esp_ping_handle_t, void *);
} esp_ping_callbacks_t;
esp_err_t esp_ping_get_profile(esp_ping_handle_t, int, void *, uint32_t);
esp_err_t esp_ping_new_session(const esp_ping_config_t *, const esp_ping_callbacks_t *,
                               esp_ping_handle_t *);
esp_err_t esp_ping_start(esp_ping_handle_t);
esp_err_t esp_ping_delete_session(esp_ping_handle_t);
#endif
