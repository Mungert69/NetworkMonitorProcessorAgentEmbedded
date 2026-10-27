#include "camera_capture.h"
#include "camera_http.h"
#include "camera_rtsp.h"
#include "endpoint_internal.h"
#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "freertos/idf_additions.h"
#include "nvs_flash.h"
#include <assert.h>
#include <stdio.h>
#include <sys/time.h>
static EventGroupHandle_t connected;
static char gateway[32];
static atomic_bool cancel;
static void got_ip(void *arg, esp_event_base_t base, int32_t id, void *event)
{
    (void)arg;
    (void)base;
    (void)id;
    ip_event_got_ip_t *ip = event;
    snprintf(gateway, sizeof(gateway), IPSTR, IP2STR(&ip->ip_info.gw));
    xEventGroupSetBits(connected, 1);
}
lookup_result nm_endpoint_resolve(const char *host, unsigned port, unsigned timeout,
                                  struct addrinfo **out)
{
    (void)timeout;
    char service[8];
    snprintf(service, sizeof(service), "%u", port);
    struct addrinfo hints = {
        .ai_family = AF_INET, .ai_socktype = SOCK_STREAM, .ai_flags = AI_NUMERICHOST};
    return getaddrinfo(host, service, &hints, out) == 0 ? LOOKUP_OK : LOOKUP_ERROR;
}
static void cancel_later(void *arg)
{
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(200));
    atomic_store(&cancel, true);
    vTaskDelete(NULL);
}
static void run(void *arg)
{
    (void)arg;
    char args[256];
    const char *error;
    snprintf(
        args, sizeof(args),
        "--address %s --onvif_port 18081 --protocol onvif --username test --password test-password",
        gateway);
    nm_camera_command *command = calloc(1, sizeof(*command));
    assert(command && nm_camera_cmd_parse(args, command, &error));
    command->timeout_ms = 60000;
    nm_cmd_result result = nm_camera_cmd_run(command, &cancel);
    printf("CAMERA_ONVIF success=%d bytes=%u output=%s\n", result.success,
           (unsigned)result.raw_length, result.output ? result.output : "");
    assert(result.success && result.raw_length && strlen(result.raw_sha256) == 64);
    free(result.output);
    free(result.raw_data);
    const char *paths[] = {"/basic.jpg",     "/digest.jpg",    "/chunked.jpg",
                           "/oversized.jpg", "/truncated.jpg", "/redirect.jpg"};
    for (unsigned i = 0; i < 6; ++i) {
        char url[128];
        snprintf(url, sizeof(url), "http://%s:18081%s", gateway, paths[i]);
        nm_camera_http_reply reply;
        bool ok =
            nm_camera_http(url, NULL, NULL, "test", "test-password", 3000, &cancel, 65536, &reply);
        printf("CAMERA_HTTP path=%s ok=%d bytes=%u status=%d\n", paths[i], ok,
               (unsigned)reply.length, reply.status);
        assert(ok == (i < 3));
        free(reply.data);
    }
    char url[128];
    snprintf(url, sizeof(url), "rtsp://%s:18554/jpeg", gateway);
    nm_camera_image image;
    assert(nm_camera_rtsp(url, "test", "test-password", 5000, &cancel, &image));
    assert(image.width == 640 && image.height == 360 && image.length > 600);
    free(image.data);
    puts("CAMERA_RTSP_JPEG_PASS");
    snprintf(url, sizeof(url), "http://%s:18081/stall", gateway);
    nm_camera_http_reply reply;
    int64_t start = nm_camera_now_us();
    assert(!nm_camera_http(url, NULL, NULL, "", "", 500, &cancel, 65536, &reply));
    assert(nm_camera_now_us() - start < 1500000);
    free(reply.data);
    assert(xTaskCreate(cancel_later, "cancel", 2048, NULL, 2, NULL) == pdPASS);
    start = nm_camera_now_us();
    assert(!nm_camera_http(url, NULL, NULL, "", "", 5000, &cancel, 65536, &reply));
    assert(atomic_load(&cancel) && nm_camera_now_us() - start < 2000000);
    free(reply.data);
    assert(heap_caps_check_integrity_all(true));
    free(command);
    puts("CAMERA_CAPTURE_INTEGRATION_PASS");
    for (;;)
        vTaskDelay(pdMS_TO_TICKS(1000));
}
void app_main(void)
{
    struct timeval now = {.tv_sec = NM_TEST_EPOCH};
    assert(!settimeofday(&now, NULL));
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    connected = xEventGroupCreate();
    assert(connected);
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, got_ip, NULL));
    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&init));
    wifi_config_t wifi = {.sta = {.ssid = "test", .password = "test-password"}};
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_connect());
    assert(xEventGroupWaitBits(connected, 1, false, true, pdMS_TO_TICKS(15000)) & 1);
    TaskHandle_t task;
    assert(xTaskCreatePinnedToCoreWithCaps(run, "camera", 16384, NULL, tskIDLE_PRIORITY, &task, 1,
                                           MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT) == pdPASS);
}
