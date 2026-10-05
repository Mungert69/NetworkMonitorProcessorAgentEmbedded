#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "http_deadline.h"
#include "endpoint_internal.h"
#include "nvs_flash.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

static EventGroupHandle_t connected;
void run_probe_memory_test(void);
static void got_ip(void *arg, esp_event_base_t base, int32_t id, void *event)
{
    (void)arg;
    (void)base;
    (void)id;
    (void)event;
    xEventGroupSetBits(connected, 1);
}

/* Test numeric routing avoids external DNS and trust secrets. The production
 * bounded resolver is tested separately by endpoint lifetime tests. */
static bool resolve_test(const char *host, unsigned port, unsigned timeout, struct addrinfo **out)
{
    (void)port;
    (void)timeout;
    struct addrinfo hints = {
        .ai_family = AF_INET, .ai_socktype = SOCK_STREAM, .ai_flags = AI_NUMERICHOST};
    const char *ip =
        (!strcmp(host, "deadline.test") || !strcmp(host, "wrong.test")) ? "192.168.4.1" : host;
    return getaddrinfo(ip, NULL, &hints, out) == 0;
}
static void run_url_policy(const char *url, bool timeout_expected, bool success_expected,
                           bool policy)
{
    nm_http_deadline *deadline = nm_http_deadline_new(1200, resolve_test);
    assert(deadline);
    nm_http_deadline_check_certificate_expiry(deadline, policy);
    esp_http_client_config_t config = {.url = url,
                                       .timeout_ms = 1200,
                                       .max_redirection_count = 5,
                                       .transport = nm_http_deadline_transport(deadline)};
    esp_http_client_handle_t client = esp_http_client_init(&config);
    assert(client);
    nm_http_deadline_bind(deadline, client);
    int64_t start = esp_timer_get_time();
    esp_err_t error = esp_http_client_perform(client);
    int64_t ms = (esp_timer_get_time() - start) / 1000;
    bool expired = nm_http_deadline_expired(deadline);
    int status = esp_http_client_get_status_code(client);
    printf("CASE %s error=%d status=%d expired=%d elapsed=%lld\n", url, error, status, expired,
           (long long)ms);
    assert(expired == timeout_expected);
    assert(ms < 1600);
    if (timeout_expected)
        assert(ms >= 1190 && error != ESP_OK);
    else if (success_expected)
        assert(error == ESP_OK && status == 200);
    else
        assert(error != ESP_OK);
    esp_http_client_cleanup(client);
    nm_http_deadline_free(deadline);
    assert(heap_caps_check_integrity_all(true));
}
static void run_url(const char *url, bool timeout_expected, bool success_expected)
{
    run_url_policy(url, timeout_expected, success_expected, false);
}
static void run_case(const char *path, bool timeout_expected)
{
    char url[192];
    snprintf(url, sizeof(url), "http://192.168.4.1:18080%s", path);
    run_url(url, timeout_expected, !timeout_expected);
}
void app_main(void)
{
    struct timeval time = {.tv_sec = NM_TEST_EPOCH};
    assert(settimeofday(&time, NULL) == 0);
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
    run_case("/ok", false);
    run_url("https://deadline.test:18443/ok", false, true);
    run_url_policy("https://deadline.test:18443/ok", false, true, true);
    run_url_policy("https://deadline.test:18446/ok", false, true, false);
    run_url_policy("https://deadline.test:18446/ok", false, false, true);
    run_url_policy("https://wrong.test:18443/ok", false, false, true);
    run_url_policy("https://deadline.test:18445/ok", false, false, true);
    assert(nm_esp_endpoint_configure_limit(4));
    nm_esp_result near = nm_endpoint_check_http("https://deadline.test:18446/ok", "https", 0, 1200);
    printf("HTTPS_EXPIRY_ENDPOINT status=%s detail=%s\n", near.status, near.message);
    assert(!near.ok && !strcmp(near.status, "HttpRequestException"));
    puts("HTTPS_EXPIRY_POLICY_PASS");
    size_t baseline = heap_caps_get_free_size(MALLOC_CAP_8BIT);
    for (int repeat = 0; repeat < 3; ++repeat) {
        run_case("/stall", true);
        run_case("/headers", true);
        run_case("/drip", true);
        run_case("/chunked", true);
        run_case("/redirect/0", true);
        run_case("/ok", false);
        run_url("https://deadline.test:18443/drip", true, false);
        run_url("https://deadline.test:18443/headers", true, false);
        run_url("https://deadline.test:18444/ok", true, false);
        run_url("https://wrong.test:18443/ok", false, false);
        run_case("/to-tls", false);
        run_url("https://deadline.test:18443/to-http", false, false);
        run_url("https://deadline.test:18445/ok", false, false);
        run_url("http://192.168.4.99:18080/ok", true, false);
    }
    size_t after = heap_caps_get_free_size(MALLOC_CAP_8BIT);
    printf("HEAP before=%u after=%u\n", (unsigned)baseline, (unsigned)after);
    assert(after + 4096 >= baseline);
    run_probe_memory_test();
    puts("HTTP_DEADLINE_INTEGRATION_PASS");
}
