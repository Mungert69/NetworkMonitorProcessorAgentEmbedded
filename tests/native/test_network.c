/* Actual production network task steps; only SDK/clock boundaries substituted. */
#include "platform.h"
#include <assert.h>
#include <stdio.h>
#define NM_ESP_H
typedef struct {
    const char *wifi_ssid, *wifi_password;
    bool wifi_setup;
} nm_esp_config;
#define time test_time
#define settimeofday test_settimeofday
#include "../../firmware/main/network.c"
#undef time
#undef settimeofday
static int64_t now_us, saved_clock;
static time_t wall;
static unsigned connects, ntp_inits, ntp_stops, tasks;
static bool init_fail, task_fail, ntp_fail, connect_fail, auto_step, auto_reply;
static void (*sync_callback)(struct timeval *);
time_t test_time(time_t *out)
{
    if (out)
        *out = wall;
    return wall;
}
int test_settimeofday(const struct timeval *tv, const void *zone)
{
    (void)zone;
    wall = tv->tv_sec;
    return 0;
}
int64_t esp_timer_get_time(void)
{
    return now_us;
}
int64_t nm_esp_storage_clock_load(void)
{
    return saved_clock;
}
void vTaskDelay(unsigned ms)
{
    now_us += (int64_t)ms * 1000;
    if (auto_step)
        network_step(now_us);
    if (auto_reply && ntp_active) {
        struct timeval tv = {.tv_sec = 1800000000};
        wall = tv.tv_sec;
        sync_callback(&tv);
    }
}
int xTaskCreate(void (*fn)(void *), const char *name, unsigned stack, void *arg, unsigned priority,
                void *handle)
{
    (void)name;
    (void)arg;
    (void)priority;
    (void)handle;
    assert(fn == network_task && stack == 4096);
    ++tasks;
    return task_fail ? 0 : pdPASS;
}
int nvs_flash_init(void)
{
    return init_fail ? ESP_FAIL : ESP_OK;
}
int esp_netif_init(void)
{
    return ESP_OK;
}
int esp_event_loop_create_default(void)
{
    return ESP_OK;
}
void *esp_netif_create_default_wifi_sta(void)
{
    return &wall;
}
int esp_wifi_init(const wifi_init_config_t *c)
{
    assert(c);
    return ESP_OK;
}
int esp_event_handler_register(esp_event_base_t base, int id,
                               void (*fn)(void *, esp_event_base_t, int32_t, void *), void *arg)
{
    (void)base;
    (void)id;
    (void)arg;
    assert(fn == wifi_event);
    return ESP_OK;
}
int esp_wifi_set_mode(int mode)
{
    assert(mode == WIFI_MODE_STA);
    return ESP_OK;
}
int esp_wifi_set_config(int interface, const wifi_config_t *config)
{
    assert(interface == WIFI_IF_STA && !strcmp(config->sta.ssid, "test"));
    return ESP_OK;
}
int esp_wifi_start(void)
{
    return ESP_OK;
}
int esp_wifi_connect(void)
{
    ++connects;
    return connect_fail ? ESP_FAIL : ESP_OK;
}
int esp_netif_sntp_init(const esp_sntp_config_t *c)
{
    assert(c && !c->wait_for_sync);
    sync_callback = c->sync_cb;
    ++ntp_inits;
    return ntp_fail ? ESP_FAIL : ESP_OK;
}
void esp_netif_sntp_deinit(void)
{
    ++ntp_stops;
}
const char *esp_err_to_name(int error)
{
    (void)error;
    return "mock";
}
static void reset(void)
{
    atomic_store(&online, false);
    atomic_store(&fresh_request, false);
    atomic_store(&sync_generation, 0);
    atomic_store(&correction_available, false);
    atomic_store(&correction_applied, false);
    recording_started = false;
    boot_us = boot_utc = correction_offset = 0;
    retry_index = 0;
    wifi_due = ntp_due = 0;
    ntp_active = false;
    connects = ntp_inits = ntp_stops = tasks = 0;
    now_us = saved_clock = wall = 0;
    init_fail = task_fail = ntp_fail = connect_fail = auto_step = auto_reply = false;
}
static void step(unsigned seconds)
{
    now_us = (int64_t)seconds * 1000000;
    network_step(now_us);
}
int main(void)
{
    nm_esp_config c = {.wifi_ssid = "test", .wifi_password = "password"};
    reset();
    assert(nm_esp_wifi_connect(&c)); /* Offline startup returns without waiting. */
    assert(tasks == 1 && now_us == 0 && wall == 1640995200 && !nm_network_ready());
    connect_fail = true;
    step(0);
    assert(connects == 1);
    wifi_event(NULL, WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, NULL);
    step(4);
    assert(connects == 1); /* Callbacks cannot bypass backoff. */
    step(5);
    assert(connects == 2);
    step(19);
    assert(connects == 2);
    step(20);
    assert(connects == 3);
    step(50);
    assert(connects == 4);
    step(109);
    assert(connects == 4);
    step(110);
    assert(connects == 5);
    wifi_event(NULL, IP_EVENT, IP_EVENT_STA_GOT_IP, NULL);
    step(111);
    assert(ntp_inits == 1 && !nm_network_ready());
    step(126);
    assert(ntp_stops == 1 && !nm_network_ready());
    step(185);
    assert(ntp_inits == 1);
    step(186);
    assert(ntp_inits == 2);
    struct timeval tv = {.tv_sec = 1800000000};
    wall = tv.tv_sec;
    sync_callback(&tv);
    assert(nm_network_time_synced() && !nm_network_ready());
    int64_t offset;
    assert(nm_network_correction(&offset));
    assert(offset == 1800000000 - 1640995200 - 186);
    assert(nm_network_recording_time() == 1640995200 + 186);
    /* NTP changes wall time, but in-flight probes keep the provisional timeline. */
    nm_network_accept_correction();
    assert(nm_network_ready() && nm_network_recording_time() == wall);
    step(187);
    assert(ntp_stops == 2);
    step(247);
    assert(ntp_inits == 2); /* No periodic resync after the one boot event. */
    step(262);
    assert(nm_network_ready());
    wifi_event(NULL, WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, NULL);
    assert(!nm_network_ready() && nm_network_time_synced());
    step(263);
    assert(connects == 6 && retry_index == 1);
    wifi_event(NULL, IP_EVENT, IP_EVENT_STA_GOT_IP, NULL);
    assert(nm_network_ready());
    auto_step = auto_reply = true;
    assert(nm_esp_clock_sync()); /* OTA requires and gets a new reply. */
    auto_reply = false;
    assert(!nm_esp_clock_sync()); /* An old synchronization cannot satisfy OTA. */
    reset();
    saved_clock = 1770000000;
    assert(nm_esp_wifi_connect(&c) && wall == saved_clock && !nm_network_time_synced());
    reset();
    c.wifi_setup = true;
    assert(!nm_esp_wifi_connect(&c) && now_us == 30000000);
    c.wifi_setup = false;
    reset();
    init_fail = true;
    assert(!nm_esp_wifi_connect(&c));
    reset();
    task_fail = true;
    assert(!nm_esp_wifi_connect(&c));
    reset();
    wifi_event(NULL, IP_EVENT, IP_EVENT_STA_GOT_IP, NULL);
    ntp_fail = true;
    step(0);
    step(59);
    assert(ntp_inits == 1 && !nm_network_ready());
    step(60);
    assert(ntp_inits == 2);
    puts("network offline startup/backoff/readiness/NTP recovery/OTA tests passed");
}
