/* Real production pool/endpoints with test-only DNS routing/delay. No secrets.
 * Main remains an internal-stack flash writer while PSRAM workers perform I/O. */
#include "nm_probe_pool.h"
#include "esp_heap_caps.h"
#include "esp_memory_utils.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs.h"
#include <assert.h>
#include <netdb.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static atomic_bool release_dns;
static atomic_uint late_dns, checked_probes;
int __real_lwip_getaddrinfo(const char *, const char *, const struct addrinfo *,
                            struct addrinfo **);
int __wrap_lwip_getaddrinfo(const char *host, const char *service, const struct addrinfo *hints,
                            struct addrinfo **out)
{
    if (!strcmp(host, "late.test")) {
        int stack_marker = 0;
        assert(esp_ptr_external_ram(&stack_marker));
        atomic_fetch_add(&late_dns, 1);
        while (!atomic_load(&release_dns))
            vTaskDelay(1);
        atomic_fetch_sub(&late_dns, 1);
        host = "192.168.4.1";
    }
    if (!strcmp(host, "deadline.test") || !strcmp(host, "wrong.test"))
        host = "192.168.4.1";
    return __real_lwip_getaddrinfo(host, service, hints, out);
}

nm_esp_result __real_nm_esp_endpoint_run(const nm_monitor_record *);
nm_esp_result __wrap_nm_esp_endpoint_run(const nm_monitor_record *monitor)
{
    int stack_marker = 0;
    assert(esp_ptr_external_ram(&stack_marker));
    assert(esp_ptr_external_ram(monitor->Address));
    assert(esp_ptr_external_ram(monitor->EndPointType));
    atomic_fetch_add(&checked_probes, 1);
    return __real_nm_esp_endpoint_run(monitor);
}

static void write_snapshot(nvs_handle_t nvs, unsigned sequence)
{
    unsigned char bytes[2048];
    assert(esp_ptr_internal(bytes));
    memset(bytes, (int)(sequence & 255), sizeof(bytes));
    ESP_ERROR_CHECK(nvs_set_blob(nvs, "snapshot", bytes, sizeof(bytes)));
    ESP_ERROR_CHECK(nvs_commit(nvs));
}

static void submit(nm_probe_executor *pool, unsigned id, const char *type, const char *address,
                   unsigned timeout)
{
    nm_monitor_record monitor = {
        .Address = (char *)address, .EndPointType = (char *)type, .Timeout = (int32_t)timeout};
    assert(pool->submit(pool->context, (int32_t)id, 123, &monitor));
}

void run_probe_memory_test(void)
{
    assert(nm_esp_endpoint_configure_limit(4));
    size_t baseline = heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    nm_probe_executor *pool = nm_probe_pool_freertos_create(8);
    assert(pool && esp_ptr_external_ram(pool));
    printf("PROBE_MEMORY pool8 internal_before=%u internal_after=%u psram=%u\n", (unsigned)baseline,
           (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
           (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    nvs_handle_t nvs;
    ESP_ERROR_CHECK(nvs_open("probe_test", NVS_READWRITE, &nvs));
    for (unsigned i = 0; i < 4; ++i)
        submit(pool, i, "dns", "late.test", 150);
    unsigned replies = 0;
    int64_t start = esp_timer_get_time();
    while (replies < 4) {
        nm_probe_reply reply;
        if (pool->poll(pool->context, &reply, 10)) {
            assert(!reply.result.ok);
            ++replies;
        }
        write_snapshot(nvs, replies);
        assert(esp_timer_get_time() - start < 2000000);
    }
    assert(pool->in_flight(pool->context) == 0 && atomic_load(&late_dns) == 4);
    /* Probe completion and NVS must not wait for these deliberately late helpers. */
    submit(pool, 5, "dns", "192.168.4.1", 50);
    nm_probe_reply reply;
    assert(pool->poll(pool->context, &reply, 500));
    assert(reply.result.disposition == NM_PROBE_LOCAL_FAILURE);
    write_snapshot(nvs, 5);
    atomic_store(&release_dns, true);
    while (atomic_load(&late_dns))
        vTaskDelay(1);
    vTaskDelay(pdMS_TO_TICKS(50)); /* permit the internal reaper to run */

    for (unsigned cycle = 0; cycle < 3; ++cycle) {
        unsigned sent = 0, received = 0, writes = 0;
        while (received < 50) {
            while (sent < 50 && pool->in_flight(pool->context) < 8) {
                switch (sent % 5) {
                case 0:
                    submit(pool, sent, "https", "https://deadline.test:18443/ok", 5000);
                    break;
                case 1:
                    submit(pool, sent, "http", "http://192.168.4.1:18080/ok", 5000);
                    break;
                case 2:
                    submit(pool, sent, "dns", "192.168.4.1", 5000);
                    break;
                case 3:
                    submit(pool, sent, "icmp", "192.168.4.1", 5000);
                    break;
                default:
                    submit(pool, sent, "icmp", "192.168.4.99", 100);
                    break;
                }
                ++sent;
            }
            if (pool->poll(pool->context, &reply, 10)) {
                if (reply.result.disposition == NM_PROBE_LOCAL_FAILURE ||
                    reply.result.ok != (reply.monitor_id % 5 != 4))
                    printf("PROBE_MEMORY unexpected id=%ld disposition=%d ok=%d message=%s\n",
                           (long)reply.monitor_id, reply.result.disposition, reply.result.ok,
                           reply.result.message);
                assert(reply.result.disposition != NM_PROBE_LOCAL_FAILURE);
                assert(reply.result.ok == (reply.monitor_id % 5 != 4));
                ++received;
            }
            /* Intentional stress: unlike production, overlap frequent NVS writes
             * with probes, including a late ICMP session after caller timeout. */
            write_snapshot(nvs, ++writes);
        }
        assert(heap_caps_check_integrity_all(true));
        printf("PROBE_MEMORY cycle=%u probes=%u writes=%u internal=%u minimum=%u psram=%u "
               "stack_free=%u\n",
               cycle, received, writes,
               (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
               (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
               (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),
               (unsigned)nm_probe_pool_worker_stack_free(pool));
    }
    nvs_close(nvs);
    pool->destroy(pool->context);
    free(pool);
    vTaskDelay(pdMS_TO_TICKS(200));
    assert(atomic_load(&checked_probes) == 155);
    assert(heap_caps_check_integrity_all(true));
    puts("PROBE_MEMORY_INTEGRATION_PASS");
}
