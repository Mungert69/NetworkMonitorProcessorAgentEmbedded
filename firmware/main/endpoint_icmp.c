#include "endpoint_internal.h"
#include "nm_memory.h"
#include "esp_timer.h"
#include "freertos/semphr.h"
#include "ping/ping_sock.h"
#include <stdlib.h>

typedef struct {
    atomic_uint references;
    SemaphoreHandle_t done;
    bool success;
    unsigned round_trip_ms;
} ping_context;

static void ping_release(ping_context *context)
{
    if (atomic_fetch_sub(&context->references, 1) == 1) {
        vSemaphoreDelete(context->done);
        free(context);
    }
}

static void ping_success(esp_ping_handle_t handle, void *arg)
{
    ping_context *context = arg;
    uint32_t time_ms = 0;
    context->success =
        esp_ping_get_profile(handle, ESP_PING_PROF_TIMEGAP, &time_ms, sizeof(time_ms)) == ESP_OK;
    context->round_trip_ms = time_ms;
}

static void ping_done(esp_ping_handle_t handle, void *arg)
{
    ping_context *context = arg;
    /* Only the end callback deletes a started session. IDF deletion is
     * asynchronous; deleting it in the waiter would not stop late callbacks.
     * After on_ping_end IDF never accesses cb_args again for this session. */
    esp_ping_delete_session(handle);
    xSemaphoreGive(context->done);
    ping_release(context); /* caller may already have timed out */
    nm_endpoint_release_slot();
}

static nm_esp_result ping_once(const ip_addr_t *address, unsigned timeout,
                               const atomic_bool *cancellation)
{
    int64_t start = esp_timer_get_time();
    bool admitted = false;
    while (nm_endpoint_remaining(start, timeout)) {
        if (cancellation && atomic_load(cancellation))
            return nm_endpoint_local_failure(nm_endpoint_elapsed(start), "ICMP cancelled");
        unsigned remaining = nm_endpoint_remaining(start, timeout);
        unsigned slice = cancellation && remaining > 100 ? 100 : remaining;
        if (nm_endpoint_wait_slot(esp_timer_get_time(), slice)) {
            admitted = true;
            break;
        }
        if (!cancellation)
            break;
    }
    if (!admitted)
        return nm_endpoint_local_failure(nm_endpoint_elapsed(start),
                                         "Shared DNS/ICMP operation budget busy");
    ping_context *context = nm_bulk_calloc(1, sizeof(*context));
    if (!context) {
        nm_endpoint_release_slot();
        return nm_endpoint_local_failure(0, "Unable to allocate ping context");
    }
    context->done = xSemaphoreCreateBinary();
    if (!context->done) {
        free(context);
        nm_endpoint_release_slot();
        return nm_endpoint_local_failure(0, "Unable to allocate ping semaphore");
    }
    atomic_init(&context->references, 2); /* caller + end callback */
    esp_ping_config_t config = ESP_PING_DEFAULT_CONFIG();
    config.count = 1;
    config.interval_ms = 0;
    config.timeout_ms = nm_endpoint_remaining(start, timeout);
    config.target_addr = *address;
    esp_ping_callbacks_t callbacks = {
        .cb_args = context, .on_ping_success = ping_success, .on_ping_end = ping_done};
    esp_ping_handle_t handle = NULL;
    if (!config.timeout_ms) {
        ping_release(context);
        ping_release(context);
        nm_endpoint_release_slot();
        return nm_endpoint_local_failure(nm_endpoint_elapsed(start), "ICMP admission deadline");
    }
    esp_err_t error = esp_ping_new_session(&config, &callbacks, &handle);
    if (error == ESP_OK)
        error = esp_ping_start(handle);
    if (error != ESP_OK) {
        /* Neither failed creation nor failed start schedules callbacks. */
        if (handle)
            esp_ping_delete_session(handle);
        ping_release(context);
        ping_release(context);
        nm_endpoint_release_slot();
        if (error == ESP_ERR_NO_MEM)
            return nm_endpoint_local_failure(nm_endpoint_elapsed(start),
                                             "Unable to allocate ping session");
        return nm_endpoint_result("icmp", NM_ENDPOINT_EXCEPTION, 0, nm_endpoint_elapsed(start),
                                  esp_err_to_name(error));
    }
    nm_esp_result result = nm_endpoint_result("icmp", NM_ENDPOINT_TIMEOUT, 0, timeout, "TimedOut");
    unsigned budget = nm_endpoint_remaining(start, timeout);
    while (budget) {
        if (cancellation && atomic_load(cancellation)) {
            result = nm_endpoint_local_failure(nm_endpoint_elapsed(start), "ICMP cancelled");
            break;
        }
        unsigned slice = cancellation && budget > 100 ? 100 : budget;
        if (xSemaphoreTake(context->done, nm_endpoint_wait_ticks(slice)) == pdTRUE) {
            result = nm_endpoint_result(
                "icmp", context->success ? NM_ENDPOINT_SUCCESS : NM_ENDPOINT_TIMEOUT, 0,
                context->success ? context->round_trip_ms : nm_endpoint_elapsed(start), "TimedOut");
            break;
        }
        if (!cancellation)
            break;
        budget = nm_endpoint_remaining(start, timeout);
    }
    /* Do not touch handle: ping_done may already have deleted the session. */
    ping_release(context);
    return result;
}

nm_esp_result nm_endpoint_check_icmp(const char *host, unsigned timeout)
{
    return nm_endpoint_check_icmp_cancelable(host, timeout, NULL);
}

nm_esp_result nm_endpoint_check_icmp_cancelable(const char *host, unsigned timeout,
                                                const atomic_bool *cancellation)
{
    if (cancellation && atomic_load(cancellation))
        return nm_endpoint_local_failure(0, "ICMP cancelled");
    ip_addr_t address;
    if (ipaddr_aton(host, &address))
        return ping_once(&address, timeout, cancellation);
    int64_t start = esp_timer_get_time();
    struct addrinfo *addresses = NULL;
    lookup_result lookup =
        nm_endpoint_resolve_cancelable(host, 0, timeout, &addresses, cancellation);
    if (lookup != LOOKUP_OK)
        return nm_endpoint_lookup_failure("icmp", lookup, nm_endpoint_elapsed(start));
    nm_esp_result result =
        nm_endpoint_result("icmp", NM_ENDPOINT_EXCEPTION, 0, nm_endpoint_elapsed(start),
                           "No supported address family");
    /* Intentionally improve on .NET's first-address behavior: retain IPv6
     * support and try later addresses when an earlier family cannot connect. */
    for (const struct addrinfo *item = addresses; item; item = item->ai_next) {
        char numeric[48]; /* enough for an IPv6 presentation plus NUL */
        if (!nm_endpoint_address_text(item, numeric, sizeof(numeric)) ||
            !ipaddr_aton(numeric, &address))
            continue;
        unsigned budget = nm_endpoint_remaining(start, timeout);
        if (!budget) {
            result = nm_endpoint_result("icmp", NM_ENDPOINT_TIMEOUT, 0, nm_endpoint_elapsed(start),
                                        "TimedOut");
            break;
        }
        result = ping_once(&address, budget, cancellation);
        if (result.ok || result.disposition == NM_PROBE_LOCAL_FAILURE)
            break;
    }
    freeaddrinfo(addresses);
    return result;
}
