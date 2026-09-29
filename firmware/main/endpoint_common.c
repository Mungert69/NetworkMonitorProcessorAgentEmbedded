#include "endpoint_internal.h"
#include "probe_config.h"
#include "esp_timer.h"
#include "freertos/task.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

unsigned nm_endpoint_elapsed(int64_t start)
{
    int64_t delta = esp_timer_get_time() - start;
    return delta < 0 ? 0 : delta / 1000 > UINT32_MAX ? UINT32_MAX : (unsigned)(delta / 1000);
}

unsigned nm_endpoint_remaining(int64_t start, unsigned timeout)
{
    unsigned spent = nm_endpoint_elapsed(start);
    return spent < timeout ? timeout - spent : 0;
}

TickType_t nm_endpoint_wait_ticks(unsigned milliseconds)
{
    TickType_t ticks = pdMS_TO_TICKS(milliseconds);
    /* Round up, including sub-tick timeouts. */
    return ticks < portMAX_DELAY - 1 ? ticks + 1 : portMAX_DELAY - 1;
}

nm_esp_result nm_endpoint_result(const char *type, nm_endpoint_outcome event, int code,
                                 unsigned milliseconds, const char *detail)
{
    nm_endpoint_status_result mapped = nm_endpoint_status(type, event, code, milliseconds);
    nm_esp_result result = {.ok = mapped.ok, .elapsed_ms = milliseconds};
    snprintf(result.status, sizeof(result.status), "%s", mapped.status);
    if (result.ok) {
        snprintf(result.message, sizeof(result.message), "%s", mapped.status);
    } else {
        char upper[16] = "ENDPOINT";
        if (nm_esp_endpoint_supported(type)) {
            size_t i = 0;
            for (; type[i] && i + 1 < sizeof(upper); ++i)
                upper[i] =
                    (char)(type[i] >= 'a' && type[i] <= 'z' ? type[i] - ('a' - 'A') : type[i]);
            upper[i] = 0;
        }
        snprintf(result.message, sizeof(result.message), "%s: Failed to connect: %s", upper,
                 detail ? detail : mapped.status);
    }
    return result;
}

nm_esp_result nm_endpoint_local_failure(unsigned milliseconds, const char *detail)
{
    nm_esp_result result = {.disposition = NM_PROBE_LOCAL_FAILURE, .elapsed_ms = milliseconds};
    snprintf(result.status, sizeof(result.status), "%s", "LocalResourceFailure");
    snprintf(result.message, sizeof(result.message), "%s", detail);
    return result;
}

static atomic_uint outstanding_operations;
static unsigned operation_limit = NM_ENDPOINT_DEFAULT_OPERATIONS;

bool nm_esp_endpoint_configure_limit(unsigned limit)
{
    /* Startup-only contract: no concurrent probes/configuration calls allowed. */
    if (!limit || limit > NM_ENDPOINT_MAX_OPERATIONS || atomic_load(&outstanding_operations))
        return false;
    if (!nm_dns_tasks_init())
        return false;
    operation_limit = limit;
    return true;
}

void nm_endpoint_release_slot(void)
{
    atomic_fetch_sub(&outstanding_operations, 1);
}

static bool nm_endpoint_reserve(void)
{
    unsigned count = atomic_load(&outstanding_operations);
    while (count < operation_limit) {
        if (atomic_compare_exchange_weak(&outstanding_operations, &count, count + 1))
            return true;
    }
    return false;
}

bool nm_endpoint_wait_slot(int64_t start, unsigned timeout)
{
    while (nm_endpoint_remaining(start, timeout)) {
        if (nm_endpoint_reserve())
            return true;
        vTaskDelay(1);
    }
    return false;
}

bool nm_endpoint_address_text(const struct addrinfo *address, char *out, size_t size)
{
    if (address->ai_family == AF_INET)
        return inet_ntop(AF_INET, &((struct sockaddr_in *)address->ai_addr)->sin_addr, out, size) !=
               NULL;
#if LWIP_IPV6
    if (address->ai_family == AF_INET6)
        return inet_ntop(AF_INET6, &((struct sockaddr_in6 *)address->ai_addr)->sin6_addr, out,
                         size) != NULL;
#endif
    return false;
}
