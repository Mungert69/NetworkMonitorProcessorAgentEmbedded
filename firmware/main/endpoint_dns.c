#include "endpoint_internal.h"
#include "nm_memory.h"
#include "esp_timer.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* getaddrinfo cannot safely be cancelled in lwIP. A bounded worker retains
 * its own reference and a COPY of all inputs, even if the caller times out.
 * No task is forcibly deleted; the worker eventually frees its own results.
 * DNS shares the device-wide outstanding-operation budget with ICMP, so a stalled
 * resolver cannot cause unbounded task/heap growth across monitor cycles. */
typedef struct {
    atomic_uint references;
    SemaphoreHandle_t done;
    char host[1025];
    char service[6];
    struct addrinfo *addresses;
    int error;
} dns_context;

static void dns_release(dns_context *context)
{
    if (atomic_fetch_sub(&context->references, 1) == 1) {
        if (context->addresses)
            freeaddrinfo(context->addresses);
        vSemaphoreDelete(context->done);
        free(context);
    }
}

static void dns_worker(void *arg)
{
    dns_context *context = arg;
    struct addrinfo hints = {.ai_socktype = SOCK_STREAM, .ai_family = AF_UNSPEC};
    context->error = getaddrinfo(context->host, *context->service ? context->service : NULL, &hints,
                                 &context->addresses);
    xSemaphoreGive(context->done);
    dns_release(context);
    nm_dns_task_finish();
}

lookup_result nm_endpoint_resolve(const char *host, unsigned port, unsigned timeout,
                                  struct addrinfo **addresses)
{
    return nm_endpoint_resolve_cancelable(host, port, timeout, addresses, NULL);
}

lookup_result nm_endpoint_resolve_cancelable(const char *host, unsigned port, unsigned timeout,
    struct addrinfo **addresses, const atomic_bool *cancellation)
{
    *addresses = NULL;
    if (!host || strlen(host) > 1024 || port > 65535)
        return LOOKUP_ERROR;
    if (!timeout)
        return LOOKUP_TIMEOUT;
    int64_t start = esp_timer_get_time();
    if (!cancellation) {
        if (!nm_endpoint_wait_slot(start, timeout)) return LOOKUP_BUSY;
    } else {
        for (;;) {
            if (atomic_load(cancellation)) return LOOKUP_CANCELLED;
            unsigned remaining = nm_endpoint_remaining(start, timeout);
            if (!remaining) return LOOKUP_BUSY;
            if (nm_endpoint_wait_slot(esp_timer_get_time(), remaining > 100 ? 100 : remaining)) break;
        }
    }
    dns_context *context = nm_bulk_calloc(1, sizeof(*context));
    if (!context) {
        nm_endpoint_release_slot();
        return LOOKUP_NO_MEMORY;
    }
    context->done = xSemaphoreCreateBinary();
    if (!context->done) {
        free(context);
        nm_endpoint_release_slot();
        return LOOKUP_NO_MEMORY;
    }
    atomic_init(&context->references, 2); /* caller + worker */
    snprintf(context->host, sizeof(context->host), "%s", host);
    if (port)
        snprintf(context->service, sizeof(context->service), "%u", (unsigned)(uint16_t)port);
    if (!nm_dns_task_start(dns_worker, context)) {
        dns_release(context);
        dns_release(context);
        nm_endpoint_release_slot();
        return LOOKUP_NO_MEMORY;
    }
    unsigned budget = nm_endpoint_remaining(start, timeout);
    lookup_result result = LOOKUP_TIMEOUT;
    bool completed = false;
    while (budget) {
        if (cancellation && atomic_load(cancellation)) { result = LOOKUP_CANCELLED; break; }
        unsigned slice = cancellation && budget > 100 ? 100 : budget;
        if (xSemaphoreTake(context->done, nm_endpoint_wait_ticks(slice)) == pdTRUE) {
            completed = true;
            break;
        }
        if (!cancellation) break;
        budget = nm_endpoint_remaining(start, timeout);
    }
    if (completed) {
        result = context->error ? LOOKUP_ERROR : context->addresses ? LOOKUP_OK : LOOKUP_EMPTY;
        if (context->error == EAI_MEMORY)
            result = LOOKUP_NO_MEMORY;
        if (result == LOOKUP_OK) {
            *addresses = context->addresses;
            context->addresses = NULL; /* transfer only after completion */
        }
    }
    dns_release(context);
    return result;
}

nm_esp_result nm_endpoint_lookup_failure(const char *type, lookup_result lookup, unsigned ms)
{
    if (lookup == LOOKUP_BUSY || lookup == LOOKUP_NO_MEMORY)
        return nm_endpoint_local_failure(ms, lookup == LOOKUP_BUSY
                                                 ? "Shared DNS/ICMP operation budget busy"
                                                 : "DNS allocation failed");
    const char *detail = lookup == LOOKUP_TIMEOUT ? "Timeout while resolving host address"
                         : lookup == LOOKUP_EMPTY ? "No IP addresses found for host"
                         : lookup == LOOKUP_BUSY  ? "DNS resolver busy"
                                                  : "DNS lookup failed";
    if (lookup == LOOKUP_EMPTY && !strcmp(type, "rawconnect"))
        detail = "Unable to resolve domain.";
    /* SocketConnect's DNS exceptions use Exception, not its connect timeout. */
    return nm_endpoint_result(
        type, lookup == LOOKUP_EMPTY ? NM_ENDPOINT_NO_ADDRESSES : NM_ENDPOINT_EXCEPTION, 0, ms,
        detail);
}

nm_esp_result nm_endpoint_check_dns(const char *host, unsigned timeout)
{
    struct addrinfo *addresses = NULL;
    int64_t start = esp_timer_get_time();
    lookup_result lookup = nm_endpoint_resolve(host, 0, timeout, &addresses);
    if (lookup != LOOKUP_OK)
        return nm_endpoint_lookup_failure("dns", lookup, nm_endpoint_elapsed(start));
    nm_esp_result result =
        nm_endpoint_result("dns", NM_ENDPOINT_SUCCESS, 0, nm_endpoint_elapsed(start), NULL);
    /* ProcessStatus adds a space before extraData, which itself starts " : ". */
    size_t used = (size_t)snprintf(result.message, sizeof(result.message), "%s  : ", result.status);
    bool first = true;
    for (const struct addrinfo *item = addresses; item; item = item->ai_next) {
        char numeric[48];
        if (!nm_endpoint_address_text(item, numeric, sizeof(numeric)))
            continue;
        int count = snprintf(result.message + used, sizeof(result.message) - used, "%s%s",
                             first ? "" : ", ", numeric);
        if (count < 0 || (size_t)count >= sizeof(result.message) - used)
            break;
        used += (size_t)count;
        first = false;
    }
    freeaddrinfo(addresses);
    return result;
}
