#ifndef NM_ENDPOINT_INTERNAL_H
#define NM_ENDPOINT_INTERNAL_H
#include "endpoint_status.h"
#include "endpoint_dns_task.h"
#include "freertos/FreeRTOS.h"
#include "nm_esp.h"
#include <netdb.h>
#include <stdatomic.h>
/* Shared endpoint contracts. The resolver transfers its address list to the caller.
 * Workers retain their own context until completion; timeouts never cancel a task. */
typedef enum {
    LOOKUP_OK,
    LOOKUP_EMPTY,
    LOOKUP_ERROR,
    LOOKUP_TIMEOUT,
    LOOKUP_BUSY,
    LOOKUP_NO_MEMORY,
    LOOKUP_CANCELLED
} lookup_result;
unsigned nm_endpoint_elapsed(int64_t start);
unsigned nm_endpoint_remaining(int64_t start, unsigned timeout);
TickType_t nm_endpoint_wait_ticks(unsigned milliseconds);
/* One device-wide DNS/ICMP lifetime budget, including late completions.
 * Every acquired slot must be released exactly once, by completion or startup failure. */
void nm_endpoint_release_slot(void);
/* Wait within the caller's original deadline; never create extra late workers. */
bool nm_endpoint_wait_slot(int64_t start, unsigned timeout);
nm_esp_result nm_endpoint_result(const char *, nm_endpoint_outcome, int, unsigned, const char *);
nm_esp_result nm_endpoint_local_failure(unsigned milliseconds, const char *detail);
lookup_result nm_endpoint_resolve(const char *, unsigned, unsigned, struct addrinfo **);
lookup_result nm_endpoint_resolve_cancelable(const char *, unsigned, unsigned, struct addrinfo **,
                                             const atomic_bool *);
nm_esp_result nm_endpoint_lookup_failure(const char *, lookup_result, unsigned);
bool nm_endpoint_address_text(const struct addrinfo *, char *, size_t);
nm_esp_result nm_endpoint_check_icmp(const char *, unsigned);
nm_esp_result nm_endpoint_check_icmp_cancelable(const char *, unsigned, const atomic_bool *);
nm_esp_result nm_endpoint_check_dns(const char *, unsigned);
nm_esp_result nm_endpoint_check_tcp(const char *, unsigned, unsigned);
nm_esp_result nm_endpoint_check_nmap(const char *, unsigned, unsigned);
nm_esp_result nm_endpoint_check_http(const char *, const char *, unsigned, unsigned);
nm_esp_result nm_endpoint_check_quantum(const char *, const char *, unsigned, unsigned);
nm_esp_result nm_endpoint_check_ble(const nm_monitor_record *, uint64_t);
#endif
