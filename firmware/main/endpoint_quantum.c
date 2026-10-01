#include "endpoint_internal.h"
#include "quantum_tls.h"
#include "esp_timer.h"
#include <pthread.h>
#include <stdio.h>
#include <string.h>

static pthread_mutex_t provider_mutex = PTHREAD_MUTEX_INITIALIZER;
static nm_quantum_tls *provider;
extern const unsigned char roots_start[] asm("_binary_quantum_roots_pem_start");
extern const unsigned char roots_end[] asm("_binary_quantum_roots_pem_end");

/* Initialize on first use, retry on allocation failure. Immutable thereafter;
 * never free process-lifetime trust while probe workers may be using it. */
static nm_quantum_tls *get_provider(void)
{
    if (pthread_mutex_lock(&provider_mutex))
        return NULL;
    if (!provider)
        provider = nm_quantum_tls_new(roots_start, (size_t)(roots_end - roots_start));
    nm_quantum_tls *ready = provider;
    pthread_mutex_unlock(&provider_mutex);
    return ready;
}

nm_esp_result nm_endpoint_check_quantum(const char *host, const char *type, unsigned port,
                                        unsigned timeout)
{
    int64_t start = esp_timer_get_time();
    int64_t monotonic_start = nm_quantum_now_ms();
    bool certificate = !strcmp(type, "quantumcert");
    nm_quantum_tls *tls = get_provider();
    if (!tls || monotonic_start < 0)
        return nm_endpoint_local_failure(nm_endpoint_elapsed(start),
                                         "Quantum TLS provider unavailable");
    unsigned remaining = nm_endpoint_remaining(start, timeout);
    if (!remaining)
        return (nm_esp_result){
            .elapsed_ms = nm_endpoint_elapsed(start), .status = "Timeout", .message = "Timeout"};
    struct addrinfo *addresses = NULL;
    lookup_result lookup = nm_endpoint_resolve(host, port ? port : 443, remaining, &addresses);
    if (lookup != LOOKUP_OK) {
        if (lookup == LOOKUP_BUSY || lookup == LOOKUP_NO_MEMORY)
            return nm_endpoint_local_failure(nm_endpoint_elapsed(start),
                                             "Quantum DNS resources unavailable");
        nm_esp_result failed = {.elapsed_ms = nm_endpoint_elapsed(start)};
        snprintf(failed.status, sizeof(failed.status), "%s",
                 lookup == LOOKUP_TIMEOUT ? "Timeout" : "Exception");
        snprintf(failed.message, sizeof(failed.message), "%s", failed.status);
        return failed;
    }
    nm_quantum_result probed =
        nm_quantum_tls_probe(tls, certificate, host, addresses, monotonic_start + timeout);
    freeaddrinfo(addresses);
    unsigned elapsed = nm_endpoint_elapsed(start);
    if (probed.outcome == NM_QUANTUM_LOCAL_FAILURE) {
        nm_quantum_result_free(&probed);
        return nm_endpoint_local_failure(elapsed, "Quantum TLS local resource failure");
    }
    nm_esp_result result = {.ok = probed.outcome == NM_QUANTUM_OK, .elapsed_ms = elapsed};
    const char *status = probed.outcome == NM_QUANTUM_TIMEOUT ? "Timeout"
                         : probed.outcome == NM_QUANTUM_ERROR ? "Exception"
                         : certificate ? (result.ok ? "Quantum-safe certificate detected"
                                                    : "Certificate not quantum-safe")
                                       : (result.ok ? "Using quantum safe handshake"
                                                    : "Could not negotiate quantum safe handshake");
    snprintf(result.status, sizeof(result.status), "%s", status);
    if (probed.summary) {
        result.detail_message = probed.summary;
        probed.summary = NULL;
    }
    if (probed.error)
        snprintf(result.message, sizeof(result.message), "%s; group=%s; %s error=%d; %.120s",
                 status, probed.group[0] ? probed.group : "none",
                 probed.socket_error ? "socket" : "TLS", probed.error, probed.error_message);
    else if (certificate && result.detail_message)
        snprintf(result.message, sizeof(result.message), "%s; SigAlg=%s; KeyAlg=%s", status,
                 probed.signature_algorithm, probed.key_algorithm);
    else
        snprintf(result.message, sizeof(result.message), "%s; group=%s", status,
                 probed.group[0] ? probed.group : "none");
    nm_quantum_result_free(&probed);
    return result;
}
