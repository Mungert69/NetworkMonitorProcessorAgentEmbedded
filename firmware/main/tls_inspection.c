#include "tls_inspection.h"
#include "endpoint_internal.h"
#include "esp_timer.h"
#include <pthread.h>

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

nm_tls_inspection nm_tls_inspect(const nm_tls_inspection_request *request)
{
    if (!request || !request->host || !request->host[0] || request->port > 65535 ||
        (request->mode != NM_TLS_INSPECT_HANDSHAKE && request->mode != NM_TLS_INSPECT_CERTIFICATE))
        return (nm_tls_inspection){.observation.outcome = NM_QUANTUM_ERROR};
    int64_t start = esp_timer_get_time();
    if (request->cancellation && atomic_load(request->cancellation))
        return (nm_tls_inspection){.observation.outcome = NM_QUANTUM_CANCELLED};
    int64_t monotonic_start = nm_quantum_now_ms();
    bool certificate = request->mode == NM_TLS_INSPECT_CERTIFICATE;
    const char *host = request->host;
    const char *destination = request->connect_host ? request->connect_host : host;
    unsigned port = request->port, timeout = request->timeout_ms;
    nm_quantum_tls *tls = get_provider();
    if (!tls || monotonic_start < 0)
        return (nm_tls_inspection){.observation.outcome = NM_QUANTUM_LOCAL_FAILURE,
                                   .elapsed_ms = nm_endpoint_elapsed(start)};
    unsigned remaining = nm_endpoint_remaining(start, timeout);
    if (!remaining)
        return (nm_tls_inspection){.observation.outcome = NM_QUANTUM_TIMEOUT,
                                   .elapsed_ms = nm_endpoint_elapsed(start)};
    struct addrinfo *addresses = NULL;
    lookup_result lookup =
        request->cancellation ? nm_endpoint_resolve_cancelable(destination, port ? port : 443, remaining,
                                                               &addresses, request->cancellation)
                              : nm_endpoint_resolve(destination, port ? port : 443, remaining, &addresses);
    if (lookup != LOOKUP_OK)
        return (nm_tls_inspection){.elapsed_ms = nm_endpoint_elapsed(start),
                                   .observation.outcome =
                                       lookup == LOOKUP_CANCELLED ? NM_QUANTUM_CANCELLED
                                       : lookup == LOOKUP_BUSY || lookup == LOOKUP_NO_MEMORY
                                           ? NM_QUANTUM_LOCAL_FAILURE
                                       : lookup == LOOKUP_TIMEOUT ? NM_QUANTUM_TIMEOUT
                                                                  : NM_QUANTUM_ERROR};
    nm_quantum_result probed =
        request->group ? nm_quantum_tls_probe_group(tls, certificate, host, addresses,
                                                    monotonic_start + timeout,
                                                    request->cancellation, request->group)
        : request->cancellation
            ? nm_quantum_tls_probe_cancelable(tls, certificate, host, addresses,
                                              monotonic_start + timeout, request->cancellation)
            : nm_quantum_tls_probe(tls, certificate, host, addresses, monotonic_start + timeout);
    freeaddrinfo(addresses);
    return (nm_tls_inspection){.observation = probed, .elapsed_ms = nm_endpoint_elapsed(start)};
}

void nm_tls_inspection_release(nm_tls_inspection *result)
{
    if (result)
        nm_quantum_result_free(&result->observation);
}
