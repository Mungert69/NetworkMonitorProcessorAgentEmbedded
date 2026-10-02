#define _POSIX_C_SOURCE 200809L
#include "endpoint_internal.h"
#include "quantum_tls.h"
#include "tls_inspection.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

const unsigned char _binary_quantum_roots_pem_start[] = "test";
__asm__(".global _binary_quantum_roots_pem_end\n"
        ".set _binary_quantum_roots_pem_end, _binary_quantum_roots_pem_start + 4");
static int64_t clock_us;
static bool fail_provider, cert_seen;
static unsigned port_seen, timeout_seen, frees;
static lookup_result lookup = LOOKUP_OK;
static nm_quantum_outcome outcome;
static int64_t deadline_seen;
int64_t esp_timer_get_time(void)
{
    return clock_us;
}
int64_t nm_quantum_now_ms(void)
{
    return clock_us / 1000;
}
unsigned nm_endpoint_elapsed(int64_t start)
{
    return (unsigned)((clock_us - start) / 1000);
}
unsigned nm_endpoint_remaining(int64_t start, unsigned timeout)
{
    unsigned elapsed = nm_endpoint_elapsed(start);
    return elapsed < timeout ? timeout - elapsed : 0;
}
nm_quantum_tls *nm_quantum_tls_new(const unsigned char *pem, size_t length)
{
    assert(pem && length == 4);
    return fail_provider ? NULL : (nm_quantum_tls *)(void *)pem;
}
lookup_result nm_endpoint_resolve(const char *host, unsigned port, unsigned timeout,
                                  struct addrinfo **out)
{
    assert(!strcmp(host, "example.com"));
    port_seen = port;
    timeout_seen = timeout;
    clock_us += 20000;
    if (lookup == LOOKUP_OK) {
        *out = calloc(1, sizeof(**out));
        assert(*out);
    }
    return lookup;
}
void freeaddrinfo(struct addrinfo *address)
{
    assert(address);
    free(address);
    ++frees;
}
nm_quantum_result nm_quantum_tls_probe(nm_quantum_tls *p, bool cert, const char *host,
                                       const struct addrinfo *addresses, int64_t deadline)
{
    assert(p && addresses && host);
    cert_seen = cert;
    deadline_seen = deadline;
    clock_us += 30000;
    nm_quantum_result r = {.outcome = outcome};
    if (outcome == NM_QUANTUM_ERROR) {
        r.error = EHOSTUNREACH;
        r.socket_error = true;
        snprintf(r.error_message, sizeof(r.error_message), "Host is unreachable");
    }
    if (cert && (outcome == NM_QUANTUM_OK || outcome == NM_QUANTUM_NEGATIVE)) {
        snprintf(r.signature_algorithm, sizeof(r.signature_algorithm), "ML-DSA-65");
        snprintf(r.key_algorithm, sizeof(r.key_algorithm), "ML-DSA-65");
        r.summary = strdup("Certificate PQC: yes");
        assert(r.summary);
    }
    return r;
}
void nm_quantum_result_free(nm_quantum_result *result)
{
    free(result->summary);
    result->summary = NULL;
}
lookup_result nm_endpoint_resolve_cancelable(const char *host, unsigned port, unsigned timeout,
                                             struct addrinfo **out, const atomic_bool *cancellation)
{
    if (cancellation && atomic_load(cancellation))
        return LOOKUP_CANCELLED;
    return nm_endpoint_resolve(host, port, timeout, out);
}
nm_quantum_result nm_quantum_tls_probe_cancelable(nm_quantum_tls *p, bool cert, const char *host,
                                                  const struct addrinfo *addresses,
                                                  int64_t deadline, const atomic_bool *cancellation)
{
    if (cancellation && atomic_load(cancellation))
        return (nm_quantum_result){.outcome = NM_QUANTUM_CANCELLED};
    return nm_quantum_tls_probe(p, cert, host, addresses, deadline);
}
nm_quantum_result nm_quantum_tls_probe_group(nm_quantum_tls *p, bool cert, const char *host,
                                             const struct addrinfo *addresses, int64_t deadline,
                                             const atomic_bool *cancel, const char *group)
{
    assert(group);
    return nm_quantum_tls_probe_cancelable(p, cert, host, addresses, deadline, cancel);
}
nm_esp_result nm_endpoint_local_failure(unsigned elapsed, const char *detail)
{
    nm_esp_result r = {.elapsed_ms = elapsed, .disposition = NM_PROBE_LOCAL_FAILURE};
    snprintf(r.message, sizeof(r.message), "%s", detail);
    return r;
}

int main(void)
{
    nm_tls_inspection invalid = nm_tls_inspect(NULL);
    assert(invalid.observation.outcome == NM_QUANTUM_ERROR);
    nm_tls_inspection_release(&invalid);
    nm_tls_inspection_request bad = {.host = "example.com", .port = 443};
    bad.mode = (nm_tls_inspection_mode)99;
    invalid = nm_tls_inspect(&bad);
    assert(invalid.observation.outcome == NM_QUANTUM_ERROR && frees == 0);
    nm_tls_inspection_release(&invalid);
    bad.port = 65536;
    bad.mode = NM_TLS_INSPECT_HANDSHAKE;
    invalid = nm_tls_inspect(&bad);
    assert(invalid.observation.outcome == NM_QUANTUM_ERROR && frees == 0);
    nm_tls_inspection_release(&invalid);
    fail_provider = true;
    nm_esp_result r = nm_endpoint_check_quantum("example.com", "quantum", 0, 100);
    assert(r.disposition == NM_PROBE_LOCAL_FAILURE && !r.ok);
    fail_provider = false;
    clock_us = 1000000;
    nm_tls_inspection_request expired = {
        .host = "example.com", .mode = NM_TLS_INSPECT_HANDSHAKE, .timeout_ms = 0};
    nm_tls_inspection timed = nm_tls_inspect(&expired);
    assert(timed.observation.outcome == NM_QUANTUM_TIMEOUT && frees == 0);
    nm_tls_inspection_release(&timed);
    for (unsigned cert = 0; cert < 2; ++cert) {
        for (outcome = NM_QUANTUM_OK; outcome <= NM_QUANTUM_LOCAL_FAILURE; ++outcome) {
            clock_us = 1000000;
            r = nm_endpoint_check_quantum("example.com", cert ? "quantumcert" : "quantum", 0, 100);
            assert(cert_seen == (bool)cert && port_seen == 443 && timeout_seen == 100);
            assert(deadline_seen == 1100 && r.elapsed_ms == 50);
            assert(r.ok == (outcome == NM_QUANTUM_OK));
            if (outcome == NM_QUANTUM_OK || outcome == NM_QUANTUM_NEGATIVE) {
                assert(!strstr(r.message, "error="));
                if (cert) {
                    assert(strstr(r.message, "SigAlg=ML-DSA-65"));
                    assert(strstr(r.message, "KeyAlg=ML-DSA-65"));
                    assert(!strstr(r.message, "group="));
                }
            }
            assert(r.disposition == (outcome == NM_QUANTUM_LOCAL_FAILURE ? NM_PROBE_LOCAL_FAILURE
                                                                         : NM_PROBE_OBSERVATION));
            if (outcome == NM_QUANTUM_TIMEOUT)
                assert(!strcmp(r.status, "Timeout"));
            else if (outcome == NM_QUANTUM_ERROR) {
                assert(!strcmp(r.status, "Exception"));
                assert(strstr(r.message, "socket error="));
                assert(strstr(r.message, "Host is unreachable"));
                assert(!r.detail_message);
            } else if (outcome != NM_QUANTUM_LOCAL_FAILURE)
                assert(!strcmp(r.status,
                               cert ? (r.ok ? "Quantum-safe certificate detected"
                                            : "Certificate not quantum-safe")
                                    : (r.ok ? "Using quantum safe handshake"
                                            : "Could not negotiate quantum safe handshake")));
            if (cert && (outcome == NM_QUANTUM_OK || outcome == NM_QUANTUM_NEGATIVE))
                assert(r.detail_message);
            nm_esp_result_release(&r);
        }
    }
    assert(frees == 10);
    for (lookup = LOOKUP_EMPTY; lookup <= LOOKUP_NO_MEMORY; ++lookup) {
        r = nm_endpoint_check_quantum("example.com", "quantum", 9443, 100);
        assert(!r.ok && port_seen == 9443);
        assert(r.disposition == (lookup == LOOKUP_BUSY || lookup == LOOKUP_NO_MEMORY
                                     ? NM_PROBE_LOCAL_FAILURE
                                     : NM_PROBE_OBSERVATION));
        if (lookup == LOOKUP_TIMEOUT)
            assert(!strcmp(r.status, "Timeout"));
        nm_esp_result_release(&r);
    }
    puts("Quantum .NET statuses, shared deadline, ownership and local-failure adapter checks "
         "passed");
    return 0;
}
