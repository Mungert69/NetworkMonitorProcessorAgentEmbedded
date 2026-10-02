#ifndef NM_QUANTUM_TLS_H
#define NM_QUANTUM_TLS_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
struct addrinfo;
typedef struct nm_quantum_tls nm_quantum_tls;
typedef enum {
    NM_QUANTUM_OK,
    NM_QUANTUM_NEGATIVE,
    NM_QUANTUM_TIMEOUT,
    NM_QUANTUM_ERROR,
    NM_QUANTUM_LOCAL_FAILURE,
    NM_QUANTUM_CANCELLED
} nm_quantum_outcome;
typedef struct {
    nm_quantum_outcome outcome;
    int error;
    /* Socket errors are errno values; TLS errors use wolfSSL's namespace. */
    bool socket_error;
    char error_message[128];
    char group[64];
    char protocol[24], cipher[128];
    char alpn[256];
    char *certificate_pem; /* Owned presented chain, or NULL; released with summary. */
    char signature_algorithm[48], key_algorithm[48];
    bool certificate_trusted;
    int signature_oid, key_oid;
    /* Owned diagnostic, free()-compatible. Released by result_free. */
    char *summary;
} nm_quantum_result;
/* Copies trusted public PEM certificates. Create before concurrent use; free
 * only after all probes drain. No per-probe global wolfSSL initialization or
 * cleanup. The immutable provider may be shared by probe workers. */
nm_quantum_tls *nm_quantum_tls_new(const unsigned char *pem, size_t length);
void nm_quantum_tls_free(nm_quantum_tls *provider);
/* Addresses and host are borrowed for this synchronous call. DNS is done by
 * the caller's bounded resolver. Deadline is CLOCK_MONOTONIC milliseconds and
 * includes DNS, TCP and TLS; crypto calls are not hard-real-time preemptible.
 * Certificate mode observes the presented leaf like .NET's -showcerts probe;
 * CA trust, expiry and hostname are not classification criteria. This mode
 * must never be used for authenticated application traffic. */
nm_quantum_result nm_quantum_tls_probe(nm_quantum_tls *provider, bool certificate, const char *host,
                                       const struct addrinfo *addresses, int64_t deadline_ms);
void nm_quantum_result_free(nm_quantum_result *result);
nm_quantum_result nm_quantum_tls_probe_cancelable(nm_quantum_tls *provider, bool certificate,
                                                  const char *host,
                                                  const struct addrinfo *addresses,
                                                  int64_t deadline_ms,
                                                  const atomic_bool *cancellation);
/* Optional OpenSSL-style group name. NULL preserves the endpoint defaults.
 * Unknown/uncompiled groups fail without starting a socket. */
nm_quantum_result nm_quantum_tls_probe_group(nm_quantum_tls *provider, bool certificate,
                                             const char *host, const struct addrinfo *addresses,
                                             int64_t deadline_ms, const atomic_bool *cancellation,
                                             const char *group);
int64_t nm_quantum_now_ms(void);
/* Optional diagnostic controls, borrowed for synchronous execution. NULL keeps
 * the existing quantum endpoint policy. No provider/global context mutation. */
typedef struct {
    const char *ciphersuites, *alpn, *verify_host;
    bool no_sni, explicit_sni, certificate_details, export_chain;
    int address_family;   /* 0 = any, 4 = IPv4, 6 = IPv6. */
    unsigned tls_version; /* 0/13 = TLS 1.3, 12 = TLS 1.2 diagnostics. */
} nm_tls_diagnostic_options;
nm_quantum_result nm_quantum_tls_probe_options(nm_quantum_tls *provider, bool certificate,
                                               const char *host, const struct addrinfo *addresses,
                                               int64_t deadline_ms, const atomic_bool *cancellation,
                                               const char *group,
                                               const nm_tls_diagnostic_options *options);
#endif
