#ifndef NM_OPENSSL_RUNNER_H
#define NM_OPENSSL_RUNNER_H
#include "tls_inspection.h"
#include <stddef.h>

/* OpenSSL-compatible names at the command boundary; wolfSSL handles remain
 * private. This is a bounded connection-testing subset, not a shell emulator. */
const char *nm_openssl_group_name(const char *name);
size_t nm_openssl_group_count(void);
const char *nm_openssl_group_at(size_t index);
/* Exact enabled TLS 1.3 suite names, not OpenSSL's cipher expression language. */
bool nm_openssl_ciphers_valid(const char *list);
const char *nm_openssl_ciphers(void);
bool nm_openssl_tls12_ciphers_valid(const char *list);
const char *nm_openssl_tls12_ciphers(void);
const char *nm_openssl_cipher_name(const char *provider_name); /* Borrowed mapping, or input. */
typedef struct {
    const char *host, *group; /* Borrowed for synchronous execution. */
    const char *connect_host;
    unsigned port, timeout_ms;
    bool show_certificates;
    const atomic_bool *cancellation;
    const nm_tls_diagnostic_options *diagnostics;
} nm_openssl_request;
/* Owns the returned observation; release with nm_tls_inspection_release().
 * Explicit unsupported algorithms fail; never silently use default groups. */
nm_tls_inspection nm_openssl_execute(const nm_openssl_request *request);
#endif
