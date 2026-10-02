#ifndef NM_OPENSSL_RUNNER_H
#define NM_OPENSSL_RUNNER_H
#include "tls_inspection.h"
#include <stddef.h>

/* OpenSSL-compatible names at the command boundary; wolfSSL handles remain
 * private. This is a bounded connection-testing subset, not a shell emulator. */
const char *nm_openssl_group_name(const char *name);
size_t nm_openssl_group_count(void);
const char *nm_openssl_group_at(size_t index);
typedef struct {
    const char *host, *group; /* Borrowed for synchronous execution. */
    const char *connect_host;
    unsigned port, timeout_ms;
    bool show_certificates;
    const atomic_bool *cancellation;
} nm_openssl_request;
/* Owns the returned observation; release with nm_tls_inspection_release().
 * Explicit unsupported algorithms fail; never silently use default groups. */
nm_tls_inspection nm_openssl_execute(const nm_openssl_request *request);
#endif
