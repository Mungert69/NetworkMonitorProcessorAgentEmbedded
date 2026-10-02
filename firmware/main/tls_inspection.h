#ifndef NM_TLS_INSPECTION_H
#define NM_TLS_INSPECTION_H
#include "quantum_tls.h"
#include <stdatomic.h>
typedef enum { NM_TLS_INSPECT_HANDSHAKE, NM_TLS_INSPECT_CERTIFICATE } nm_tls_inspection_mode;
typedef struct {
    /* Borrowed for this synchronous call; port zero means 443. */
    const char *host;
    unsigned port, timeout_ms;
    nm_tls_inspection_mode mode;
    const atomic_bool *cancellation; /* Optional, borrowed through completion. */
    const char *group;               /* Optional canonical OpenSSL group, borrowed. */
    const char *connect_host; /* Optional DNS destination; host remains SNI/verification identity. */
} nm_tls_inspection_request;
typedef struct {
    nm_quantum_result observation;
    unsigned elapsed_ms;
} nm_tls_inspection;
/* No SDK/wolfSSL handles or extra task. One deadline covers setup/DNS/TCP/TLS.
 * Shared immutable trust initialization is serialized; sessions are per-call.
 * Certificate mode observes only; NEVER use it for application traffic.
 * Result owns observation.summary: release once, or null after transfer. */
nm_tls_inspection nm_tls_inspect(const nm_tls_inspection_request *request);
void nm_tls_inspection_release(nm_tls_inspection *result);
#endif
