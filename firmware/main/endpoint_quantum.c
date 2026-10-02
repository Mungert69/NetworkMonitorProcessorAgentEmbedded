#include "endpoint_internal.h"
#include "tls_inspection.h"
#include <stdio.h>
#include <string.h>

nm_esp_result nm_endpoint_check_quantum(const char *host, const char *type, unsigned port,
                                        unsigned timeout)
{
    bool certificate = !strcmp(type, "quantumcert");
    nm_tls_inspection_request request = {.host = host,
                                         .port = port,
                                         .timeout_ms = timeout,
                                         .mode = certificate ? NM_TLS_INSPECT_CERTIFICATE
                                                             : NM_TLS_INSPECT_HANDSHAKE};
    nm_tls_inspection inspection = nm_tls_inspect(&request);
    nm_quantum_result probed = inspection.observation;
    unsigned elapsed = inspection.elapsed_ms;
    if (probed.outcome == NM_QUANTUM_LOCAL_FAILURE) {
        nm_tls_inspection_release(&inspection);
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
        inspection.observation.summary = NULL;
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
    nm_tls_inspection_release(&inspection);
    return result;
}
