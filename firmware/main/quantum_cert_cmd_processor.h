#ifndef NM_QUANTUM_CERT_CMD_PROCESSOR_H
#define NM_QUANTUM_CERT_CMD_PROCESSOR_H

/* Names are intentionally distinct, matching QuantumCertCmdProcessor.cs and
 * CmdProcessorProvider.cs. The Type sent over the wire is the registered type,
 * not CmdName. tests/tooling/test_cmd_processor_contract.py checks the sibling
 * .NET sources; change these only when the shared contract changes. */
#define NM_QUANTUM_CERT_PROCESSOR_TYPE "QuantumCert"
#define NM_QUANTUM_CERT_CMD_NAME "quantum-cert"
#define NM_QUANTUM_CERT_DISPLAY_NAME "Quantum Certificate Check"
#define NM_QUANTUM_CERT_TARGET_ARGUMENT "target"
#define NM_QUANTUM_CERT_PORT_ARGUMENT "port"
#define NM_QUANTUM_CERT_TIMEOUT_ARGUMENT "timeout"
#define NM_QUANTUM_CERT_DEFAULT_PORT 443
#define NM_QUANTUM_CERT_DEFAULT_TIMEOUT_MS 59000

#include <stdbool.h>
#include <stdatomic.h>
#include "tls_inspection.h"
#include "cmd_arguments.h"
#include "cmd_result.h"
typedef struct {
    char target[254];
    unsigned port, timeout_ms;
} nm_quantum_cert_command;
/* Arguments borrowed; parsed request owns its target. No shell is invoked.
 * Error is a borrowed diagnostic. Numeric overflow/invalid ranges are rejected. */
bool nm_quantum_cert_cmd_parse(const char *arguments, nm_quantum_cert_command *request,
                               const char **error);
/* Synchronous worker-only API. cancellation is borrowed through completion. */
nm_cmd_result nm_quantum_cert_cmd_run(const nm_quantum_cert_command *request,
                                      const atomic_bool *cancellation);
const char *nm_quantum_cert_cmd_help(void);

#endif
