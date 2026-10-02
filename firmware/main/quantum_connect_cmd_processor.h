#ifndef NM_QUANTUM_CONNECT_CMD_PROCESSOR_H
#define NM_QUANTUM_CONNECT_CMD_PROCESSOR_H
#include "quantum_cert_cmd_processor.h"
#define NM_QUANTUM_CONNECT_PROCESSOR_TYPE "QuantumConnect"
#define NM_QUANTUM_CONNECT_CMD_NAME "quantum"
#define NM_QUANTUM_CONNECT_DISPLAY_NAME "Quantum Security Check"
typedef struct {
    nm_quantum_cert_command connection;
    /* Owned copied names; unknown algorithms produce explicit per-group errors. */
    char algorithms[16][64];
    size_t count;
    bool batch; /* Default list is offered together, matching .NET batch mode. */
} nm_quantum_connect_command;
bool nm_quantum_connect_cmd_parse(const char *arguments, nm_quantum_connect_command *request,
                                  const char **error);
nm_cmd_result nm_quantum_connect_cmd_run(const nm_quantum_connect_command *request,
                                         const atomic_bool *cancellation);
const char *nm_quantum_connect_cmd_help(void);
#endif
