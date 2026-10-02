#ifndef NM_QUANTUM_PORT_SCANNER_CMD_PROCESSOR_H
#define NM_QUANTUM_PORT_SCANNER_CMD_PROCESSOR_H
#include "quantum_connect_cmd_processor.h"
#include <stdint.h>
typedef struct {
    nm_quantum_connect_command quantum;
    uint16_t ports[20];
    size_t count;
    unsigned total_timeout_ms;
} nm_quantum_scan_command;
bool nm_quantum_scan_cmd_parse(const char *arguments, nm_quantum_scan_command *request,
                               const char **error);
nm_cmd_result nm_quantum_scan_cmd_run(const nm_quantum_scan_command *request,
                                      const atomic_bool *cancellation);
const char *nm_quantum_scan_cmd_help(void);
#endif
