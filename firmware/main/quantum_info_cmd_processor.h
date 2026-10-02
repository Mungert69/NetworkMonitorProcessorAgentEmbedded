#ifndef NM_QUANTUM_INFO_CMD_PROCESSOR_H
#define NM_QUANTUM_INFO_CMD_PROCESSOR_H
#include "cmd_result.h"
#include "cmd_arguments.h"
typedef struct {
    char query[128];
} nm_quantum_info_command;
bool nm_quantum_info_cmd_parse(const char *arguments, nm_quantum_info_command *request,
                               const char **error);
nm_cmd_result nm_quantum_info_cmd_run(const nm_quantum_info_command *request,
                                      const atomic_bool *cancellation);
const char *nm_quantum_info_cmd_help(void);
#endif
