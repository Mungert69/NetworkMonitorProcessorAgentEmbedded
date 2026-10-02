#ifndef NM_OPENSSL_CMD_PROCESSOR_H
#define NM_OPENSSL_CMD_PROCESSOR_H
#include "cmd_result.h"
#include "cmd_arguments.h"
typedef enum { NM_OPENSSL_CLIENT, NM_OPENSSL_VERSION, NM_OPENSSL_GROUPS } nm_openssl_operation;
typedef struct {
    nm_openssl_operation operation;
    char host[254], servername[254], groups[512];
    unsigned port, timeout_ms;
    bool verify;
} nm_openssl_command;
bool nm_openssl_cmd_parse(const char *arguments, nm_openssl_command *request, const char **error);
nm_cmd_result nm_openssl_cmd_run(const nm_openssl_command *request,
                                 const atomic_bool *cancellation);
const char *nm_openssl_cmd_help(void);
#endif
