#include "quantum_cert_cmd_processor.h"
#include "openssl_runner.h"
#include "nm_memory.h"
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

const char *nm_quantum_cert_cmd_help(void)
{
    return "\nRun a Quantum Certificate Check against a host.\n\n"
           "Usage:\n  --target <host|url> [--port <int>] [--timeout <ms>]\n"
           "  (You may also pass the target as the first positional argument.)\n\n"
           "Required:\n only --target is required.\n\nExamples:\n"
           "  example.com\n"
           "  --target example.com --port 8443 --timeout 15000\n\n"
           "Notes:\n  • Target may be a hostname or http/https URL; schemes are stripped before "
           "testing.\n";
}

bool nm_quantum_cert_cmd_parse(const char *arguments, nm_quantum_cert_command *request,
                               const char **error)
{
    if (!request || !error)
        return false;
    *error = "Invalid QuantumCert arguments. Use --target <host> [--port <int>] [--timeout <ms>].";
    *request = (nm_quantum_cert_command){.port = NM_QUANTUM_CERT_DEFAULT_PORT,
                                         .timeout_ms = NM_QUANTUM_CERT_DEFAULT_TIMEOUT_MS};
    if (!arguments || strlen(arguments) > 4096)
        return false;
    const char *cursor = arguments;
    char option[512], value[512], target[512] = "";
    while (*cursor) {
        if (!nm_cmd_argument_token(&cursor, option, sizeof(option)))
            return false;
        if (!option[0])
            break;
        /* CliArgParser ignores positional tokens. Its required-target check
         * runs before QuantumCert's positional fallback, so require --target. */
        if (option[0] != '-')
            continue;
        char *key = option + (option[1] == '-' ? 2 : 1);
        char *equals = strchr(key, '=');
        const char *argument;
        if (equals) {
            *equals = 0;
            argument = equals + 1;
        } else {
            if (!nm_cmd_argument_token(&cursor, value, sizeof(value)) || !value[0])
                return false;
            argument = value;
        }
        if (!strcasecmp(key, NM_QUANTUM_CERT_TARGET_ARGUMENT)) {
            memcpy(target, argument, strlen(argument) + 1);
        } else if (!strcasecmp(key, NM_QUANTUM_CERT_PORT_ARGUMENT)) {
            if (!nm_cmd_argument_number(argument, 65535, &request->port))
                return false;
        } else if (!strcasecmp(key, NM_QUANTUM_CERT_TIMEOUT_ARGUMENT)) {
            if (!nm_cmd_argument_number(argument, INT_MAX, &request->timeout_ms))
                return false;
        } else
            return false;
    }
    char *host = target;
    while (isspace((unsigned char)*host))
        ++host;
    if (!strncasecmp(host, "https://", 8))
        host += 8;
    else if (!strncasecmp(host, "http://", 7))
        host += 7;
    size_t length = strlen(host);
    while (length && (host[length - 1] == '/' || isspace((unsigned char)host[length - 1])))
        host[--length] = 0;
    if (!length || length >= sizeof(request->target))
        return false;
    for (size_t i = 0; i < length; ++i)
        if (isspace((unsigned char)host[i]) || host[i] == '/' || host[i] == '@' || host[i] == '?' ||
            host[i] == '#')
            return false;
    memcpy(request->target, host, length + 1);
    *error = NULL;
    return true;
}

nm_cmd_result nm_quantum_cert_cmd_run(const nm_quantum_cert_command *request,
                                      const atomic_bool *cancellation)
{
    if (!request)
        return (nm_cmd_result){0};
    nm_openssl_request inspection = {.host = request->target,
                                     .port = request->port,
                                     .timeout_ms = request->timeout_ms,
                                     .show_certificates = true,
                                     .cancellation = cancellation};
    nm_tls_inspection result = nm_openssl_execute(&inspection);
    bool cancelled = cancellation && atomic_load(cancellation);
    nm_cmd_result command = {.success = !cancelled && result.observation.outcome == NM_QUANTUM_OK};
    const char *output = cancelled || result.observation.outcome == NM_QUANTUM_TIMEOUT ||
                                 result.observation.outcome == NM_QUANTUM_CANCELLED
                             ? "Quantum certificate check canceled or timed out.\n"
                         : result.observation.summary ? result.observation.summary
                         : result.observation.outcome == NM_QUANTUM_LOCAL_FAILURE
                             ? "Quantum certificate check failed: local resource unavailable"
                             : "Quantum certificate check failed: TLS connection failed";
    command.output = nm_bulk_strdup(output);
    if (!command.output)
        command.success = false;
    nm_tls_inspection_release(&result);
    return command;
}
