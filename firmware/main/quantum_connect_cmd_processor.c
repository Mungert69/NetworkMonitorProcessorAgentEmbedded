#include "quantum_connect_cmd_processor.h"
#include "openssl_runner.h"
#include "nm_memory.h"
#include <stdio.h>
#include <string.h>
#include <strings.h>

const char *nm_quantum_connect_cmd_help(void)
{
    return "Run a Quantum Security Check against a host.\n"
           "Usage: --target <host|url> [--algorithms <list>] [--port <int>] [--timeout <ms>]\n"
           "Algorithms accept comma, space, semicolon or colon separators.\n"
           "Compiled groups: X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024, "
           "MLKEM512, MLKEM768, MLKEM1024.\n"
           "Omitting --algorithms tests the compiled quantum groups. "
           "Unsupported groups are reported, not substituted.\n";
}

static bool add_algorithms(nm_quantum_connect_command *request, char *text)
{
    char *save = NULL;
    for (char *name = strtok_r(text, ",;: \t\r\n", &save); name;
         name = strtok_r(NULL, ",;: \t\r\n", &save)) {
        bool duplicate = false;
        for (size_t i = 0; i < request->count; ++i)
            duplicate |= !strcasecmp(name, request->algorithms[i]);
        if (duplicate)
            continue;
        if (request->count == 16 || strlen(name) >= sizeof(request->algorithms[0]))
            return false;
        memcpy(request->algorithms[request->count++], name, strlen(name) + 1);
    }
    return true;
}

typedef struct {
    char connection[4097], option[512], value[512];
} connect_cli;
static bool parse_connection(const char *arguments, nm_quantum_connect_command *request,
                             const char **error, connect_cli *cli)
{
    if (!request || !error)
        return false;
    *request = (nm_quantum_connect_command){0};
    *error = "Invalid QuantumConnect arguments";
    if (!arguments || strlen(arguments) > 4096)
        return false;
    /* Reuse the validated connection parser; remove only the algorithms option.
     * Re-encode values as quoted data, escaping quote/backslash characters. */
    char *connection = cli->connection, *option = cli->option, *value = cli->value;
    size_t used = 0;
    const char *cursor = arguments;
    bool collecting = false;
    while (*cursor) {
        if (!nm_cmd_argument_token(&cursor, option, sizeof(cli->option)))
            return false;
        if (!option[0])
            break;
        if (option[0] != '-') {
            if (collecting && !add_algorithms(request, option))
                return false;
            continue;
        }
        char *key = option + (option[1] == '-' ? 2 : 1);
        char *equals = strchr(key, '=');
        if (equals) {
            *equals = 0;
            memcpy(value, equals + 1, strlen(equals + 1) + 1);
        } else if (!nm_cmd_argument_token(&cursor, value, sizeof(cli->value)) || !value[0])
            return false;
        collecting = !strcasecmp(key, "algorithms");
        if (collecting) {
            if (!add_algorithms(request, value))
                return false;
            continue;
        }
        int written = snprintf(connection + used, sizeof(cli->connection) - used, " --%s \"", key);
        if (written < 0 || (size_t)written >= sizeof(cli->connection) - used)
            return false;
        used += (size_t)written;
        for (const char *p = value; *p; ++p) {
            size_t required = (*p == '"' || *p == '\\') ? 2 : 1;
            if (required + 2 >= sizeof(cli->connection) - used)
                return false;
            if (required == 2)
                connection[used++] = '\\';
            connection[used++] = *p;
        }
        connection[used++] = '"';
        connection[used] = 0;
    }
    if (!nm_quantum_cert_cmd_parse(connection, &request->connection, error))
        return false;
    if (!request->count) {
        request->batch = true;
        for (size_t i = 0; i < 6; ++i) {
            const char *name = nm_openssl_group_at(i);
            memcpy(request->algorithms[request->count++], name, strlen(name) + 1);
        }
    }
    *error = NULL;
    return true;
}

bool nm_quantum_connect_cmd_parse(const char *arguments, nm_quantum_connect_command *request,
                                  const char **error)
{
    if (!request || !error)
        return false;
    connect_cli *cli = nm_bulk_calloc(1, sizeof(*cli));
    if (!cli) {
        *error = "QuantumConnect parser local allocation failed";
        return false;
    }
    bool parsed = parse_connection(arguments, request, error, cli);
    free(cli);
    return parsed;
}

nm_cmd_result nm_quantum_connect_cmd_run(const nm_quantum_connect_command *request,
                                         const atomic_bool *cancellation)
{
    if (!request || !request->count || request->count > 16)
        return (nm_cmd_result){0};
    char *success = nm_bulk_calloc(1, 4096), *errors = nm_bulk_calloc(1, 4096);
    if (!success || !errors) {
        free(success);
        free(errors);
        return (nm_cmd_result){0};
    }
    size_t ok_length = 0, error_length = 0;
    int64_t start = nm_quantum_now_ms();
    bool interrupted = false, failed_output = start < 0;
    size_t tests = request->batch ? 1 : request->count;
    for (size_t i = 0; i < tests && !failed_output; ++i) {
        int64_t elapsed = nm_quantum_now_ms() - start;
        if ((cancellation && atomic_load(cancellation)) || elapsed < 0 ||
            (uint64_t)elapsed >= request->connection.timeout_ms) {
            interrupted = true;
            break;
        }
        nm_openssl_request connection = {.host = request->connection.target,
                                         .port = request->connection.port,
                                         .timeout_ms =
                                             request->connection.timeout_ms - (unsigned)elapsed,
                                         .group = request->batch ? NULL : request->algorithms[i],
                                         .cancellation = cancellation};
        nm_tls_inspection result = nm_openssl_execute(&connection);
        bool ok = result.observation.outcome == NM_QUANTUM_OK;
        char *destination = ok ? success : errors;
        size_t *length = ok ? &ok_length : &error_length;
        const char *diagnostic = ok ? "Using quantum safe handshake"
                                 : result.observation.error_message[0]
                                     ? result.observation.error_message
                                     : "Could not negotiate quantum safe handshake";
        int written =
            snprintf(destination + *length, 4096 - *length, "%s: %s; group=%s\n",
                     request->batch && result.observation.group[0] ? result.observation.group
                     : request->batch                              ? "default PQ groups"
                                                                   : request->algorithms[i],
                     diagnostic, result.observation.group[0] ? result.observation.group : "none");
        interrupted = result.observation.outcome == NM_QUANTUM_CANCELLED ||
                      result.observation.outcome == NM_QUANTUM_TIMEOUT;
        nm_tls_inspection_release(&result);
        if (written < 0 || (size_t)written >= 4096 - *length)
            failed_output = true;
        else
            *length += (size_t)written;
        if (interrupted)
            break;
    }
    nm_cmd_result output = {0};
    if (failed_output)
        output.output = nm_bulk_strdup("Quantum check failed: local output resource unavailable");
    else if (interrupted || (cancellation && atomic_load(cancellation)))
        output.output = nm_bulk_strdup("Quantum check canceled or timed out.\n");
    else if (ok_length) {
        output.success = true;
        output.output = success;
        success = NULL;
    } else {
        output.output = nm_bulk_calloc(1, error_length + 64);
        if (output.output)
            snprintf(output.output, error_length + 64,
                     "No quantum-safe algorithms supported. Errors:\n%s", errors);
    }
    free(success);
    free(errors);
    return output;
}
