#include "quantum_port_scanner_cmd_processor.h"
#include "nmap_runner.h"
#include "cmd_output.h"
#include "nm_memory.h"
#include <stdio.h>
#include <string.h>
#include <strings.h>

const char *nm_quantum_scan_cmd_help(void)
{
    return "Scan a host for quantum-ready TLS across one or more ports.\n"
           "Usage: --target <host|url> [--algorithms <list>] [--ports <list>] [--timeout <ms>] "
           "[--nmap_options <options>]\n"
           "At most 20 ports; list separators: comma, semicolon, colon or whitespace.\n"
           "Omitted ports use the embedded common-port TCP discovery, not a full Nmap scan.\n"
           "Sequential per-port checks share the request's overall TimeoutSeconds budget.\n"
           "Discovery options: -sT --open, empty, or the .NET default timing string.\n";
}
typedef struct {
    char filtered[4097], item[1025], ports[1025], value[1025];
} scan_cli;
static bool parse_scan(const char *arguments, nm_quantum_scan_command *request, const char **error,
                       scan_cli *cli)
{
    if (!request || !error)
        return false;
    *request = (nm_quantum_scan_command){.total_timeout_ms = 600000};
    *error = "Invalid QuantumPortScanner arguments; at most 20 ports in range 1..65535";
    if (!arguments || strlen(arguments) > 4096)
        return false;
    char *filtered = cli->filtered, *item = cli->item, *ports = cli->ports;
    size_t used = 0, ports_used = 0;
    const char *cursor = arguments;
    bool collecting_ports = false;
    while (*cursor) {
        if (!nm_cmd_argument_token(&cursor, item, sizeof(cli->item)))
            return false;
        if (!*item)
            break;
        if (collecting_ports && item[0] != '-') {
            size_t length = strlen(item);
            if (length + 2 > sizeof(cli->ports) - ports_used)
                return false;
            ports[ports_used++] = ' ';
            memcpy(ports + ports_used, item, length + 1);
            ports_used += length;
            continue;
        }
        collecting_ports = false;
        const char *key = item + (item[0] == '-' ? (item[1] == '-' ? 2 : 1) : 0);
        char *equals = strchr((char *)key, '=');
        if (equals)
            *equals = 0;
        bool port_option = !strcasecmp(key, "ports");
        bool nmap_option = !strcasecmp(key, "nmap_options");
        if (port_option || nmap_option) {
            char *value = cli->value;
            if (equals)
                memcpy(value, equals + 1, strlen(equals + 1) + 1);
            else if (!nm_cmd_argument_token(&cursor, value, sizeof(cli->value)))
                return false;
            if (port_option) {
                if (ports_used)
                    return false;
                memcpy(ports, value, strlen(value) + 1);
                ports_used = strlen(value);
                collecting_ports = true;
            } else if (*value && strcmp(value, "-sT --open") &&
                       strcmp(value, "-T4 --open --max-retries 2 --host-timeout 30s "
                                     "--initial-rtt-timeout 200ms --max-rtt-timeout 1s")) {
                *error = "Unsupported embedded nmap_options; use -sT --open or explicit --ports";
                return false;
            }
        } else {
            if (equals)
                *equals = '=';
            if (!nm_cmd_argument_append(filtered, sizeof(cli->filtered), &used, item))
                return false;
        }
    }
    if (*ports &&
        (!nm_cmd_ports_parse(ports, request->ports, 20, &request->count, false) || !request->count))
        return false;
    if (!nm_quantum_connect_cmd_parse(filtered, &request->quantum, error))
        return false;
    *error = NULL;
    return true;
}

bool nm_quantum_scan_cmd_parse(const char *arguments, nm_quantum_scan_command *request,
                               const char **error)
{
    if (!request || !error)
        return false;
    scan_cli *cli = nm_bulk_calloc(1, sizeof(*cli));
    if (!cli) {
        *error = "QuantumPortScanner parser local allocation failed";
        return false;
    }
    bool parsed = parse_scan(arguments, request, error, cli);
    free(cli);
    return parsed;
}

nm_cmd_result nm_quantum_scan_cmd_run(const nm_quantum_scan_command *request,
                                      const atomic_bool *cancellation)
{
    if (!request || request->count > 20)
        return (nm_cmd_result){.output = nm_bulk_strdup("Invalid quantum scan request")};
    uint16_t ports[20];
    size_t count = request->count;
    memcpy(ports, request->ports, count * sizeof(*ports));
    int64_t start = nm_quantum_now_ms();
    if (start < 0)
        return (nm_cmd_result){.output = nm_bulk_strdup("Quantum scan failed: clock unavailable")};
    if (!count) {
        unsigned discovery_budget = request->quantum.connection.timeout_ms;
        if (discovery_budget > request->total_timeout_ms)
            discovery_budget = request->total_timeout_ms;
        nm_nmap_scan_request discovery = {.host = request->quantum.connection.target,
                                          .timeout_ms = discovery_budget,
                                          .cancellation = cancellation};
        nm_nmap_run_result result = nm_nmap_runner_scan(&discovery);
        if (result.state != NM_NMAP_RUN_COMPLETED || !result.open_count || result.open_count > 20) {
            const char *message =
                result.state == NM_NMAP_RUN_CANCELLED ? "Quantum scan canceled or timed out.\n"
                : result.state == NM_NMAP_RUN_TIMED_OUT
                    ? "Nmap scan exceeded timeout. Please specify a smaller port list."
                : result.state != NM_NMAP_RUN_COMPLETED ? result.error
                : result.open_count > 20 ? "Too many open ports. The maximum allowed is 20."
                                         : "No open ports found to scan";
            nm_cmd_result failed = {.output = nm_bulk_strdup(message)};
            nm_nmap_runner_result_release(&result);
            return failed;
        }
        count = result.open_count;
        memcpy(ports, result.open_ports, count * sizeof(*ports));
        nm_nmap_runner_result_release(&result);
    }
    nm_cmd_output successes, failures, output;
    nm_cmd_output_init(&successes, 8192);
    nm_cmd_output_init(&failures, 8192);
    bool any_success = false, any_failure = false, canceled = false;
    for (size_t i = 0; i < count && successes.valid && failures.valid; ++i) {
        int64_t elapsed = nm_quantum_now_ms() - start;
        if ((cancellation && atomic_load(cancellation)) || elapsed < 0 ||
            (uint64_t)elapsed >= request->total_timeout_ms) {
            canceled = true;
            break;
        }
        nm_quantum_connect_command connection = request->quantum;
        connection.connection.port = ports[i];
        unsigned remaining = request->total_timeout_ms - (unsigned)elapsed;
        if (connection.connection.timeout_ms > remaining)
            connection.connection.timeout_ms = remaining;
        nm_cmd_result result = nm_quantum_connect_cmd_run(&connection, cancellation);
        if (!result.output) {
            successes.valid = false;
            break;
        }
        if (result.success) {
            any_success = true;
            nm_cmd_output_append(&successes, "Port %u: %s\n", ports[i], result.output);
        } else {
            any_failure = true;
            nm_cmd_output_append(&failures, "Port %u: %s\n", ports[i], result.output);
        }
        free(result.output);
    }
    nm_cmd_output_init(&output, 8192);
    if (canceled || (cancellation && atomic_load(cancellation))) {
        nm_cmd_output_append(&output, "Quantum scan canceled or timed out.\n");
        any_success = false;
    } else if (!successes.valid || !failures.valid)
        output.valid = false;
    else {
        if (any_success)
            nm_cmd_output_append(&output, "Quantum-safe ports found:\n%s", successes.text);
        if (any_failure)
            nm_cmd_output_append(&output, "Ports that failed quantum-safe handshake:\n%s",
                                 failures.text);
    }
    free(successes.text);
    free(failures.text);
    return nm_cmd_output_finish(&output, any_success);
}
