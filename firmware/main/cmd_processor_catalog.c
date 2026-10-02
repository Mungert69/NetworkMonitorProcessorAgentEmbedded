#include "cmd_processor_catalog.h"
#include "nm_memory.h"
#include <strings.h>

static const char *const types[] = {"QuantumCert", "QuantumConnect", "QuantumPortScanner",
                                    "QuantumInfo", "Openssl",        "Nmap"};
static const char *const names[] = {"quantum-cert", "quantum", "quantum-scan",
                                    "quantuminfo",  "openssl", "nmap"};
const char *nm_cmd_kind_type(nm_cmd_kind kind)
{
    return kind < NM_CMD_COUNT && kind >= 0 ? types[kind] : NULL;
}
const char *nm_cmd_kind_name(nm_cmd_kind kind)
{
    return kind < NM_CMD_COUNT && kind >= 0 ? names[kind] : NULL;
}
bool nm_cmd_kind_find(const char *type, nm_cmd_kind *kind)
{
    if (!type || !kind)
        return false;
    for (unsigned i = 0; i < NM_CMD_COUNT; ++i)
        if (!strcasecmp(type, types[i])) {
            *kind = (nm_cmd_kind)i;
            return true;
        }
    return false;
}
const char *nm_cmd_kind_help(nm_cmd_kind kind)
{
    switch (kind) {
    case NM_CMD_CERT:
        return nm_quantum_cert_cmd_help();
    case NM_CMD_CONNECT:
        return nm_quantum_connect_cmd_help();
    case NM_CMD_SCAN:
        return nm_quantum_scan_cmd_help();
    case NM_CMD_INFO:
        return nm_quantum_info_cmd_help();
    case NM_CMD_OPENSSL:
        return nm_openssl_cmd_help();
    case NM_CMD_NMAP:
        return nm_nmap_cmd_help();
    default:
        return "Unknown command processor";
    }
}
static void limit_timeout(unsigned *timeout, unsigned limit)
{
    if (*timeout > limit)
        *timeout = limit;
}
bool nm_cmd_kind_parse(nm_cmd_kind kind, const char *arguments, unsigned timeout_ms,
                       nm_embedded_command *request, const char **error)
{
    if (!request || !error || !timeout_ms)
        return false;
    *request = (nm_embedded_command){.kind = kind};
    switch (kind) {
    case NM_CMD_CERT:
        if (!nm_quantum_cert_cmd_parse(arguments, &request->data.cert, error))
            return false;
        limit_timeout(&request->data.cert.timeout_ms, timeout_ms);
        break;
    case NM_CMD_CONNECT:
        if (!nm_quantum_connect_cmd_parse(arguments, &request->data.connect, error))
            return false;
        limit_timeout(&request->data.connect.connection.timeout_ms, timeout_ms);
        break;
    case NM_CMD_SCAN:
        if (!nm_quantum_scan_cmd_parse(arguments, &request->data.scan, error))
            return false;
        request->data.scan.total_timeout_ms = timeout_ms;
        break;
    case NM_CMD_INFO:
        return nm_quantum_info_cmd_parse(arguments, &request->data.info, error);
    case NM_CMD_OPENSSL:
        if (!nm_openssl_cmd_parse(arguments, &request->data.openssl, error))
            return false;
        limit_timeout(&request->data.openssl.timeout_ms, timeout_ms);
        break;
    case NM_CMD_NMAP:
        if (!nm_nmap_cmd_parse(arguments, &request->data.nmap, error))
            return false;
        request->data.nmap.timeout_ms = timeout_ms;
        break;
    default:
        return false;
    }
    return true;
}
nm_cmd_result nm_cmd_kind_run(const nm_embedded_command *request, const atomic_bool *cancellation)
{
    if (!request)
        return (nm_cmd_result){.output = nm_bulk_strdup("Invalid command request")};
    switch (request->kind) {
    case NM_CMD_CERT:
        return nm_quantum_cert_cmd_run(&request->data.cert, cancellation);
    case NM_CMD_CONNECT:
        return nm_quantum_connect_cmd_run(&request->data.connect, cancellation);
    case NM_CMD_SCAN:
        return nm_quantum_scan_cmd_run(&request->data.scan, cancellation);
    case NM_CMD_INFO:
        return nm_quantum_info_cmd_run(&request->data.info, cancellation);
    case NM_CMD_OPENSSL:
        return nm_openssl_cmd_run(&request->data.openssl, cancellation);
    case NM_CMD_NMAP:
        return nm_nmap_cmd_run(&request->data.nmap, cancellation);
    default:
        return (nm_cmd_result){.output = nm_bulk_strdup("Unknown command processor")};
    }
}
