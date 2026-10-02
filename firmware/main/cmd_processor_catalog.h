#ifndef NM_CMD_PROCESSOR_CATALOG_H
#define NM_CMD_PROCESSOR_CATALOG_H
#include "quantum_cert_cmd_processor.h"
#include "quantum_connect_cmd_processor.h"
#include "quantum_port_scanner_cmd_processor.h"
#include "quantum_info_cmd_processor.h"
#include "openssl_cmd_processor.h"
#include "nmap_cmd_processor.h"
typedef enum {
    NM_CMD_CERT,
    NM_CMD_CONNECT,
    NM_CMD_SCAN,
    NM_CMD_INFO,
    NM_CMD_OPENSSL,
    NM_CMD_NMAP,
    NM_CMD_COUNT
} nm_cmd_kind;
typedef struct {
    nm_cmd_kind kind;
    union {
        nm_quantum_cert_command cert;
        nm_quantum_connect_command connect;
        nm_quantum_scan_command scan;
        nm_quantum_info_command info;
        nm_openssl_command openssl;
        nm_nmap_command nmap;
    } data;
} nm_embedded_command;
bool nm_cmd_kind_find(const char *type, nm_cmd_kind *kind);
const char *nm_cmd_kind_type(nm_cmd_kind kind);
const char *nm_cmd_kind_name(nm_cmd_kind kind);
const char *nm_cmd_kind_help(nm_cmd_kind kind);
/* Parse into caller-owned typed storage; no JSON/transport dependency.
 * timeout_ms is the overall message budget, already range-validated. */
bool nm_cmd_kind_parse(nm_cmd_kind kind, const char *arguments, unsigned timeout_ms,
                       nm_embedded_command *request, const char **error);
nm_cmd_result nm_cmd_kind_run(const nm_embedded_command *request, const atomic_bool *cancellation);
#endif
