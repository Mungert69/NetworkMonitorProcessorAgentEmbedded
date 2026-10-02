#ifndef NM_NMAP_CMD_PROCESSOR_H
#define NM_NMAP_CMD_PROCESSOR_H
#include "cmd_result.h"
#include "cmd_arguments.h"
#include <stdint.h>
typedef struct {
    /* Original single hostname/IP or CIDR text, used for display. */
    char host[254];
    /* Normalized usable IPv4 interval for bounded -sn CIDR scans. */
    uint32_t first_ipv4;
    uint16_t target_count;
    uint16_t ports[64];
    size_t count;
    unsigned timeout_ms;
    bool discovery_only;
    bool has_ipv4_range;
    bool fast_scan;
    bool no_ping;
    bool arp_only;
    bool show_open;
    bool service_version;
    bool system_dns;
    bool show_reason;
    uint8_t verbosity;
} nm_nmap_command;
bool nm_nmap_cmd_parse(const char *arguments, nm_nmap_command *request, const char **error);
nm_cmd_result nm_nmap_cmd_run(const nm_nmap_command *request, const atomic_bool *cancellation);
const char *nm_nmap_cmd_help(void);
#endif
