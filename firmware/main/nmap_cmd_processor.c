#include "nmap_cmd_processor.h"
#include "nmap_runner.h"
#include "nmap_targets.h"
#include "nm_memory.h"
#include <ctype.h>
#include <string.h>

const char *nm_nmap_cmd_help(void)
{
    return "Embedded Nmap-compatible scanner (project-owned; not the Nmap binary).\n"
           "Usage: [-sT|-sV] [-Pn|-PR] [-F] [-v|-vv] [--open] [--reason] [--system-dns] [-p "
           "<ports/ranges>] <host>\n"
           "       -sn [-PR] <host/IPv4 CIDR> performs bounded discovery (CIDR /24 through /32).\n"
           "Local IPv4 uses fresh ARP replies; off-link discovery uses ICMP. -PR requires local "
           "IPv4.\n"
           "TCP mode scans one host and up to 64 explicit ports; default ports are a small set.\n"
           "-F uses a smaller 8-port set; -Pn assumes host up; --open hides non-open rows.\n"
           "--reason shows TCP-connect classification; -v/-vv adds a scan summary.\n"
           "-sV reports IANA TCP port-name hints, not active service fingerprinting.\n"
           "No SYN/UDP scans, scripts, OS detection, IPv6 CIDR or file output.\n";
}

static bool port_syntax(const char *text)
{
    if (!text || !*text || *text == ',')
        return false;
    char previous = 0;
    for (const char *p = text; *p; ++p) {
        if ((*p < '0' || *p > '9') && *p != ',' && *p != '-')
            return false;
        if (*p == ',' && (previous == ',' || previous == '-'))
            return false;
        previous = *p;
    }
    return previous >= '0' && previous <= '9';
}
bool nm_nmap_cmd_parse(const char *arguments, nm_nmap_command *request, const char **error)
{
    if (!request || !error)
        return false;
    *request = (nm_nmap_command){.timeout_ms = 59000};
    *error = "Invalid or unsupported embedded Nmap arguments; request help for supported options";
    if (!arguments || strlen(arguments) > 4096)
        return false;
    const char *cursor = arguments;
    char item[1025];
    bool seen_ports = false;
    bool seen_target = false;
    bool first_token = true, tcp_scan = false;
    while (*cursor) {
        while (isspace((unsigned char)*cursor))
            ++cursor;
        if (!*cursor)
            break;
        if (!nm_cmd_argument_token(&cursor, item, sizeof(item)))
            return false;
        if (!*item)
            return false;
        bool executable = first_token && !strcmp(item, "nmap");
        first_token = false;
        if (executable)
            continue;
        if (!strcmp(item, "-sT")) {
            tcp_scan = true;
            continue;
        }
        if (!strcmp(item, "-sV")) {
            request->service_version = true;
            continue;
        }
        if (!strcmp(item, "-Pn")) {
            request->no_ping = true;
            continue;
        }
        if (!strcmp(item, "-PR")) {
            request->arp_only = true;
            continue;
        }
        if (!strcmp(item, "-sn")) {
            request->discovery_only = true;
            continue;
        }
        if (!strcmp(item, "-F")) {
            request->fast_scan = true;
            continue;
        }
        if (!strcmp(item, "--open")) {
            request->show_open = true;
            continue;
        }
        if (!strcmp(item, "--system-dns")) {
            request->system_dns = true;
            continue;
        }
        if (!strcmp(item, "--reason")) {
            request->show_reason = true;
            continue;
        }
        if (!strcmp(item, "-v")) {
            if (request->verbosity < 2)
                ++request->verbosity;
            continue;
        }
        if (!strcmp(item, "-vv")) {
            request->verbosity = 2;
            continue;
        }
        if (!strcmp(item, "-p") || (!strncmp(item, "-p", 2) && item[2])) {
            char *value = item + 2;
            if (!*value) {
                if (!nm_cmd_argument_token(&cursor, item, sizeof(item)))
                    return false;
                value = item;
            }
            if (seen_ports || !port_syntax(value) ||
                !nm_cmd_ports_parse(value, request->ports, 64, &request->count, true) ||
                !request->count)
                return false;
            seen_ports = true;
            continue;
        }
        if (*item == '-' || seen_target || strlen(item) >= sizeof(request->host))
            return false;
        for (const char *p = item; *p; ++p)
            if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                  (*p >= '0' && *p <= '9') || *p == '-' || *p == '_' || *p == '.' || *p == ':' ||
                  *p == '/'))
                return false;
        /* Do not let resolver-specific octal/abbreviated IPv4 syntax silently
         * change a dotted numeric target. Hostnames are still resolved normally. */
        bool dotted_numeric = strchr(item, '.') != NULL;
        for (const char *p = item; *p; ++p)
            if ((*p < '0' || *p > '9') && *p != '.')
                dotted_numeric = false;
        uint32_t ipv4;
        if (dotted_numeric && !nm_nmap_ipv4_parse(item, &ipv4))
            return false;
        memcpy(request->host, item, strlen(item) + 1);
        seen_target = true;
    }
    if (!seen_target || (request->no_ping && request->arp_only) ||
        (request->discovery_only &&
         (seen_ports || request->no_ping || tcp_scan || request->service_version ||
          request->fast_scan || request->show_open)) ||
        (!request->discovery_only && strchr(request->host, '/')))
        return false;
    if (request->discovery_only && strchr(request->host, '/')) {
        nm_nmap_ipv4_range range;
        if (!nm_nmap_ipv4_cidr_parse(request->host, &range))
            return false;
        request->first_ipv4 = range.first_address;
        request->target_count = range.count;
        request->has_ipv4_range = true;
    } else if (request->discovery_only) {
        request->target_count = 1;
    }
    *error = NULL;
    return true;
}
nm_cmd_result nm_nmap_cmd_run(const nm_nmap_command *request, const atomic_bool *cancellation)
{
    if (!request || request->count > 64 ||
        (request->discovery_only &&
         (!request->target_count || request->target_count > NM_NMAP_MAX_TARGETS)))
        return (nm_cmd_result){.output = nm_bulk_strdup("Invalid Nmap command request")};
    if (request->discovery_only) {
        nm_nmap_discovery_request discovery = {.display_target = request->host,
                                               .first_ipv4 = request->first_ipv4,
                                               .target_count = request->target_count,
                                               .has_ipv4_range = request->has_ipv4_range,
                                               .arp_only = request->arp_only,
                                               .show_reason = request->show_reason,
                                               .verbosity = request->verbosity,
                                               .timeout_ms = request->timeout_ms,
                                               .cancellation = cancellation};
        nm_nmap_run_result scanned = nm_nmap_runner_discover(&discovery);
        nm_cmd_result result = {.success = scanned.state == NM_NMAP_RUN_COMPLETED &&
                                           scanned.exit_code == 0};
        result.output = scanned.standard_output;
        scanned.standard_output = NULL;
        if (!result.output)
            result.output =
                nm_bulk_strdup(scanned.error[0] ? scanned.error : "Nmap discovery failed");
        nm_nmap_runner_result_release(&scanned);
        return result;
    }
    nm_nmap_scan_request scan = {.host = request->host,
                                 .ports = request->ports,
                                 .count = request->count,
                                 .timeout_ms = request->timeout_ms,
                                 .fast_scan = request->fast_scan,
                                 .show_open = request->show_open,
                                 .no_ping = request->no_ping,
                                 .arp_only = request->arp_only,
                                 .show_reason = request->show_reason,
                                 .verbosity = request->verbosity,
                                 .cancellation = cancellation};
    nm_nmap_run_result scanned = nm_nmap_runner_scan(&scan);
    nm_cmd_result result = {.success =
                                scanned.state == NM_NMAP_RUN_COMPLETED && scanned.exit_code == 0};
    if (result.success) {
        result.output = scanned.standard_output;
        scanned.standard_output = NULL;
    } else
        result.output =
            nm_bulk_strdup(scanned.state == NM_NMAP_RUN_CANCELLED ? "Nmap command was cancelled.\n"
                                                                  : scanned.error);
    nm_nmap_runner_result_release(&scanned);
    return result;
}
