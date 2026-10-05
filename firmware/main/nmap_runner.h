#ifndef NM_NMAP_RUNNER_H
#define NM_NMAP_RUNNER_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>

/* Process-like boundary for Nmap. ESP32 uses the embedded adapter; a host
 * implementation could execute the real binary behind this same contract. */
typedef enum {
    NM_NMAP_RUN_COMPLETED,
    NM_NMAP_RUN_TIMED_OUT,
    NM_NMAP_RUN_LOCAL_FAILURE,
    NM_NMAP_RUN_ERROR,
    NM_NMAP_RUN_CANCELLED
} nm_nmap_run_state;

typedef struct {
    nm_nmap_run_state state;
    int exit_code;
    unsigned elapsed_ms;
    char *standard_output;
    char error[192];
    uint16_t open_ports[64];
    size_t open_count;
} nm_nmap_run_result;

typedef struct {
    const char *host;      /* Borrowed through synchronous completion. */
    const uint16_t *ports; /* NULL/count zero uses the built-in common-port set. */
    size_t count;          /* At most 64 ports. */
    unsigned timeout_ms;   /* Exact total budget, including the endpoint wrapper. */
    bool fast_scan;        /* Smaller project-owned port set when no explicit ports are supplied. */
    bool show_open;        /* Match --open by suppressing non-open findings. */
    bool no_ping;          /* -Pn: skip discovery and assume the target is up. */
    bool arp_only;         /* -PR: require local IPv4 ARP discovery. */
    bool show_reason;      /* --reason: include the TCP-connect classification reason. */
    uint8_t verbosity;     /* -v/-vv: include bounded scan summary details. */
    const atomic_bool *cancellation;
} nm_nmap_scan_request;

typedef struct {
    const char *display_target; /* Hostname/IP or original CIDR, borrowed for the call. */
    uint32_t first_ipv4;        /* Host-order first usable address. */
    uint16_t target_count;      /* One for a hostname/IP; bounded CIDR count otherwise. */
    bool has_ipv4_range;
    bool arp_only; /* Otherwise local IPv4 uses ARP; off-link uses ICMP. */
    bool show_reason;
    uint8_t verbosity;
    unsigned timeout_ms; /* Total budget shared by every target. */
    const atomic_bool *cancellation;
} nm_nmap_discovery_request;
nm_nmap_run_result nm_nmap_runner_scan(const nm_nmap_scan_request *request);
nm_nmap_run_result nm_nmap_runner_discover(const nm_nmap_discovery_request *request);

/* argv is a bounded token vector, not a shell command string. The runner
 * accepts only the small Nmap-compatible option subset implemented here.
 * timeout_ms is the exact total budget; endpoint extension belongs to endpoints.c. */
nm_nmap_run_result nm_nmap_runner_execute(const char *const argv[], size_t argc,
                                          unsigned timeout_ms);
void nm_nmap_runner_result_release(nm_nmap_run_result *result);

#endif
