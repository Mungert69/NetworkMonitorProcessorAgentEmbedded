#include "nmap_runner.h"
#include "endpoint_internal.h"
#include "endpoint_resource.h"
#include "nmap_targets.h"
#include "nmap_arp.h"
#include "service_hints.h"
#include "nm_memory.h"
#include "esp_timer.h"
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

/* Project-owned limited catalogue; no Nmap source, database, or scripts. */
static const uint16_t common_ports[] = {21,   22,   23,   25,   53,   80,   110,  143,
                                        443,  445,  587,  993,  995,  1433, 1883, 3306,
                                        3389, 5432, 5672, 5900, 8080, 8443};
static const uint16_t fast_ports[] = {22, 53, 80, 443, 445, 1883, 8080, 8443};

enum {
    NMAP_MAX_REPORT = 32768, /* 254 host rows including MAC/reason, in PSRAM. */
    NMAP_DEFAULT_PER_PORT_MS = 250,
    NMAP_DISCOVERY_PER_HOST_MS = 200
};

static void set_port(struct sockaddr *address, uint16_t port)
{
    if (address->sa_family == AF_INET)
        ((struct sockaddr_in *)address)->sin_port = htons(port);
#if LWIP_IPV6
    else if (address->sa_family == AF_INET6)
        ((struct sockaddr_in6 *)address)->sin6_port = htons(port);
#else
    (void)port;
#endif
}

/* 1=open, 0=closed/filtered, -1=local resource failure, -2=total deadline,
 * -3=cancelled. One per-port budget covers ALL resolved addresses. */
static int probe_port(const struct addrinfo *addresses, uint16_t port, int64_t started,
                      unsigned total_budget_ms, unsigned per_port_ms, int *last_error,
                      const atomic_bool *cancellation)
{
    int64_t port_started = esp_timer_get_time();
    for (const struct addrinfo *address = addresses; address; address = address->ai_next) {
        if (cancellation && atomic_load(cancellation))
            return -3;
        unsigned remaining = nm_endpoint_remaining(started, total_budget_ms);
        if (!remaining)
            return -2;
        if (!nm_endpoint_remaining(port_started, per_port_ms)) {
            *last_error = ETIMEDOUT;
            return 0;
        }
        int fd = socket(address->ai_family, SOCK_STREAM, 0);
        if (fd < 0) {
            *last_error = errno;
            if (nm_endpoint_resource_errno(errno))
                return -1;
            continue;
        }
#ifdef LWIP_SELECT_MAXNFDS
        int select_limit = LWIP_SELECT_MAXNFDS;
#else
        int select_limit = FD_SETSIZE;
#endif
        if (fd >= select_limit) {
            *last_error = EMFILE;
            close(fd);
            return -1;
        }
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            *last_error = errno;
            close(fd);
            return nm_endpoint_resource_errno(*last_error) ? -1 : 0;
        }
        struct sockaddr_storage destination;
        if (!address->ai_addr || address->ai_addrlen > sizeof(destination)) {
            close(fd);
            *last_error = EINVAL;
            return 0;
        }
        memcpy(&destination, address->ai_addr, address->ai_addrlen);
        set_port((struct sockaddr *)&destination, port);
        *last_error = 0;
        bool connected = connect(fd, (struct sockaddr *)&destination, address->ai_addrlen) == 0;
        if (!connected) {
            *last_error = errno;
            if (*last_error == EINPROGRESS || *last_error == EWOULDBLOCK) {
                int rc = 0;
                for (;;) {
                    if (cancellation && atomic_load(cancellation)) {
                        close(fd);
                        return -3;
                    }
                    remaining = nm_endpoint_remaining(started, total_budget_ms);
                    unsigned port_remaining = nm_endpoint_remaining(port_started, per_port_ms);
                    if (remaining > port_remaining)
                        remaining = port_remaining;
                    if (!remaining) {
                        rc = 0;
                        break;
                    }
                    unsigned wait_ms = remaining < per_port_ms ? remaining : per_port_ms;
                    if (cancellation && wait_ms > 100)
                        wait_ms = 100;
                    fd_set writable;
                    FD_ZERO(&writable);
                    FD_SET(fd, &writable);
                    struct timeval wait = {.tv_sec = wait_ms / 1000,
                                           .tv_usec = (wait_ms % 1000) * 1000};
                    rc = select(fd + 1, NULL, &writable, NULL, &wait);
                    if (rc < 0 && errno == EINTR)
                        continue;
                    if (rc == 0)
                        continue;
                    break;
                }
                if (rc > 0) {
                    int error = 0;
                    socklen_t size = sizeof(error);
                    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0) {
                        *last_error = error;
                        connected = error == 0;
                    } else {
                        *last_error = errno;
                    }
                } else if (rc < 0) {
                    *last_error = errno;
                    close(fd);
                    return nm_endpoint_resource_errno(*last_error) ? -1 : 0;
                } else {
                    *last_error = ETIMEDOUT;
                }
            }
        }
        int error = *last_error;
        close(fd);
        if (connected)
            return 1;
        if (nm_endpoint_resource_errno(error))
            return -1;
        if (error == ECONNREFUSED || error == ECONNRESET)
            return 0;
        if (error == ETIMEDOUT && !nm_endpoint_remaining(started, total_budget_ms))
            return -2;
    }
    return 0;
}

static bool append_report(char *buffer, size_t capacity, size_t *used, const char *format, ...)
{
    if (*used >= capacity)
        return false;
    va_list args;
    va_start(args, format);
    int written = vsnprintf(buffer + *used, capacity - *used, format, args);
    va_end(args);
    if (written < 0 || (size_t)written >= capacity - *used)
        return false;
    *used += (size_t)written;
    return true;
}

static bool parse_invocation(const char *const argv[], size_t argc, const char **host,
                             uint16_t *port)
{
    if (!argv || !host || !port || argc < 4 || argc > 6 || !argv[0] || strcmp(argv[0], "nmap") ||
        !argv[1] || strcmp(argv[1], "-sV") || !argv[2] || strcmp(argv[2], "--system-dns"))
        return false;
    *port = 0;
    size_t target_index = 3;
    if (argc == 6) {
        if (!argv[3] || strcmp(argv[3], "-p") || !argv[4] || !*argv[4])
            return false;
        char *end = NULL;
        unsigned long parsed = strtoul(argv[4], &end, 10);
        if (!end || *end || parsed == 0 || parsed > UINT16_MAX)
            return false;
        *port = (uint16_t)parsed;
        target_index = 5;
    } else if (argc != 4) {
        return false;
    }
    if (!argv[target_index] || !*argv[target_index] || strlen(argv[target_index]) > 253)
        return false;
    *host = argv[target_index];
    return true;
}

static nm_nmap_run_result runner_error(nm_nmap_run_state state, unsigned elapsed,
                                       const char *message)
{
    nm_nmap_run_result result = {.state = state, .elapsed_ms = elapsed};
    snprintf(result.error, sizeof(result.error), "%.191s", message ? message : "Nmap runner error");
    return result;
}

nm_nmap_run_result nm_nmap_runner_execute(const char *const argv[], size_t argc,
                                          unsigned timeout_ms)
{
    const char *host = NULL;
    uint16_t configured_port = 0;
    if (!parse_invocation(argv, argc, &host, &configured_port))
        return runner_error(NM_NMAP_RUN_ERROR, 0, "Unsupported Nmap command arguments");

    nm_nmap_scan_request request = {.host = host,
                                    .ports = configured_port ? &configured_port : NULL,
                                    .count = configured_port ? 1 : 0,
                                    .timeout_ms = timeout_ms};
    return nm_nmap_runner_scan(&request);
}

nm_nmap_run_result nm_nmap_runner_scan(const nm_nmap_scan_request *request)
{
    if (!request || !request->host || !*request->host || strlen(request->host) > 253 ||
        request->count > 64 || (request->count && !request->ports) || !request->timeout_ms ||
        (request->arp_only && request->no_ping))
        return runner_error(NM_NMAP_RUN_ERROR, 0, "Invalid TCP scan request");
    for (size_t i = 0; i < request->count; ++i)
        if (!request->ports[i])
            return runner_error(NM_NMAP_RUN_ERROR, 0, "Invalid TCP port");
    if (request->cancellation && atomic_load(request->cancellation))
        return runner_error(NM_NMAP_RUN_CANCELLED, 0, "Nmap command was cancelled.");
    const char *host = request->host;
    const uint16_t *ports = request->count       ? request->ports
                            : request->fast_scan ? fast_ports
                                                 : common_ports;
    const size_t count = request->count       ? request->count
                         : request->fast_scan ? sizeof(fast_ports) / sizeof(fast_ports[0])
                                              : sizeof(common_ports) / sizeof(common_ports[0]);

    int64_t started = esp_timer_get_time();
    unsigned budget = request->timeout_ms;
    struct addrinfo *addresses = NULL;
    lookup_result lookup = request->cancellation
                               ? nm_endpoint_resolve_cancelable(host, ports[0], budget, &addresses,
                                                                request->cancellation)
                               : nm_endpoint_resolve(host, ports[0], budget, &addresses);
    if (lookup != LOOKUP_OK) {
        nm_esp_result failed =
            nm_endpoint_lookup_failure("rawconnect", lookup, nm_endpoint_elapsed(started));
        nm_nmap_run_state state = lookup == LOOKUP_CANCELLED ? NM_NMAP_RUN_CANCELLED
                                  : lookup == LOOKUP_TIMEOUT ? NM_NMAP_RUN_TIMED_OUT
                                  : failed.disposition == NM_PROBE_LOCAL_FAILURE
                                      ? NM_NMAP_RUN_LOCAL_FAILURE
                                      : NM_NMAP_RUN_ERROR;
        nm_nmap_run_result result =
            runner_error(state, nm_endpoint_elapsed(started), failed.message);
        return result;
    }

    bool arp_up = false, skip_tcp = false;
    if (!request->no_ping) {
        const struct addrinfo *v4 = addresses;
        while (v4 && v4->ai_family != AF_INET)
            v4 = v4->ai_next;
        nm_nmap_arp_result arp = {.state = NM_ARP_OFF_LINK};
        if (v4 && v4->ai_addr && v4->ai_addrlen >= sizeof(struct sockaddr_in)) {
            unsigned remaining = nm_endpoint_remaining(started, budget);
            uint32_t ip = ntohl(((const struct sockaddr_in *)v4->ai_addr)->sin_addr.s_addr);
            arp = nm_nmap_arp_probe(
                ip, remaining < NMAP_DISCOVERY_PER_HOST_MS ? remaining : NMAP_DISCOVERY_PER_HOST_MS,
                request->cancellation);
        }
        if (arp.state == NM_ARP_LOCAL_FAILURE || arp.state == NM_ARP_ERROR ||
            arp.state == NM_ARP_CANCELLED || (request->arp_only && arp.state == NM_ARP_OFF_LINK)) {
            freeaddrinfo(addresses);
            return runner_error(arp.state == NM_ARP_CANCELLED       ? NM_NMAP_RUN_CANCELLED
                                : arp.state == NM_ARP_LOCAL_FAILURE ? NM_NMAP_RUN_LOCAL_FAILURE
                                                                    : NM_NMAP_RUN_ERROR,
                                nm_endpoint_elapsed(started),
                                arp.state == NM_ARP_CANCELLED  ? "Nmap command was cancelled."
                                : arp.state == NM_ARP_OFF_LINK ? "-PR requires a local IPv4 target"
                                                               : "ARP discovery could not execute");
        }
        arp_up = arp.state == NM_ARP_REPLY;
        skip_tcp = request->arp_only && arp.state == NM_ARP_TIMEOUT;
    }

    char *report = nm_bulk_calloc(NMAP_MAX_REPORT, 1);
    if (!report) {
        freeaddrinfo(addresses);
        return runner_error(NM_NMAP_RUN_LOCAL_FAILURE, nm_endpoint_elapsed(started),
                            "Unable to allocate bounded Nmap output");
    }
    size_t used = 0;
    bool reachable = request->no_ping || arp_up, deadline_hit = false, report_ok = true;
    uint16_t open_ports[64];
    uint8_t states[64]; /* 1=open, 2=closed, 3=filtered/unknown. */
    int errors[64];
    size_t open_count = 0;
    int last_error = 0;
    const size_t scanned_count = skip_tcp ? 0 : count;
    for (size_t i = 0; report_ok && i < scanned_count; ++i) {
        uint16_t port = ports[i];
        unsigned remaining = nm_endpoint_remaining(started, budget);
        if (!remaining) {
            deadline_hit = true;
            break;
        }
        unsigned per_port =
            count == 1
                ? remaining
                : (remaining < NMAP_DEFAULT_PER_PORT_MS ? remaining : NMAP_DEFAULT_PER_PORT_MS);
        last_error = 0;
        int probe = probe_port(addresses, port, started, budget, per_port, &last_error,
                               request->cancellation);
        if (probe < 0) {
            free(report);
            freeaddrinfo(addresses);
            return runner_error(probe == -3   ? NM_NMAP_RUN_CANCELLED
                                : probe == -1 ? NM_NMAP_RUN_LOCAL_FAILURE
                                              : NM_NMAP_RUN_TIMED_OUT,
                                nm_endpoint_elapsed(started),
                                probe == -3   ? "Nmap command was cancelled."
                                : probe == -1 ? strerror(last_error ? last_error : ENOMEM)
                                              : "TCP scan deadline exceeded");
        }
        reachable =
            reachable || probe == 1 || last_error == ECONNREFUSED || last_error == ECONNRESET;
        states[i] = probe == 1 ? 1 : last_error == ECONNREFUSED || last_error == ECONNRESET ? 2 : 3;
        errors[i] = last_error;
        if (probe == 1)
            open_ports[open_count++] = port;
    }
    freeaddrinfo(addresses);
    if (request->cancellation && atomic_load(request->cancellation)) {
        free(report);
        return runner_error(NM_NMAP_RUN_CANCELLED, nm_endpoint_elapsed(started),
                            "Nmap command was cancelled.");
    }
    deadline_hit |= !nm_endpoint_remaining(started, budget);
    if (!report_ok || deadline_hit) {
        free(report);
        return runner_error(deadline_hit ? NM_NMAP_RUN_TIMED_OUT : NM_NMAP_RUN_LOCAL_FAILURE,
                            nm_endpoint_elapsed(started),
                            deadline_hit ? "TCP scan deadline exceeded"
                                         : "Nmap output limit exceeded");
    }

    report_ok = append_report(report, NMAP_MAX_REPORT, &used, "Nmap scan report for %s\n%s\n", host,
                              reachable ? "Host is up" : "Host seems down");
    bool any_reported = false;
    for (size_t i = 0; i < scanned_count; ++i)
        any_reported |= !request->show_open || states[i] == 1;
    if (report_ok && any_reported)
        report_ok =
            append_report(report, NMAP_MAX_REPORT, &used,
                          request->show_reason ? "PORT     STATE     SERVICE        REASON\n"
                                               : "PORT     STATE     SERVICE\n");
    for (size_t i = 0; report_ok && i < scanned_count; ++i) {
        if (request->show_open && states[i] != 1)
            continue;
        const char *state = states[i] == 1 ? "open" : states[i] == 2 ? "closed" : "filtered";
        const char *reason = states[i] == 1              ? "connect"
                             : errors[i] == ECONNREFUSED ? "conn-refused"
                             : errors[i] == ECONNRESET   ? "conn-reset"
                             : errors[i] == ETIMEDOUT    ? "no-response"
                             : errors[i]                 ? "network-error"
                                                         : "no-response";
        char service[64] = "unknown";
        (void)nm_service_hint_lookup(ports[i], service, sizeof(service));
        report_ok = request->show_reason
                        ? append_report(report, NMAP_MAX_REPORT, &used, "%u/tcp %-9s %-14s %s\n",
                                        ports[i], state, service, reason)
                        : append_report(report, NMAP_MAX_REPORT, &used, "%u/tcp %-9s %s\n",
                                        ports[i], state, service);
    }
    if (report_ok && request->verbosity)
        report_ok = append_report(report, NMAP_MAX_REPORT, &used,
                                  "Scanned %zu TCP ports in %u ms; open ports: %zu\n",
                                  scanned_count, nm_endpoint_elapsed(started), open_count);
    if (!report_ok) {
        free(report);
        return runner_error(NM_NMAP_RUN_LOCAL_FAILURE, nm_endpoint_elapsed(started),
                            "Nmap output limit exceeded");
    }
    nm_nmap_run_result result = {.state = NM_NMAP_RUN_COMPLETED,
                                 .exit_code = 0,
                                 .elapsed_ms = nm_endpoint_elapsed(started),
                                 .standard_output = report};
    result.open_count = open_count;
    memcpy(result.open_ports, open_ports, open_count * sizeof(*open_ports));
    return result;
}

typedef struct {
    nm_nmap_run_state state;
    bool up, has_mac;
    uint8_t mac[6];
    const char *reason;
    char error[192];
} discovery_observation;

static discovery_observation discover_target(const char *target, unsigned timeout, bool arp_only,
                                             const atomic_bool *cancellation)
{
    discovery_observation result = {.state = NM_NMAP_RUN_COMPLETED, .reason = "no-response"};
    int64_t started = esp_timer_get_time();
    uint32_t ipv4;
    bool is_v4 = nm_nmap_ipv4_parse(target, &ipv4);
    char numeric[48];
    if (!is_v4) {
        struct addrinfo *addresses = NULL;
        lookup_result lookup =
            nm_endpoint_resolve_cancelable(target, 0, timeout, &addresses, cancellation);
        if (lookup != LOOKUP_OK) {
            result.state = lookup == LOOKUP_CANCELLED ? NM_NMAP_RUN_CANCELLED
                           : lookup == LOOKUP_BUSY || lookup == LOOKUP_NO_MEMORY
                               ? NM_NMAP_RUN_LOCAL_FAILURE
                           : lookup == LOOKUP_TIMEOUT ? NM_NMAP_RUN_TIMED_OUT
                                                      : NM_NMAP_RUN_ERROR;
            snprintf(result.error, sizeof(result.error), "Host-discovery DNS failed");
            return result;
        }
        bool formatted = nm_endpoint_address_text(addresses, numeric, sizeof(numeric));
        is_v4 = formatted && nm_nmap_ipv4_parse(numeric, &ipv4);
        freeaddrinfo(addresses);
        if (!formatted) {
            result.state = NM_NMAP_RUN_ERROR;
            snprintf(result.error, sizeof(result.error), "No supported discovery address");
            return result;
        }
        target = numeric;
    }
    nm_nmap_arp_result arp = {.state = NM_ARP_OFF_LINK};
    if (is_v4)
        arp = nm_nmap_arp_probe(ipv4, nm_endpoint_remaining(started, timeout), cancellation);
    if (arp.state == NM_ARP_REPLY) {
        result.up = result.has_mac = true;
        result.reason = arp.local_interface ? "localhost-response" : "arp-response";
        memcpy(result.mac, arp.mac, sizeof(result.mac));
    } else if (arp.state == NM_ARP_TIMEOUT) {
        /* A local ARP probe already used this target's discovery budget. */
    } else if (arp.state != NM_ARP_OFF_LINK || arp_only) {
        result.state = arp.state == NM_ARP_CANCELLED       ? NM_NMAP_RUN_CANCELLED
                       : arp.state == NM_ARP_LOCAL_FAILURE ? NM_NMAP_RUN_LOCAL_FAILURE
                                                           : NM_NMAP_RUN_ERROR;
        snprintf(result.error, sizeof(result.error), "%s",
                 arp.state == NM_ARP_CANCELLED  ? "Nmap command was cancelled."
                 : arp.state == NM_ARP_OFF_LINK ? "-PR requires a local IPv4 target"
                                                : "ARP discovery could not execute");
    } else {
        unsigned remaining = nm_endpoint_remaining(started, timeout);
        if (!remaining) {
            result.state = NM_NMAP_RUN_TIMED_OUT;
            return result;
        }
        nm_esp_result ping = nm_endpoint_check_icmp_cancelable(target, remaining, cancellation);
        if (cancellation && atomic_load(cancellation))
            result.state = NM_NMAP_RUN_CANCELLED;
        else if (ping.disposition == NM_PROBE_LOCAL_FAILURE)
            result.state = NM_NMAP_RUN_LOCAL_FAILURE;
        else if (!ping.ok && !strcmp(ping.status, "Exception"))
            result.state = NM_NMAP_RUN_ERROR;
        result.up = ping.ok;
        result.reason = ping.ok ? "echo-reply" : "no-response";
        if (result.state != NM_NMAP_RUN_COMPLETED)
            snprintf(result.error, sizeof(result.error), "Host discovery failed: %.150s",
                     ping.message);
        nm_esp_result_release(&ping);
    }
    return result;
}

nm_nmap_run_result nm_nmap_runner_discover(const nm_nmap_discovery_request *request)
{
    if (!request || !request->display_target || !*request->display_target ||
        !request->target_count || request->target_count > NM_NMAP_MAX_TARGETS ||
        !request->timeout_ms || strlen(request->display_target) > 253 ||
        (!request->has_ipv4_range && request->target_count != 1) ||
        (request->has_ipv4_range &&
         request->first_ipv4 > UINT32_MAX - ((uint32_t)request->target_count - 1)))
        return runner_error(NM_NMAP_RUN_ERROR, 0, "Invalid bounded host-discovery request");

    int64_t started = esp_timer_get_time();
    char *report = nm_bulk_calloc(NMAP_MAX_REPORT, 1);
    if (!report)
        return runner_error(NM_NMAP_RUN_LOCAL_FAILURE, 0,
                            "Unable to allocate bounded discovery output");
    size_t used = 0;
    unsigned up_count = 0;
    if (!append_report(report, NMAP_MAX_REPORT, &used, "Nmap scan report for %s\n",
                       request->display_target))
        goto output_limit;

    for (uint16_t i = 0; i < request->target_count; ++i) {
        if (request->cancellation && atomic_load(request->cancellation)) {
            free(report);
            return runner_error(NM_NMAP_RUN_CANCELLED, nm_endpoint_elapsed(started),
                                "Nmap command was cancelled.");
        }
        unsigned remaining = nm_endpoint_remaining(started, request->timeout_ms);
        if (!remaining) {
            free(report);
            return runner_error(NM_NMAP_RUN_TIMED_OUT, nm_endpoint_elapsed(started),
                                "Host-discovery deadline exceeded");
        }
        char address[16];
        const char *target = request->display_target;
        unsigned probe_timeout = remaining;
        if (request->has_ipv4_range) {
            if (!nm_nmap_ipv4_format(request->first_ipv4 + i, address, sizeof(address))) {
                free(report);
                return runner_error(NM_NMAP_RUN_ERROR, nm_endpoint_elapsed(started),
                                    "Unable to format IPv4 target");
            }
            target = address;
            if (probe_timeout > NMAP_DISCOVERY_PER_HOST_MS)
                probe_timeout = NMAP_DISCOVERY_PER_HOST_MS;
        }

        discovery_observation observed =
            discover_target(target, probe_timeout, request->arp_only, request->cancellation);
        if (observed.state != NM_NMAP_RUN_COMPLETED) {
            free(report);
            return runner_error(observed.state, nm_endpoint_elapsed(started),
                                observed.error[0] ? observed.error : "Host discovery failed");
        }
        bool appended = true;
        if (observed.up) {
            appended = request->has_ipv4_range
                           ? append_report(report, NMAP_MAX_REPORT, &used, "Host: %s is up", target)
                           : append_report(report, NMAP_MAX_REPORT, &used, "Host is up");
            if (appended && observed.has_mac)
                appended = append_report(report, NMAP_MAX_REPORT, &used,
                                         "; MAC Address: %02X:%02X:%02X:%02X:%02X:%02X",
                                         observed.mac[0], observed.mac[1], observed.mac[2],
                                         observed.mac[3], observed.mac[4], observed.mac[5]);
            if (appended && request->show_reason)
                appended =
                    append_report(report, NMAP_MAX_REPORT, &used, "; reason=%s", observed.reason);
            if (appended)
                appended = append_report(report, NMAP_MAX_REPORT, &used, "\n");
            ++up_count;
        } else if (!request->has_ipv4_range) {
            appended = append_report(report, NMAP_MAX_REPORT, &used,
                                     request->show_reason ? "Host seems down; reason=no-response\n"
                                                          : "Host seems down\n");
        }
        if (!appended)
            goto output_limit;
    }

    if (request->cancellation && atomic_load(request->cancellation)) {
        free(report);
        return runner_error(NM_NMAP_RUN_CANCELLED, nm_endpoint_elapsed(started),
                            "Nmap command was cancelled.");
    }
    if (!nm_endpoint_remaining(started, request->timeout_ms)) {
        free(report);
        return runner_error(NM_NMAP_RUN_TIMED_OUT, nm_endpoint_elapsed(started),
                            "Host-discovery deadline exceeded");
    }
    if (request->has_ipv4_range || request->verbosity) {
        if (!append_report(report, NMAP_MAX_REPORT, &used,
                           "Nmap done: %u IP addresses (%u hosts up) scanned",
                           request->target_count, up_count))
            goto output_limit;
        if (request->verbosity && !append_report(report, NMAP_MAX_REPORT, &used, " in %u ms",
                                                 nm_endpoint_elapsed(started)))
            goto output_limit;
        if (!append_report(report, NMAP_MAX_REPORT, &used, "\n"))
            goto output_limit;
    }
    return (nm_nmap_run_result){.state = NM_NMAP_RUN_COMPLETED,
                                .exit_code = 0,
                                .elapsed_ms = nm_endpoint_elapsed(started),
                                .standard_output = report};

output_limit:
    free(report);
    return runner_error(NM_NMAP_RUN_LOCAL_FAILURE, nm_endpoint_elapsed(started),
                        "Host-discovery output exceeds the embedded limit");
}

void nm_nmap_runner_result_release(nm_nmap_run_result *result)
{
    if (!result)
        return;
    free(result->standard_output);
    result->standard_output = NULL;
}
