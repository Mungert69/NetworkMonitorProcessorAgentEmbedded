#include "endpoint_internal.h"
#include "nmap_runner.h"
#include <stdio.h>
#include <string.h>
#include <strings.h>

enum { NMAP_MAX_HOST = 253, NMAP_MAX_PORT_TEXT = 6 };

static bool valid_authority_port(const char *start, const char *end)
{
    if (start == end)
        return true;
    if (*start++ != ':' || start == end || end - start > 5)
        return false;
    unsigned port = 0;
    for (; start < end; ++start) {
        if (*start < '0' || *start > '9')
            return false;
        port = port * 10U + (unsigned)(*start - '0');
    }
    return port > 0 && port <= UINT16_MAX;
}

/* Mirrors the .NET StripHttpProtocol() input handling while rejecting
 * ambiguous authorities. No user-provided Args are passed to the runner. */
static bool target_host(const char *address, char *host, size_t host_size)
{
    if (!address || !host || host_size < 2)
        return false;
    const char *start = address;
    if (!strncasecmp(start, "http://", 7))
        start += 7;
    else if (!strncasecmp(start, "https://", 8))
        start += 8;
    const char *end = start;
    while (*end && *end != '/' && *end != '?' && *end != '#') {
        unsigned char c = (unsigned char)*end;
        if (c <= 32 || c >= 127 || c == '\\' || c == '@')
            return false;
        ++end;
    }
    size_t length = (size_t)(end - start);
    if (!length)
        return false;
    if (start[0] == '[') {
        const char *close = memchr(start + 1, ']', length - 1);
        if (!close || close == start + 1 || !valid_authority_port(close + 1, end))
            return false;
        ++start;
        length = (size_t)(close - start);
    } else {
        if (memchr(start, '[', length) || memchr(start, ']', length))
            return false;
        const char *colon = memchr(start, ':', length);
        if (colon && !memchr(colon + 1, ':', (size_t)(end - colon - 1))) {
            if (colon == start || !valid_authority_port(colon, end))
                return false;
            length = (size_t)(colon - start);
        }
    }
    if (length > NMAP_MAX_HOST || length >= host_size)
        return false;
    memcpy(host, start, length);
    host[length] = '\0';
    return true;
}

static bool contains_ascii_case_insensitive(const char *text, const char *needle)
{
    if (!text || !needle || !*needle)
        return false;
    size_t needle_length = strlen(needle);
    for (const char *start = text; *start; ++start) {
        size_t i = 0;
        while (i < needle_length && start[i] && (unsigned char)start[i] < 128 &&
               (unsigned char)needle[i] < 128 && ((start[i] | 32) == (needle[i] | 32)))
            ++i;
        if (i == needle_length)
            return true;
    }
    return false;
}

static nm_esp_result nmap_failure(unsigned elapsed, const char *status, const char *detail)
{
    nm_esp_result result = {.ok = false, .elapsed_ms = elapsed};
    snprintf(result.status, sizeof(result.status), "%s", status);
    snprintf(result.message, sizeof(result.message), "NMAP: Failed to connect: %.140s",
             detail ? detail : "Nmap runner failed");
    return result;
}

nm_esp_result nm_endpoint_check_nmap(const char *address, unsigned configured_port,
                                     unsigned timeout_ms)
{
    char host[NMAP_MAX_HOST + 1];
    char port_text[NMAP_MAX_PORT_TEXT];
    if (!target_host(address, host, sizeof(host)))
        return nmap_failure(0, "Exception", "Invalid target address");
    if (configured_port > UINT16_MAX)
        return nmap_failure(0, "Exception", "Invalid TCP port");

    /* These tokens intentionally resemble the .NET NmapCmdConnect command.
     * They are passed directly to the runner; no shell parsing is involved. */
    const char *argv[6];
    size_t argc = 0;
    if (configured_port) {
        int length = snprintf(port_text, sizeof(port_text), "%u", configured_port);
        if (length <= 0 || (size_t)length >= sizeof(port_text))
            return nmap_failure(0, "Exception", "Invalid TCP port");
        argv[argc++] = "nmap";
        argv[argc++] = "-sV";
        argv[argc++] = "--system-dns";
        argv[argc++] = "-p";
        argv[argc++] = port_text;
        argv[argc++] = host;
    } else {
        argv[argc++] = "nmap";
        argv[argc++] = "-sV";
        argv[argc++] = "--system-dns";
        argv[argc++] = host;
    }

    nm_nmap_run_result run = nm_nmap_runner_execute(argv, argc, timeout_ms);
    if (run.state == NM_NMAP_RUN_LOCAL_FAILURE) {
        nm_esp_result failed = nm_endpoint_local_failure(
            run.elapsed_ms, run.error[0] ? run.error : "Nmap local resource failure");
        nm_nmap_runner_result_release(&run);
        return failed;
    }
    if (run.state == NM_NMAP_RUN_TIMED_OUT) {
        nm_esp_result failed = nmap_failure(
            run.elapsed_ms, "Exception", run.error[0] ? run.error : "TCP scan deadline exceeded");
        nm_nmap_runner_result_release(&run);
        return failed;
    }
    if (run.state != NM_NMAP_RUN_COMPLETED || run.exit_code != 0) {
        nm_esp_result failed = nmap_failure(run.elapsed_ms, "Exception",
                                            run.error[0] ? run.error : "Nmap runner error");
        nm_nmap_runner_result_release(&run);
        return failed;
    }

    const char *output = run.standard_output ? run.standard_output : "";
    bool host_up = contains_ascii_case_insensitive(output, "Host is up");
    bool host_down = contains_ascii_case_insensitive(output, "Host seems down") ||
                     contains_ascii_case_insensitive(output, "0 hosts up");
    if (!host_up && !host_down) {
        nm_esp_result failed = nmap_failure(run.elapsed_ms, "Host status unknown",
                                            "Nmap output did not include a host status");
        nm_nmap_runner_result_release(&run);
        return failed;
    }

    nm_esp_result result = {.ok = host_up, .elapsed_ms = run.elapsed_ms};
    snprintf(result.status, sizeof(result.status), "%s", host_up ? "Port/s open" : "Port/s closed");
    if (host_up)
        snprintf(result.message, sizeof(result.message), "%s", "Port/s open");
    else
        snprintf(result.message, sizeof(result.message), "%s",
                 "NMAP: Failed to connect: Host seems down");
    result.detail_message = run.standard_output;
    run.standard_output = NULL;
    nm_nmap_runner_result_release(&run);
    return result;
}
