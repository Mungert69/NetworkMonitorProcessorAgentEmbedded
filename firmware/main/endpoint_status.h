#ifndef NM_ENDPOINT_STATUS_H
#define NM_ENDPOINT_STATUS_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/*
 * Portable wire mapping for HTTPConnect, ICMPConnect, DNSConnect and
 * SocketConnect (rawconnect). No ESP-IDF or JSON dependency.
 *
 * HTTP enum names were checked against the installed .NET 10 runtime.
 * Duplicate enum aliases are runtime-dependent: notably 307 currently yields
 * RedirectKeepVerb. Recheck the oracle when changing the backend runtime.
 * Unnamed response codes retain their decimal representation.
 *
 * Integration: classify the actual outcome in endpoints.c, copy status/ok,
 * and use nm_endpoint_rtt at the state.c wire boundary instead of saturation.
 * Timing remains the caller's responsibility: rawconnect excludes DNS,
 * ICMP uses the reply RTT, DNS/HTTP measure their operation.
 * This helper does not build diagnostic messages or mutate monitor counters.
 */
typedef enum {
    NM_ENDPOINT_SUCCESS,
    NM_ENDPOINT_TIMEOUT,
    NM_ENDPOINT_EXCEPTION,
    NM_ENDPOINT_HTTP_REQUEST_EXCEPTION,
    NM_ENDPOINT_NO_ADDRESSES,
    NM_ENDPOINT_PING_REPLY_NULL,
    NM_ENDPOINT_PING_CANCELED
} nm_endpoint_outcome;

typedef struct {
    bool ok;
    uint16_t rtt;
    char status[40];
} nm_endpoint_status_result;

static inline uint16_t nm_endpoint_rtt(bool ok, uint64_t elapsed_ms)
{
    /* Match NetConnect.ProcessException and unchecked (ushort) success casts.
     * A successful 65535 ms sample is still up: never infer ok from RTT. */
    return ok ? (uint16_t)elapsed_ms : UINT16_MAX;
}

static inline bool nm_endpoint_ascii_prefix(const char *text, const char *prefix)
{
    for (; *prefix; ++text, ++prefix) {
        unsigned char c = (unsigned char)*text;
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + ('a' - 'A'));
        if (c != (unsigned char)*prefix) return false;
    }
    return true;
}

/* Bounded HTTP(S) URL assembly, including bracketed IPv6, paths and queries.
 * Like HTTPConnect: a non-default port in an absolute URL wins; otherwise a
 * nonzero monitor Port wins. On schemeless addresses Port overrides any port.
 * Intentionally keep HTTPS as the default for an https monitor (the .NET
 * implementation currently defaults every schemeless address to HTTP).
 * Credentials, bare IPv6, whitespace, backslashes and non-HTTP schemes are
 * rejected rather than ambiguously reinterpreted. International hostnames
 * must be supplied as ASCII/punycode. Fragments are not sent to the server.
 * Input and output must not overlap. The HTTP client validates IPv6 syntax.
 */
static inline bool nm_endpoint_http_url(const char *address, bool default_tls,
                                        unsigned monitor_port, char *out, size_t size)
{
    if (!out || !size) return false;
    out[0] = '\0';
    if (!address || !*address || monitor_port > 65535) return false;
    size_t length = 0;
    for (; length <= 1024 && address[length]; ++length) {
        unsigned char c = (unsigned char)address[length];
        if (c <= 32 || c >= 127 || c == '\\') return false;
    }
    if (length > 1024) return false;
    bool absolute = false, tls = default_tls;
    const char *authority = address;
    if (nm_endpoint_ascii_prefix(address, "https://")) {
        absolute = true; tls = true; authority += 8;
    } else if (nm_endpoint_ascii_prefix(address, "http://")) {
        absolute = true; tls = false; authority += 7;
    }
    const char *end = authority + strcspn(authority, "/?#");
    if (end == authority) return false;
    const char *host_end = end, *port_start = NULL;
    if (*authority == '[') {
        const char *close = memchr(authority, ']', (size_t)(end - authority));
        if (!close || close == authority + 1) return false;
        bool colon = false;
        for (const char *p = authority + 1; p < close; ++p) {
            if (*p == ':') colon = true;
            else if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') ||
                       (*p >= 'A' && *p <= 'F') || *p == '.')) return false;
        }
        if (!colon) return false;
        host_end = close + 1;
        if (host_end != end) {
            if (*host_end != ':') return false;
            port_start = host_end + 1;
        }
    } else {
        for (const char *p = authority; p < end; ++p) {
            if (*p == ':') { host_end = p; port_start = p + 1; break; }
            if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                  (*p >= '0' && *p <= '9') || *p == '.' || *p == '-' || *p == '_'))
                return false;
        }
        if (host_end == authority) return false;
    }
    unsigned default_port = tls ? 443 : 80, embedded_port = default_port;
    if (port_start) {
        if (port_start == end) return false;
        embedded_port = 0;
        for (const char *p = port_start; p < end; ++p) {
            if (*p < '0' || *p > '9') return false;
            embedded_port = embedded_port * 10 + (unsigned)(*p - '0');
            if (embedded_port > 65535) return false;
        }
        if (!embedded_port) return false;
    }
    unsigned port = absolute && embedded_port != default_port ? embedded_port :
                    monitor_port ? monitor_port : embedded_port;
    const char *fragment = strchr(end, '#');
    size_t tail_size = fragment ? (size_t)(fragment - end) : strlen(end);
    int written = snprintf(out, size, "%s://%.*s:%u%s%.*s", tls ? "https" : "http",
                           (int)(host_end - authority), authority, port,
                           *end == '/' ? "" : "/", (int)tail_size, end);
    if (written < 0 || (size_t)written >= size) { out[0] = '\0'; return false; }
    return true;
}

static inline const char *nm_endpoint_http_name(int code)
{
    switch (code) {
    case 100: return "Continue";
    case 101: return "SwitchingProtocols";
    case 102: return "Processing";
    case 103: return "EarlyHints";
    case 200: return "OK";
    case 201: return "Created";
    case 202: return "Accepted";
    case 203: return "NonAuthoritativeInformation";
    case 204: return "NoContent";
    case 205: return "ResetContent";
    case 206: return "PartialContent";
    case 207: return "MultiStatus";
    case 208: return "AlreadyReported";
    case 226: return "IMUsed";
    case 300: return "MultipleChoices";
    case 301: return "MovedPermanently";
    case 302: return "Found";
    case 303: return "SeeOther";
    case 304: return "NotModified";
    case 305: return "UseProxy";
    case 306: return "Unused";
    case 307: return "RedirectKeepVerb";
    case 308: return "PermanentRedirect";
    case 400: return "BadRequest";
    case 401: return "Unauthorized";
    case 402: return "PaymentRequired";
    case 403: return "Forbidden";
    case 404: return "NotFound";
    case 405: return "MethodNotAllowed";
    case 406: return "NotAcceptable";
    case 407: return "ProxyAuthenticationRequired";
    case 408: return "RequestTimeout";
    case 409: return "Conflict";
    case 410: return "Gone";
    case 411: return "LengthRequired";
    case 412: return "PreconditionFailed";
    case 413: return "RequestEntityTooLarge";
    case 414: return "RequestUriTooLong";
    case 415: return "UnsupportedMediaType";
    case 416: return "RequestedRangeNotSatisfiable";
    case 417: return "ExpectationFailed";
    case 421: return "MisdirectedRequest";
    case 422: return "UnprocessableEntity";
    case 423: return "Locked";
    case 424: return "FailedDependency";
    case 426: return "UpgradeRequired";
    case 428: return "PreconditionRequired";
    case 429: return "TooManyRequests";
    case 431: return "RequestHeaderFieldsTooLarge";
    case 451: return "UnavailableForLegalReasons";
    case 500: return "InternalServerError";
    case 501: return "NotImplemented";
    case 502: return "BadGateway";
    case 503: return "ServiceUnavailable";
    case 504: return "GatewayTimeout";
    case 505: return "HttpVersionNotSupported";
    case 506: return "VariantAlsoNegotiates";
    case 507: return "InsufficientStorage";
    case 508: return "LoopDetected";
    case 510: return "NotExtended";
    case 511: return "NetworkAuthenticationRequired";
    default: return NULL;
    }
}

static inline nm_endpoint_status_result nm_endpoint_status(
    const char *type, nm_endpoint_outcome outcome, int http_code,
    uint64_t elapsed_ms)
{
    nm_endpoint_status_result result = {
        .ok = false, .rtt = UINT16_MAX, .status = "Exception"
    };
    if (!type) return result;
    bool http = !strcmp(type, "http") || !strcmp(type, "httphtml") ||
                !strcmp(type, "https");
    bool icmp = !strcmp(type, "icmp");
    bool dns = !strcmp(type, "dns");
    bool tcp = !strcmp(type, "rawconnect");
    if (!http && !icmp && !dns && !tcp) return result;

    const char *status = "Exception";
    if (outcome == NM_ENDPOINT_SUCCESS) {
        if (http) {
            /* HttpClient accepts three-digit final responses beyond 599 too.
             * Caller must provide a completed response, not interim headers. */
            if (http_code < 100 || http_code > 999) return result;
            status = nm_endpoint_http_name(http_code);
            if (!status)
                snprintf(result.status, sizeof(result.status), "%d", http_code);
        } else {
            status = icmp ? "Success" : dns ? "Found IP Addresses" : "Connected";
        }
        result.ok = true;
    } else if (outcome == NM_ENDPOINT_TIMEOUT) {
        status = http ? "Timeout" : tcp ? "Connection timed out." : "Exception";
    } else if (http && outcome == NM_ENDPOINT_HTTP_REQUEST_EXCEPTION) {
        status = "HttpRequestException";
    } else if (tcp && outcome == NM_ENDPOINT_NO_ADDRESSES) {
        status = "Unable to resolve domain.";
    } else if (icmp && outcome == NM_ENDPOINT_PING_REPLY_NULL) {
        status = "Ping Reply Null";
    } else if (icmp && outcome == NM_ENDPOINT_PING_CANCELED) {
        /* Explicit cancellation result; actual .NET callback may overwrite
         * this with Ping Reply Null because it does not return early. */
        status = "Ping Canceled";
    }
    if (status) snprintf(result.status, sizeof(result.status), "%s", status);
    result.rtt = nm_endpoint_rtt(result.ok, elapsed_ms);
    return result;
}

#endif
