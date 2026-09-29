#include "endpoint_status.h"
#include <assert.h>
#include <limits.h>
#include <stdio.h>

/* Standalone, no network/ESP-IDF/JSON dependencies:
 * cc -std=c17 -Wall -Wextra -Wpedantic -Werror -UNDEBUG -Ifirmware/main \
 *   tests/native/test_endpoint_status.c -o /tmp/test_endpoint_status
 * /tmp/test_endpoint_status
 * --http-table emits all 100..599 mappings for comparison with the backend's
 * foreach code: ((System.Net.HttpStatusCode)code).ToString() oracle.
 */
static void expect(const char *type, nm_endpoint_outcome outcome, int code,
                   uint64_t elapsed, bool ok, const char *status, uint16_t rtt)
{
    nm_endpoint_status_result result = nm_endpoint_status(type, outcome, code, elapsed);
    assert(result.ok == ok);
    assert(strcmp(result.status, status) == 0);
    assert(result.rtt == rtt);
}

static void http_statuses(void)
{
    /* Golden examples include aliases, unnamed codes, errors that still mean
     * reachable, and valid three-digit extensions outside the usual range. */
    const struct { int code; const char *status; } cases[] = {
        {100, "Continue"}, {103, "EarlyHints"}, {200, "OK"}, {204, "NoContent"},
        {300, "MultipleChoices"}, {301, "MovedPermanently"}, {302, "Found"},
        {303, "SeeOther"}, {307, "RedirectKeepVerb"}, {308, "PermanentRedirect"},
        {404, "NotFound"}, {408, "RequestTimeout"}, {418, "418"},
        {422, "UnprocessableEntity"}, {425, "425"}, {429, "TooManyRequests"},
        {500, "InternalServerError"}, {504, "GatewayTimeout"},
        {511, "NetworkAuthenticationRequired"}, {599, "599"},
        {600, "600"}, {999, "999"}
    };
    const char *types[] = {"http", "https", "httphtml"};
    for (size_t t = 0; t < sizeof(types) / sizeof(types[0]); ++t) {
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
            expect(types[t], NM_ENDPOINT_SUCCESS, cases[i].code, 17,
                   true, cases[i].status, 17);
        expect(types[t], NM_ENDPOINT_TIMEOUT, 200, 123, false, "Timeout", UINT16_MAX);
        expect(types[t], NM_ENDPOINT_HTTP_REQUEST_EXCEPTION, 200, 123,
               false, "HttpRequestException", UINT16_MAX);
        expect(types[t], NM_ENDPOINT_EXCEPTION, 200, 123, false, "Exception", UINT16_MAX);
        const int invalid[] = {INT_MIN, -1, 0, 99, 1000, INT_MAX};
        for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
            expect(types[t], NM_ENDPOINT_SUCCESS, invalid[i], 17,
                   false, "Exception", UINT16_MAX);
    }
}

static void other_endpoints(void)
{
    expect("icmp", NM_ENDPOINT_SUCCESS, 0, 3, true, "Success", 3);
    expect("icmp", NM_ENDPOINT_TIMEOUT, 0, 10000, false, "Exception", UINT16_MAX);
    expect("icmp", NM_ENDPOINT_EXCEPTION, 0, 0, false, "Exception", UINT16_MAX);
    expect("icmp", NM_ENDPOINT_PING_REPLY_NULL, 0, 0, false, "Ping Reply Null", UINT16_MAX);
    expect("icmp", NM_ENDPOINT_PING_CANCELED, 0, 0, false, "Ping Canceled", UINT16_MAX);
    expect("dns", NM_ENDPOINT_SUCCESS, 0, 4, true, "Found IP Addresses", 4);
    expect("dns", NM_ENDPOINT_TIMEOUT, 0, 10000, false, "Exception", UINT16_MAX);
    expect("dns", NM_ENDPOINT_EXCEPTION, 0, 0, false, "Exception", UINT16_MAX);
    expect("dns", NM_ENDPOINT_NO_ADDRESSES, 0, 0, false, "Exception", UINT16_MAX);
    expect("rawconnect", NM_ENDPOINT_SUCCESS, 0, 5, true, "Connected", 5);
    expect("rawconnect", NM_ENDPOINT_TIMEOUT, 0, 10000,
           false, "Connection timed out.", UINT16_MAX);
    expect("rawconnect", NM_ENDPOINT_NO_ADDRESSES, 0, 0,
           false, "Unable to resolve domain.", UINT16_MAX);
    expect("rawconnect", NM_ENDPOINT_EXCEPTION, 0, 0, false, "Exception", UINT16_MAX);
    expect(NULL, NM_ENDPOINT_SUCCESS, 200, 0, false, "Exception", UINT16_MAX);
    expect("", NM_ENDPOINT_SUCCESS, 200, 0, false, "Exception", UINT16_MAX);
}

static void rtt_and_sequences(void)
{
    const struct { uint64_t elapsed; uint16_t rtt; } cases[] = {
        {0, 0}, {1, 1}, {65534, 65534}, {65535, 65535}, {65536, 0},
        {70000, 4464}, {600000, 10176}, {UINT32_MAX, 65535}, {UINT64_MAX, 65535}
    };
    const char *types[] = {"icmp", "dns", "rawconnect", "http", "httphtml", "https"};
    for (size_t t = 0; t < sizeof(types) / sizeof(types[0]); ++t) {
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            nm_endpoint_status_result result = nm_endpoint_status(
                types[t], NM_ENDPOINT_SUCCESS, 200, cases[i].elapsed);
            assert(result.ok && result.rtt == cases[i].rtt);
            result = nm_endpoint_status(types[t], NM_ENDPOINT_EXCEPTION, 200, cases[i].elapsed);
            assert(!result.ok && result.rtt == UINT16_MAX);
            assert(strcmp(result.status, "Exception") == 0);
            result = nm_endpoint_status(types[t], NM_ENDPOINT_SUCCESS, 200, 2);
            assert(result.ok && result.rtt == 2);
        }
    }
    /* HTTP error responses recover reachability; they are not probe failures. */
    expect("http", NM_ENDPOINT_TIMEOUT, 0, 1000, false, "Timeout", UINT16_MAX);
    expect("http", NM_ENDPOINT_SUCCESS, 404, 10, true, "NotFound", 10);
    expect("http", NM_ENDPOINT_SUCCESS, 500, 11, true, "InternalServerError", 11);
    expect("http", NM_ENDPOINT_HTTP_REQUEST_EXCEPTION, 500, 12,
           false, "HttpRequestException", UINT16_MAX);
    expect("http", NM_ENDPOINT_SUCCESS, 200, 13, true, "OK", 13);
}

static void urls(void)
{
    const struct { const char *input; bool tls; unsigned port; const char *url; } cases[] = {
        {"example.com", false, 0, "http://example.com:80/"},
        {"example.com/a?b=c#fragment", true, 8443, "https://example.com:8443/a?b=c"},
        {"example.com?x=1", false, 8080, "http://example.com:8080/?x=1"},
        {"example.com:8081/path", false, 8080, "http://example.com:8080/path"},
        {"example.com:8081/path", false, 0, "http://example.com:8081/path"},
        {"https://example.com/path", false, 8443, "https://example.com:8443/path"},
        {"HTTPS://example.com:443/path", false, 8443, "https://example.com:8443/path"},
        {"http://example.com:8081/path", false, 8080, "http://example.com:8081/path"},
        {"http://example.com:80/path", false, 8080, "http://example.com:8080/path"},
        {"[2001:db8::1]/x", true, 0, "https://[2001:db8::1]:443/x"},
        {"http://[::1]:8081?x=y", false, 8080, "http://[::1]:8081/?x=y"},
        {"example.com/a://b", false, 0, "http://example.com:80/a://b"},
        {"example.com/#fragment", false, 0, "http://example.com:80/"},
        {"example.com:65535", false, 0, "http://example.com:65535/"}
    };
    char out[1200];
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        assert(nm_endpoint_http_url(cases[i].input, cases[i].tls, cases[i].port, out, sizeof(out)));
        assert(strcmp(out, cases[i].url) == 0);
        size_t exact = strlen(cases[i].url) + 1;
        assert(nm_endpoint_http_url(cases[i].input, cases[i].tls, cases[i].port, out, exact));
        assert(!nm_endpoint_http_url(cases[i].input, cases[i].tls, cases[i].port, out, exact - 1));
        assert(out[0] == 0);
    }
    const char *invalid[] = {NULL, "", "http://", "http:///x", "ftp://example.com",
        "http:/example.com", "//example.com", "example.com:", "example.com:0",
        "example.com:65536", "example.com:99999999999999999999999", "example.com:-1",
        "example.com:1.0", "example.com:1e0", "example.com:abc", "a@b", "http://u:p@host/",
        "example.com\r\nHeader:bad", "example.com/a b", "example.com\\path", "example.com\t",
        "[::1", "[]", "[abc]", "[::1]garbage", "[::1]:", "[::g]", "::1", "[::1]]"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        assert(!nm_endpoint_http_url(invalid[i], false, 0, out, sizeof(out)));
        assert(out[0] == 0);
    }
    char long_address[1026];
    memset(long_address, 'a', sizeof(long_address));
    long_address[sizeof(long_address) - 1] = 0;
    assert(!nm_endpoint_http_url(long_address, false, 0, out, sizeof(out)));
    long_address[1024] = 0;
    assert(nm_endpoint_http_url(long_address, false, 0, out, sizeof(out)));
    assert(!nm_endpoint_http_url("example.com", false, 65536, out, sizeof(out)));
    assert(!nm_endpoint_http_url("example.com", false, 0, NULL, 0));
    assert(!nm_endpoint_http_url("example.com", false, 0, out, 1));
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--http-table") == 0) {
        for (int code = 100; code <= 599; ++code) {
            nm_endpoint_status_result result = nm_endpoint_status("http", NM_ENDPOINT_SUCCESS, code, 0);
            printf("%d %s\n", code, result.status);
        }
        return 0;
    }
    http_statuses();
    other_endpoints();
    rtt_and_sequences();
    urls();
    puts("endpoint status tests passed");
    return 0;
}
