/* Unit tests exercise the production transport callbacks with controlled time;
 * real ESP-IDF parser/socket/TLS tests live in tests/integration/http_deadline. */
#include "../../firmware/main/http_deadline.c"
#include <assert.h>
#include <stdio.h>

typedef struct {
    void *context;
    int (*destroy)(esp_transport_handle_t);
    bool tls;
    const char *name;
} transport;
static int64_t now;
static unsigned alive, dns_ms, io_ms, connect_ms;
static unsigned transient_reads;
static int transient_result;
static bool dns_failure, connect_failure, connect_pending, allocation_failure;
static int captured_tls_error, captured_esp_error, captured_errno;
esp_tls_error_handle_t esp_transport_get_error_handle(esp_transport_handle_t t)
{
    return t;
}
int esp_transport_get_errno(esp_transport_handle_t t)
{
    assert(t);
    return captured_errno;
}
int esp_tls_get_and_clear_last_error(void *handle, int *code, int *flags)
{
    assert(handle);
    *code = captured_tls_error;
    *flags = 0;
    return captured_esp_error;
}
static esp_http_client_transport_t scheme = HTTP_TRANSPORT_OVER_TCP;
int64_t esp_timer_get_time(void)
{
    return now;
}
void vTaskDelay(TickType_t ticks)
{
    now += (int64_t)ticks * 1000;
}
int esp_crt_bundle_attach(void *config)
{
    (void)config;
    return 0;
}
esp_http_client_transport_t esp_http_client_get_transport_type(esp_http_client_handle_t c)
{
    assert(c);
    return scheme;
}
esp_transport_handle_t esp_transport_init(void)
{
    if (allocation_failure)
        return NULL;
    transport *t = calloc(1, sizeof(*t));
    assert(t);
    ++alive;
    return t;
}
esp_transport_handle_t esp_transport_tcp_init(void)
{
    return esp_transport_init();
}
esp_transport_handle_t esp_transport_ssl_init(void)
{
    transport *t = esp_transport_init();
    if (t)
        t->tls = true;
    return t;
}
void *esp_transport_get_context_data(esp_transport_handle_t t)
{
    return ((transport *)t)->context;
}
int esp_transport_set_context_data(esp_transport_handle_t t, void *c)
{
    ((transport *)t)->context = c;
    return 0;
}
int esp_transport_destroy(esp_transport_handle_t t)
{
    transport *p = t;
    if (p->destroy)
        p->destroy(t);
    assert(alive);
    --alive;
    free(t);
    return 0;
}
int esp_transport_set_func(esp_transport_handle_t t,
                           int (*c)(esp_transport_handle_t, const char *, int, int),
                           int (*r)(esp_transport_handle_t, char *, int, int),
                           int (*w)(esp_transport_handle_t, const char *, int, int),
                           int (*cl)(esp_transport_handle_t),
                           int (*pr)(esp_transport_handle_t, int),
                           int (*pw)(esp_transport_handle_t, int), int (*d)(esp_transport_handle_t))
{
    assert(c && r && w && cl && pr && pw && d);
    ((transport *)t)->destroy = d;
    return 0;
}
void esp_transport_ssl_set_common_name(esp_transport_handle_t t, const char *name)
{
    assert(((transport *)t)->tls);
    ((transport *)t)->name = name;
}
void esp_transport_ssl_crt_bundle_attach(esp_transport_handle_t t, int (*attach)(void *))
{
    assert(((transport *)t)->tls && attach == esp_crt_bundle_attach);
}
int esp_transport_connect_async(esp_transport_handle_t t, const char *ip, int port, int timeout)
{
    assert(port == 80 && !strcmp(ip, "127.0.0.1") && timeout > 0 && timeout <= 100);
    if (((transport *)t)->tls)
        assert(!strcmp(((transport *)t)->name, "host.test"));
    now += (int64_t)(connect_ms < (unsigned)timeout ? connect_ms : (unsigned)timeout) * 1000;
    if (connect_ms > (unsigned)timeout)
        return 0;
    return connect_failure ? -1 : connect_pending ? 0 : 1;
}
int esp_transport_read(esp_transport_handle_t t, char *b, int n, int timeout)
{
    assert(t && b && n > 0 && timeout > 0);
    now += (int64_t)(io_ms < (unsigned)timeout ? io_ms : (unsigned)timeout) * 1000;
    if (transient_reads) {
        --transient_reads;
        return transient_result;
    }
    return 1;
}
int esp_transport_write(esp_transport_handle_t t, const char *b, int n, int timeout)
{
    return esp_transport_read(t, (char *)b, n, timeout);
}
int esp_transport_poll_read(esp_transport_handle_t t, int timeout)
{
    assert(t && timeout > 0);
    return 1;
}
int esp_transport_poll_write(esp_transport_handle_t t, int timeout)
{
    return esp_transport_poll_read(t, timeout);
}
static bool resolver(const char *host, unsigned port, unsigned timeout, struct addrinfo **out)
{
    assert(!strcmp(host, "host.test") && port == 80 && timeout > 0);
    now += (int64_t)(dns_ms < timeout ? dns_ms : timeout) * 1000;
    if (dns_failure || dns_ms >= timeout)
        return false;
    struct addrinfo hints = {
        .ai_family = AF_INET, .ai_socktype = SOCK_STREAM, .ai_flags = AI_NUMERICHOST};
    return getaddrinfo("127.0.0.1", NULL, &hints, out) == 0;
}
static nm_http_deadline *request(void)
{
    nm_http_deadline *d = nm_http_deadline_new(100, resolver);
    assert(d);
    nm_http_deadline_bind(d, (void *)1);
    return d;
}
static void release(nm_http_deadline *d)
{
    nm_http_deadline_free(d);
    assert(alive == 0);
}
int main(void)
{
    const int alloc_errors[] = {MBEDTLS_ERR_SSL_ALLOC_FAILED,
                                MBEDTLS_ERR_X509_ALLOC_FAILED,
                                MBEDTLS_ERR_PK_ALLOC_FAILED,
                                MBEDTLS_ERR_ECP_ALLOC_FAILED,
                                MBEDTLS_ERR_PEM_ALLOC_FAILED,
                                MBEDTLS_ERR_MPI_ALLOC_FAILED,
                                MBEDTLS_ERR_ASN1_ALLOC_FAILED,
                                -0x2910,
                                -0x296a};
    for (size_t i = 0; i < sizeof(alloc_errors) / sizeof(alloc_errors[0]); ++i) {
        assert(tls_allocation_failed(alloc_errors[i]));
        assert(tls_allocation_failed(-alloc_errors[i]));
    }
    assert(!tls_allocation_failed(0) && !tls_allocation_failed(INT_MIN));
    assert(!tls_allocation_failed(-0x2700) && !tls_allocation_failed(-0x7280));
    assert(!nm_http_deadline_new(0, resolver));
    assert(!nm_http_deadline_new(1, NULL));
    allocation_failure = true;
    assert(!nm_http_deadline_new(1, resolver));
    allocation_failure = false;
    for (int iteration = 0; iteration < 100; ++iteration) {
        nm_http_deadline *d = request();
        dns_ms = 30;
        connect_ms = 5;
        io_ms = 10;
        assert(connect_transport(d->transport, "host.test", 80, 100) == 0);
        char b = 0;
        for (int i = 0; i < 6; ++i)
            assert(read_transport(d->transport, &b, 1, 100) == 1);
        assert(write_transport(d->transport, &b, 1, 100) == -1 && errno == ETIMEDOUT);
        assert(nm_http_deadline_expired(d));
        release(d);
    }
    nm_http_deadline *d = request();
    dns_ms = 101;
    assert(connect_transport(d->transport, "host.test", 80, 100) == -1);
    assert(nm_http_deadline_expired(d));
    release(d);
    d = request();
    dns_ms = 0;
    connect_pending = true;
    assert(connect_transport(d->transport, "host.test", 80, 100) == -1);
    assert(nm_http_deadline_expired(d));
    release(d);
    connect_pending = false;
    d = request();
    connect_failure = true;
    assert(connect_transport(d->transport, "host.test", 80, 100) == -1);
    release(d);
    connect_failure = false;
    const int memory_errors[] = {MBEDTLS_ERR_SSL_ALLOC_FAILED, -MBEDTLS_ERR_SSL_ALLOC_FAILED};
    for (size_t i = 0; i < 2; ++i) {
        d = request();
        connect_failure = true;
        captured_tls_error = memory_errors[i];
        assert(connect_transport(d->transport, "host.test", 80, 100) == -1);
        assert(nm_http_deadline_resource_failed(d));
        assert(!d->connection); /* captured before failed TLS transport was freed */
        release(d);
    }
    captured_tls_error = -0x2700; /* certificate failure is NOT local exhaustion */
    d = request();
    assert(connect_transport(d->transport, "host.test", 80, 100) == -1);
    assert(!nm_http_deadline_resource_failed(d));
    release(d);
    captured_tls_error = 0;
    connect_failure = false;
    d = request();
    dns_failure = true;
    assert(connect_transport(d->transport, "host.test", 80, 100) == -1);
    release(d);
    dns_failure = false;
    d = request();
    scheme = HTTP_TRANSPORT_OVER_SSL;
    assert(connect_transport(d->transport, "host.test", 80, 100) == 0);
    /* Redirect changes scheme, releases old TLS host, retains original deadline. */
    int64_t until = d->deadline_us;
    scheme = HTTP_TRANSPORT_OVER_TCP;
    assert(connect_transport(d->transport, "host.test", 80, 100) == 0 && d->deadline_us == until);
    assert(!d->hostname);
    release(d);
    d = request();
    allocation_failure = true;
    assert(connect_transport(d->transport, "host.test", 80, 100) == -1);
    allocation_failure = false;
    assert(nm_http_deadline_resource_failed(d));
    release(d);
    /* Two live requests have independent deadlines and ownership. */
    d = request();
    now += 50000;
    nm_http_deadline *other = request();
    now += 50000;
    assert(nm_http_deadline_expired(d) && !nm_http_deadline_expired(other));
    nm_http_deadline_free(d);
    assert(connect_transport(other->transport, "host.test", 80, 100) == 0);
    release(other);
    /* A WAN connection may need longer than a 10 ms select slice. The SDK's
     * initial select must receive the remaining budget, not a short poll. */
    d = request();
    connect_ms = 25;
    assert(connect_transport(d->transport, "host.test", 80, 100) == 0);
    release(d);
    connect_ms = 5;
    const int retry_codes[] = {0, ESP_TLS_ERR_SSL_WANT_READ, ESP_TLS_ERR_SSL_WANT_WRITE};
    for (size_t i = 0; i < sizeof(retry_codes) / sizeof(retry_codes[0]); ++i) {
        d = request();
        io_ms = 1;
        transient_result = retry_codes[i];
        assert(connect_transport(d->transport, "host.test", 80, 100) == 0);
        char byte = 0;
        transient_reads = 3;
        assert(read_transport(d->transport, &byte, 1, 100) == 1 && transient_reads == 0);
        transient_reads = 1000;
        assert(write_transport(d->transport, &byte, 1, 100) == -1 && nm_http_deadline_expired(d));
        transient_reads = 0;
        release(d);
    }
    puts("HTTP deadline unit tests passed: shared budget, DNS/TLS timeout, redirects, cleanup");
    return 0;
}
