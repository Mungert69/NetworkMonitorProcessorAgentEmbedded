#include "http_deadline.h"
#include "nm_memory.h"
#include "endpoint_resource.h"
#include "esp_crt_bundle.h"
#include "esp_timer.h"
#include "esp_tls.h"
#include "esp_transport_ssl.h"
#include "esp_transport_tcp.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/ssl.h"
#include "mbedtls/asn1.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"
#include "mbedtls/pem.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509.h"
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* All fields and all transport operations belong to the calling task. There
 * is no cancellation timer, shared client handle or asynchronous destruction. */
struct nm_http_deadline {
    int64_t deadline_us;
    nm_http_resolver resolver;
    esp_transport_handle_t transport, connection;
    esp_http_client_handle_t client;
    char *hostname; /* TLS verification AND SNI use original host, never its IP. */
    bool resource_failed;
};

bool nm_http_deadline_resource_failed(const nm_http_deadline *deadline)
{
    return deadline->resource_failed;
}

static bool tls_allocation_failed(int code)
{
    /* mbedTLS combines a high-level module error with a low-level cause.
     * ESP-TLS captures either sign. Widen before negating even malformed input. */
    uint64_t magnitude = code < 0 ? (uint64_t)-(int64_t)code : (uint64_t)code;
    if (magnitude > 0x7fff)
        return false;
    unsigned high = (unsigned)magnitude & ~0x7fU, low = (unsigned)magnitude & 0x7fU;
    return high == -MBEDTLS_ERR_SSL_ALLOC_FAILED || high == -MBEDTLS_ERR_X509_ALLOC_FAILED ||
           high == -MBEDTLS_ERR_PK_ALLOC_FAILED || high == -MBEDTLS_ERR_ECP_ALLOC_FAILED ||
           high == -MBEDTLS_ERR_PEM_ALLOC_FAILED || low == -MBEDTLS_ERR_MPI_ALLOC_FAILED ||
           low == -MBEDTLS_ERR_ASN1_ALLOC_FAILED;
}

static void capture_resource_failure(nm_http_deadline *deadline)
{
    int socket_error = errno, tls_code = 0, flags = 0;
    esp_err_t error = esp_tls_get_and_clear_last_error(
        esp_transport_get_error_handle(deadline->connection), &tls_code, &flags);
    /* ESP-TLS can capture either sign of the mbedTLS code. */
    if (error == ESP_ERR_NO_MEM || nm_endpoint_resource_errno(socket_error) ||
        nm_endpoint_resource_errno(esp_transport_get_errno(deadline->connection)) ||
        tls_allocation_failed(tls_code))
        deadline->resource_failed = true;
}

bool nm_http_deadline_expired(nm_http_deadline *deadline)
{
    return esp_timer_get_time() >= deadline->deadline_us;
}

static int budget(nm_http_deadline *deadline, int requested)
{
    int64_t us = deadline->deadline_us - esp_timer_get_time();
    if (us <= 0) {
        errno = ETIMEDOUT;
        return 0;
    }
    int64_t ms = (us + 999) / 1000;
    if (ms > INT_MAX)
        ms = INT_MAX;
    if (requested > 0 && ms > requested)
        ms = requested;
    return (int)ms;
}

static int close_transport(esp_transport_handle_t transport)
{
    nm_http_deadline *deadline = esp_transport_get_context_data(transport);
    if (deadline->connection) {
        esp_transport_destroy(deadline->connection);
        deadline->connection = NULL;
    }
    free(deadline->hostname);
    deadline->hostname = NULL;
    return 0;
}

static int connect_transport(esp_transport_handle_t transport, const char *host, int port,
                             int timeout)
{
    nm_http_deadline *deadline = esp_transport_get_context_data(transport);
    close_transport(transport);
    int left = budget(deadline, timeout);
    if (!left || !deadline->client || !host || !*host || strnlen(host, 1025) > 1024 || port < 1 ||
        port > 65535)
        return -1;
    esp_http_client_transport_t type = esp_http_client_get_transport_type(deadline->client);
    if (type != HTTP_TRANSPORT_OVER_SSL && type != HTTP_TRANSPORT_OVER_TCP)
        return -1;
    struct addrinfo *addresses = NULL;
    errno = 0;
    if (!deadline->resolver(host, (unsigned)port, (unsigned)left, &addresses)) {
        if (nm_endpoint_resource_errno(errno))
            deadline->resource_failed = true;
        return -1;
    }
    int result = -1;
    for (struct addrinfo *a = addresses; a && budget(deadline, timeout); a = a->ai_next) {
        char ip[INET6_ADDRSTRLEN];
        const void *address = NULL;
        if (!a->ai_addr)
            continue;
        if (a->ai_family == AF_INET && a->ai_addrlen >= sizeof(struct sockaddr_in))
            address = &((struct sockaddr_in *)a->ai_addr)->sin_addr;
        else if (a->ai_family == AF_INET6 && a->ai_addrlen >= sizeof(struct sockaddr_in6))
            address = &((struct sockaddr_in6 *)a->ai_addr)->sin6_addr;
        if (!address || !inet_ntop(a->ai_family, address, ip, sizeof(ip)))
            continue;
        deadline->connection =
            type == HTTP_TRANSPORT_OVER_SSL ? esp_transport_ssl_init() : esp_transport_tcp_init();
        if (!deadline->connection) {
            deadline->resource_failed = true;
            break;
        }
        if (type == HTTP_TRANSPORT_OVER_SSL) {
            deadline->hostname = nm_bulk_strdup(host);
            if (!deadline->hostname) {
                deadline->resource_failed = true;
                close_transport(transport);
                break;
            }
            esp_transport_ssl_set_common_name(deadline->connection, deadline->hostname);
            esp_transport_ssl_crt_bundle_attach(deadline->connection, esp_crt_bundle_attach);
        }
        int rc = 0;
        /* Numeric IP bypasses blocking DNS inside ESP-TLS. Give its initial
         * connect select the remaining request budget. This avoids the
         * short-timeout fd_set issue observed during the original IDF 5.5.5
         * implementation and remains covered by the IDF 6.1 integration test.
         * TLS handshake steps remain nonblocking. Never
         * pass zero, which means an indefinite select wait inside ESP-TLS. */
        while ((left = budget(deadline, timeout)) > 0) {
            errno = 0;
            rc = esp_transport_connect_async(deadline->connection, ip, port, left);
            if (rc != 0)
                break;
            vTaskDelay(1);
        }
        if (rc == 1 && !nm_http_deadline_expired(deadline)) {
            result = 0;
            break;
        }
        if (rc < 0)
            capture_resource_failure(deadline);
        close_transport(transport);
        if (deadline->resource_failed)
            break;
    }
    freeaddrinfo(addresses);
    if (nm_http_deadline_expired(deadline))
        errno = ETIMEDOUT;
    return result;
}

static int read_transport(esp_transport_handle_t transport, char *buffer, int len, int timeout)
{
    nm_http_deadline *deadline = esp_transport_get_context_data(transport);
    int left;
    while (deadline->connection && (left = budget(deadline, timeout)) > 0) {
        errno = 0;
        int rc = esp_transport_read(deadline->connection, buffer, len, left);
        if (nm_http_deadline_expired(deadline))
            break;
        /* Nonblocking TLS may have only part of a record or a control record.
         * ESP-IDF maps WANT_READ to zero; that is not HTTP EOF or timeout.
         * A real TCP FIN is the distinct negative transport error. */
        if (rc != 0 && rc != ESP_TLS_ERR_SSL_WANT_READ && rc != ESP_TLS_ERR_SSL_WANT_WRITE &&
            !(rc < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))) {
            if (rc < 0)
                capture_resource_failure(deadline);
            return rc;
        }
        vTaskDelay(1);
    }
    errno = ETIMEDOUT;
    return -1;
}
static int write_transport(esp_transport_handle_t transport, const char *buffer, int len,
                           int timeout)
{
    nm_http_deadline *deadline = esp_transport_get_context_data(transport);
    int left;
    while (deadline->connection && (left = budget(deadline, timeout)) > 0) {
        errno = 0;
        int rc = esp_transport_write(deadline->connection, buffer, len, left);
        if (nm_http_deadline_expired(deadline))
            break;
        if (rc != 0 && rc != ESP_TLS_ERR_SSL_WANT_READ && rc != ESP_TLS_ERR_SSL_WANT_WRITE &&
            !(rc < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))) {
            if (rc < 0)
                capture_resource_failure(deadline);
            return rc;
        }
        vTaskDelay(1);
    }
    errno = ETIMEDOUT;
    return -1;
}
static int poll_read(esp_transport_handle_t transport, int timeout)
{
    nm_http_deadline *deadline = esp_transport_get_context_data(transport);
    int left = budget(deadline, timeout);
    return left && deadline->connection
               ? esp_transport_poll_read(deadline->connection, timeout == 0 ? 0 : left)
               : -1;
}
static int poll_write(esp_transport_handle_t transport, int timeout)
{
    nm_http_deadline *deadline = esp_transport_get_context_data(transport);
    int left = budget(deadline, timeout);
    return left && deadline->connection
               ? esp_transport_poll_write(deadline->connection, timeout == 0 ? 0 : left)
               : -1;
}
nm_http_deadline *nm_http_deadline_new(unsigned timeout_ms, nm_http_resolver resolver)
{
    if (!timeout_ms || !resolver)
        return NULL;
    nm_http_deadline *deadline = nm_bulk_calloc(1, sizeof(*deadline));
    if (!deadline)
        return NULL;
    deadline->deadline_us = esp_timer_get_time() + (int64_t)timeout_ms * 1000;
    deadline->resolver = resolver;
    deadline->transport = esp_transport_init();
    if (!deadline->transport) {
        free(deadline);
        return NULL;
    }
    esp_transport_set_context_data(deadline->transport, deadline);
    esp_transport_set_func(deadline->transport, connect_transport, read_transport, write_transport,
                           close_transport, poll_read, poll_write, close_transport);
    return deadline;
}
esp_transport_handle_t nm_http_deadline_transport(nm_http_deadline *deadline)
{
    return deadline->transport;
}
void nm_http_deadline_bind(nm_http_deadline *deadline, esp_http_client_handle_t client)
{
    deadline->client = client;
}
void nm_http_deadline_free(nm_http_deadline *deadline)
{
    if (!deadline)
        return;
    esp_transport_destroy(deadline->transport);
    free(deadline);
}
