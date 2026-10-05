#include "endpoint_internal.h"
#include "endpoint_resource.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_timer.h"
#include "http_deadline.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>

static bool resolve_http(const char *host, unsigned port, unsigned timeout,
                         struct addrinfo **addresses)
{
    lookup_result result = nm_endpoint_resolve(host, port, timeout, addresses);
    if (result == LOOKUP_BUSY || result == LOOKUP_NO_MEMORY)
        errno = ENOMEM;
    return result == LOOKUP_OK;
}

nm_esp_result nm_endpoint_check_http(const char *host, const char *type, unsigned port,
                                     unsigned timeout)
{
    char url[1200];
    if (!nm_endpoint_http_url(host, !strcmp(type, "https"), port, url, sizeof(url)))
        return nm_endpoint_result(type, NM_ENDPOINT_EXCEPTION, 0, 0,
                                  "Invalid or oversized HTTP URL");
    int64_t start = esp_timer_get_time();
    nm_http_deadline *deadline = nm_http_deadline_new(timeout, resolve_http);
    if (!deadline)
        return nm_endpoint_local_failure(0, "Unable to initialize HTTP deadline");
    nm_http_deadline_check_certificate_expiry(deadline, !strcmp(type, "https"));
    /* The HTTP parser borrows a deadline-aware transport. Both are owned and
     * destroyed by this task; redirects retain the same request deadline. */
    esp_http_client_config_t config = {.url = url,
                                       .method = HTTP_METHOD_GET,
                                       .timeout_ms = (int)timeout,
                                       .max_redirection_count = 5,
                                       .crt_bundle_attach = esp_crt_bundle_attach,
                                       .transport = nm_http_deadline_transport(deadline)};
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        nm_http_deadline_free(deadline);
        return nm_endpoint_local_failure(nm_endpoint_elapsed(start),
                                         "Unable to initialize HTTP client");
    }
    nm_http_deadline_bind(deadline, client);
    esp_err_t error = esp_http_client_perform(client);
    int status = esp_http_client_get_status_code(client);
    int socket_error = esp_http_client_get_errno(client);
    bool timed_out = nm_http_deadline_expired(deadline) || error == ESP_ERR_TIMEOUT ||
                     error == ESP_ERR_HTTP_EAGAIN || error == ESP_ERR_HTTP_READ_TIMEOUT ||
                     (error != ESP_OK && (socket_error == ETIMEDOUT || socket_error == EAGAIN));
    char detail[96];
    if (timed_out)
        snprintf(detail, sizeof(detail), "Timed out after %u", timeout);
    else
        snprintf(detail, sizeof(detail), "%s",
                 error == ESP_OK ? "Invalid HTTP response" : esp_err_to_name(error));
    nm_esp_result result = nm_endpoint_result(
        type,
        !timed_out && error == ESP_OK && status >= 100 && status <= 999 ? NM_ENDPOINT_SUCCESS
        : timed_out                                                     ? NM_ENDPOINT_TIMEOUT
                    : NM_ENDPOINT_HTTP_REQUEST_EXCEPTION,
        status, nm_endpoint_elapsed(start), detail);
    if (error != ESP_OK && (error == ESP_ERR_NO_MEM || nm_http_deadline_resource_failed(deadline) ||
                            nm_endpoint_resource_errno(socket_error)))
        result = nm_endpoint_local_failure(nm_endpoint_elapsed(start),
                                           "HTTP/TLS local resource exhaustion");
    if (result.ok && !strcmp(type, "httphtml")) {
        int64_t bytes = esp_http_client_get_content_length(client);
        if (bytes >= 0)
            snprintf(result.message, sizeof(result.message), "%s  : %lld bytes read", result.status,
                     (long long)bytes);
    }
    esp_http_client_cleanup(client);
    nm_http_deadline_free(deadline);
    return result;
}
