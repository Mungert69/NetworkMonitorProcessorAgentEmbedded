#include "enrollment_internal.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "nm_memory.h"
#include <stdlib.h>
#include <string.h>

/* HTTPS only, normal CA/hostname validation, no redirects or bearer forwarding.
 * All remote bodies are bounded, including chunked responses. */
yyjson_mut_doc *nm_enrollment_request(const char *url, const char *form, int *status)
{
    *status = 0;
    if (!url || strncmp(url, "https://", 8))
        return NULL;
    esp_http_client_config_t options = {.url = url,
                                        .crt_bundle_attach = esp_crt_bundle_attach,
                                        .timeout_ms = 15000,
                                        .disable_auto_redirect = true,
                                        .method = form ? HTTP_METHOD_POST : HTTP_METHOD_GET};
    esp_http_client_handle_t client = esp_http_client_init(&options);
    char *body = nm_bulk_malloc(65537);
    yyjson_mut_doc *result = NULL;
    if (!client || !body)
        goto done;
    if (form)
        esp_http_client_set_header(client, "Content-Type", "application/x-www-form-urlencoded");
    size_t length = form ? strlen(form) : 0;
    if (esp_http_client_open(client, (int)length) != ESP_OK)
        goto done;
    for (size_t offset = 0; offset < length;) {
        int n = esp_http_client_write(client, form + offset, (int)(length - offset));
        if (n <= 0)
            goto done;
        offset += (size_t)n;
    }
    if (esp_http_client_fetch_headers(client) < 0)
        goto done;
    *status = esp_http_client_get_status_code(client);
    size_t used = 0;
    while (used < 65536) {
        int n = esp_http_client_read(client, body + used, (int)(65536 - used));
        if (n < 0)
            goto done;
        if (!n)
            break;
        used += (size_t)n;
    }
    if (used == 65536 || !esp_http_client_is_complete_data_received(client) ||
        memchr(body, 0, used))
        goto done;
    body[used] = 0;
    result = nm_json_read(body, used);
done:
    if (client)
        esp_http_client_cleanup(client);
    free(body);
    return result;
}
