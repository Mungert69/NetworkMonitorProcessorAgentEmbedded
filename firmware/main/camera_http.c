#include "camera_http.h"
#include "cmd_result.h"
#include "endpoint_internal.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "http_deadline.h"
#include "nm_memory.h"
#include "psa/crypto.h"
#include <errno.h>
#include <stdio.h>

int64_t nm_camera_now_us(void)
{
    return esp_timer_get_time();
}
void nm_camera_random(uint8_t *out, size_t length)
{
    esp_fill_random(out, length);
}
bool nm_camera_hash(bool sha1, const uint8_t *data, size_t length, uint8_t *out, size_t capacity)
{
    size_t written = 0;
    return psa_hash_compute(sha1 ? PSA_ALG_SHA_1 : PSA_ALG_SHA_256, data, length, out, capacity,
                            &written) == PSA_SUCCESS &&
           written == (sha1 ? 20U : 32U);
}
bool nm_camera_md5(const uint8_t *input, size_t length, uint8_t out[16])
{
    size_t written = 0;
    return psa_hash_compute(PSA_ALG_MD5, input, length, out, 16, &written) == PSA_SUCCESS &&
           written == 16;
}
static bool resolve(const char *host, unsigned port, unsigned timeout, struct addrinfo **out)
{
    lookup_result result = nm_endpoint_resolve(host, port, timeout, out);
    if (result == LOOKUP_BUSY || result == LOOKUP_NO_MEMORY)
        errno = ENOMEM;
    return result == LOOKUP_OK;
}
typedef struct {
    nm_camera_http_reply *reply;
    nm_http_deadline *deadline;
    const atomic_bool *cancel;
    size_t limit;
    bool failed;
} receive_context;
static esp_err_t receive(esp_http_client_event_t *event)
{
    receive_context *ctx = event->user_data;
    if (ctx->cancel && atomic_load(ctx->cancel))
        return ESP_FAIL;
    if (event->event_id == HTTP_EVENT_ON_STATUS_CODE)
        ctx->reply->length = 0; /* Discard any authentication challenge body. */
    if (event->event_id != HTTP_EVENT_ON_DATA)
        return ESP_OK;
    /* HTTP authentication challenge bodies aren't part of the image/XML. */
    int status = esp_http_client_get_status_code(event->client);
    if (status < 200 || status >= 300)
        return ESP_OK;
    if (event->data_len < 0 || (size_t)event->data_len > ctx->limit - ctx->reply->length) {
        ctx->failed = true;
        nm_http_deadline_stop(ctx->deadline);
        return ESP_FAIL;
    }
    memcpy(ctx->reply->data + ctx->reply->length, event->data, (size_t)event->data_len);
    ctx->reply->length += (size_t)event->data_len;
    ctx->reply->data[ctx->reply->length] = 0;
    return ESP_OK;
}
bool nm_camera_http(const char *url, const char *body, const char *action, const char *username,
                    const char *password, unsigned timeout_ms, const atomic_bool *cancel,
                    size_t limit, nm_camera_http_reply *reply)
{
    *reply = (nm_camera_http_reply){0};
    if (!timeout_ms || !limit || limit > NM_CMD_RAW_MAX || (cancel && atomic_load(cancel)))
        return false;
    reply->data = nm_bulk_calloc(limit + 1, 1);
    if (!reply->data)
        return false;
    nm_http_deadline *deadline = nm_http_deadline_new(timeout_ms, resolve);
    if (!deadline)
        return false;
    nm_http_deadline_cancel(deadline, cancel);
    receive_context ctx = {.reply = reply, .deadline = deadline, .cancel = cancel, .limit = limit};
    esp_http_client_config_t config = {.url = url,
                                       .method = body ? HTTP_METHOD_POST : HTTP_METHOD_GET,
                                       .username = username,
                                       .password = password,
                                       .auth_type = HTTP_AUTH_TYPE_NONE,
                                       .timeout_ms = (int)timeout_ms,
                                       .disable_auto_redirect = true,
                                       .max_authorization_retries = 2,
                                       .crt_bundle_attach = esp_crt_bundle_attach,
                                       .transport = nm_http_deadline_transport(deadline),
                                       .event_handler = receive,
                                       .user_data = &ctx,
                                       .buffer_size = 2048,
                                       .buffer_size_tx = 2048};
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        nm_http_deadline_free(deadline);
        return false;
    }
    nm_http_deadline_bind(deadline, client);
    bool setup = true;
    if (body) {
        char content_type[256];
        int n = snprintf(content_type, sizeof(content_type),
                         "application/soap+xml; charset=utf-8; action=\"%s\"", action);
        setup = n > 0 && (size_t)n < sizeof(content_type) &&
                esp_http_client_set_header(client, "Content-Type", content_type) == ESP_OK &&
                esp_http_client_set_header(client, "SOAPAction", action) == ESP_OK &&
                esp_http_client_set_post_field(client, body, (int)strlen(body)) == ESP_OK;
    }
    esp_err_t error = setup ? esp_http_client_perform(client) : ESP_FAIL;
    reply->status = esp_http_client_get_status_code(client);
    bool ok = error == ESP_OK && !ctx.failed && !nm_http_deadline_expired(deadline) &&
              reply->status >= 200 && reply->status < 300 &&
              esp_http_client_is_complete_data_received(client);
    esp_http_client_cleanup(client);
    nm_http_deadline_free(deadline);
    return ok;
}
