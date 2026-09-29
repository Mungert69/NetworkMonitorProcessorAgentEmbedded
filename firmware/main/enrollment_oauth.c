#include "enrollment_internal.h"
#include "enrollment_policy.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/base64.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *TAG = "nm_enrollment";
static char *escape(const char *s)
{
    if (!s || strlen(s) > 16384)
        return NULL;
    char *out = malloc(strlen(s) * 3 + 1), *p = out;
    if (!out)
        return NULL;
    for (; *s; ++s) {
        unsigned char c = (unsigned char)*s;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~')
            *p++ = (char)c;
        else {
            snprintf(p, 4, "%%%02X", c);
            p += 3;
        }
    }
    *p = 0;
    return out;
}

static unsigned seconds(yyjson_mut_val *o, const char *key, unsigned fallback)
{
    yyjson_mut_val *v = yyjson_mut_obj_get(o, key);
    if (!v)
        return fallback;
    return yyjson_mut_is_uint(v) && yyjson_mut_get_uint(v) >= 1 && yyjson_mut_get_uint(v) <= 86400
               ? (unsigned)yyjson_mut_get_uint(v)
               : 0;
}
char *nm_enrollment_authorize(yyjson_mut_val *root)
{
    const char *authority = nm_enrollment_string(root, "BaseFusionAuthURL"),
               *id = nm_enrollment_string(root, "ClientId");
    if (!authority)
        authority = "https://auth.readyforquantum.com:2096";
    if (!id)
        id = "e4838743-5873-4174-888b-044f43ea7fe8";
    if (strlen(authority) > 512 || strlen(id) > 256)
        return NULL;
    char url[600];
    snprintf(url, sizeof(url), "%s/.well-known/openid-configuration", authority);
    int status = 0;
    yyjson_mut_doc *discovery_doc = nm_enrollment_request(url, NULL, &status);
    yyjson_mut_val *discovery = yyjson_mut_doc_get_root(discovery_doc);
    const char *device = nm_enrollment_string(discovery, "device_authorization_endpoint");
    const char *token = nm_enrollment_string(discovery, "token_endpoint");
    char *client = escape(id), *form = NULL, *access = NULL;
    yyjson_mut_doc *reply_doc = NULL;
    yyjson_mut_val *reply = NULL;
    if (status != 200 || !client || !nm_enrollment_endpoint(authority, device) ||
        !nm_enrollment_endpoint(authority, token))
        goto done;
    if (asprintf(&form, "client_id=%s&scope=offline_access", client) < 0) {
        form = NULL;
        goto done;
    }
    reply_doc = nm_enrollment_request(device, form, &status);
    reply = yyjson_mut_doc_get_root(reply_doc);
    free(form);
    form = NULL;
    const char *uri = nm_enrollment_string(reply, "verification_uri_complete");
    if (!uri)
        uri = nm_enrollment_string(reply, "verification_uri");
    const char *code = nm_enrollment_string(reply, "user_code");
    char *encoded = escape(nm_enrollment_string(reply, "device_code"));
    unsigned interval = seconds(reply, "interval", 5), expiry = seconds(reply, "expires_in", 600);
    if (status != 200 || !uri || !code || !encoded || !interval || !expiry) {
        free(encoded);
        goto done;
    }
    ESP_LOGI(TAG, "Sign in at %s ; code %s", uri, code);
    int count = asprintf(
        &form,
        "client_id=%s&device_code=%s&grant_type=urn:ietf:params:oauth:grant-type:device_code",
        client, encoded);
    free(encoded);
    if (count < 0) {
        form = NULL;
        goto done;
    }
    int64_t deadline = esp_timer_get_time() + (int64_t)expiry * 1000000;
    yyjson_mut_doc_free(reply_doc);
    reply_doc = NULL;
    reply = NULL;
    while (esp_timer_get_time() + (int64_t)interval * 1000000 < deadline) {
        vTaskDelay(pdMS_TO_TICKS(interval * 1000));
        reply_doc = nm_enrollment_request(token, form, &status);
        reply = yyjson_mut_doc_get_root(reply_doc);
        const char *value = nm_enrollment_string(reply, "access_token"),
                   *error = nm_enrollment_string(reply, "error");
        if (status == 200 && value && *value && strlen(value) < 16384)
            access = strdup(value);
        bool pending = error && !strcmp(error, "authorization_pending");
        bool slow = error && !strcmp(error, "slow_down");
        bool transient = !reply || status >= 500 || status == 429;
        yyjson_mut_doc_free(reply_doc);
        reply_doc = NULL;
        reply = NULL;
        if (access)
            break;
        if (slow || transient) {
            if (interval < 60)
                interval += 5;
        } else if (!pending)
            break;
    }
done:
    yyjson_mut_doc_free(reply_doc);
    yyjson_mut_doc_free(discovery_doc);
    free(form);
    free(client);
    return access;
}

/* JWT claims select routing only. Authentication is performed by RabbitMQ. */
bool nm_enrollment_identity(yyjson_mut_doc *doc, yyjson_mut_val *root, const char *token)
{
    const char *a = strchr(token, '.'), *b = a ? strchr(a + 1, '.') : NULL;
    if (!b || b == a + 1 || b - a > 16000)
        return false;
    ++a;
    size_t n = (size_t)(b - a), padded = (n + 3) & ~(size_t)3, decoded = 0;
    char *encoded = malloc(padded + 1), *plain = calloc(1, padded + 1);
    if (!encoded || !plain) {
        free(encoded);
        free(plain);
        return false;
    }
    for (size_t i = 0; i < padded; ++i)
        encoded[i] = i >= n ? '=' : a[i] == '-' ? '+' : a[i] == '_' ? '/' : a[i];
    encoded[padded] = 0;
    bool ok = mbedtls_base64_decode((unsigned char *)plain, padded, &decoded,
                                    (unsigned char *)encoded, padded) == 0;
    yyjson_mut_doc *claims_doc =
        ok && !memchr(plain, 0, decoded) ? nm_json_read(plain, decoded) : NULL;
    yyjson_mut_val *claims = yyjson_mut_doc_get_root(claims_doc);
    const char *owner = nm_enrollment_string(claims, "sub");
    ok = nm_enrollment_owner(owner);
    uint8_t mac[6] = {0};
    nm_enrollment_names names;
    if (esp_read_mac(mac, ESP_MAC_WIFI_STA) != ESP_OK)
        ok = false;
    ok = ok && nm_enrollment_build_names(owner, nm_enrollment_string(claims, "email"),
                                         nm_enrollment_string(root, "AppName"),
                                         nm_enrollment_string(root, "DeviceName"), mac, &names);
    if (ok)
        ok = nm_json_put_str(doc, root, "mqtt_username", owner) &&
             nm_json_put_str(doc, root, "app_id", names.app_id) &&
             nm_json_put_str(doc, root, "mqtt_password", token) &&
             nm_json_put_str(doc, root, "DeviceName", names.machine) &&
             nm_json_put_str(doc, root, "MonitorLocation", names.location);
    yyjson_mut_doc_free(claims_doc);
    free(encoded);
    free(plain);
    return ok;
}
