#include "config_internal.h"
#include "probe_config.h"
#include "esp_log.h"
#include "psa/crypto.h"
#include "nvs.h"
#include "nvs_flash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *TAG = "nm_config";
static const char *required_string(yyjson_mut_val *root, const char *name)
{
    yyjson_mut_val *item = yyjson_mut_obj_get(root, name);
    return yyjson_mut_is_str(item) ? yyjson_mut_get_str(item) : NULL;
}

static bool parse_uint(yyjson_mut_val *root, const char *name, unsigned min, unsigned max,
                       unsigned *out)
{
    yyjson_mut_val *item = yyjson_mut_obj_get(root, name);
    if (!yyjson_mut_is_uint(item) || yyjson_mut_get_uint(item) < min ||
        yyjson_mut_get_uint(item) > max)
        return false;
    *out = (unsigned)yyjson_mut_get_uint(item);
    return true;
}

bool nm_esp_config_load(nm_esp_config *config)
{
    if (!config)
        return false;
    memset(config, 0, sizeof(*config));
    if (nvs_flash_init_partition("nmconfig") != ESP_OK) {
        ESP_LOGE(TAG, "configuration partition unavailable");
        return false;
    }
    nvs_handle_t handle;
    if (nvs_open_from_partition("nmconfig", "processor", NVS_READONLY, &handle) != ESP_OK) {
        ESP_LOGE(TAG, "provisioned configuration missing");
        return false;
    }
    size_t size = 0;
    esp_err_t error = nvs_get_blob(handle, "config", NULL, &size);
    if (error != ESP_OK || size < 2 || size > 64 * 1024) {
        nvs_close(handle);
        ESP_LOGE(TAG, "provisioned configuration invalid size");
        return false;
    }
    char *contents = malloc(size + 1);
    if (!contents) {
        nvs_close(handle);
        return false;
    }
    error = nvs_get_blob(handle, "config", contents, &size);
    nvs_close(handle);
    if (error != ESP_OK) {
        free(contents);
        return false;
    }
    contents[size] = 0;
    config->doc = nm_json_read(contents, size);
    config->root = yyjson_mut_doc_get_root(config->doc);
    free(contents);
    if (yyjson_mut_is_obj(config->root) && nm_config_apply_reset(config) &&
        nm_esp_config_bind(config, config->root))
        return true;
    yyjson_mut_doc_free(config->doc);
    memset(config, 0, sizeof(*config));
    return false;
}

bool nm_esp_config_save(const nm_esp_config *config)
{
    char *text = nm_json_write(config->root, 0, NULL);
    if (!text)
        return false;
    nvs_handle_t handle;
    bool ok = false;
    if (strlen(text) <= 32768 &&
        nvs_open_from_partition("nmconfig", "processor", NVS_READWRITE, &handle) == ESP_OK) {
        ok = nvs_set_blob(handle, "config", text, strlen(text)) == ESP_OK &&
             nvs_commit(handle) == ESP_OK;
        nvs_close(handle);
    }
    free(text);
    return ok;
}

bool nm_esp_config_bind(nm_esp_config *config, yyjson_mut_val *root)
{
    if (!config || !yyjson_mut_is_obj(root))
        return false;
    config->root = root;
    if (!nm_probe_config_read(root, &config->max_task_queue_size)) {
        ESP_LOGE(TAG, "MaxTaskQueueSize must be an integer from 1 to %d", NM_PROBE_MAX_WORKERS);
        return false;
    }
    if (!nm_endpoint_operation_config_read(root, &config->max_outstanding_endpoint_operations)) {
        ESP_LOGE(TAG, "MaxOutstandingEndpointOperations must be an integer from 1 to %d",
                 NM_ENDPOINT_MAX_OPERATIONS);
        return false;
    }
    yyjson_mut_val *auth = yyjson_mut_obj_get(root, "AuthDevice");
    if (auth && !yyjson_mut_is_bool(auth) &&
        !(yyjson_mut_is_str(auth) && (!strcmp(yyjson_mut_get_str(auth), "true") ||
                                      !strcmp(yyjson_mut_get_str(auth), "false"))))
        return false;
    config->auth_device = yyjson_mut_is_true(auth) ||
                          (yyjson_mut_is_str(auth) && !strcmp(yyjson_mut_get_str(auth), "true"));
    yyjson_mut_val *setup = yyjson_mut_obj_get(root, "WiFiSetup");
    if (setup && !yyjson_mut_is_bool(setup))
        return false;
    config->wifi_setup = yyjson_mut_is_true(setup);
    config->wifi_ssid = required_string(root, "wifi_ssid");
    config->wifi_password = required_string(root, "wifi_password");
    config->broker_uri = required_string(root, "broker_uri");
    config->mqtt_username = required_string(root, "mqtt_username");
    config->mqtt_password = required_string(root, "mqtt_password");
    config->app_id = required_string(root, "app_id");
    config->auth_key = required_string(root, "auth_key");
    config->source = required_string(root, "source");
    config->ota_ca_pem = required_string(root, "ota_ca_pem");
    yyjson_mut_val *quantum = yyjson_mut_obj_get(root, "IsQuantumCapable");
    if (quantum && !yyjson_mut_is_bool(quantum))
        return false;
    config->is_quantum_capable = !quantum || yyjson_mut_is_true(quantum);
    if (config->wifi_setup)
        return config->auth_device &&
               parse_uint(root, "max_monitors", 1, NM_ESP_MAX_MONITORS, &config->max_monitors) &&
               parse_uint(root, "max_pending_ping_infos", config->max_monitors, 5000,
                          &config->max_pending_ping_infos) &&
               parse_uint(root, "poll_seconds", 1, 86400, &config->poll_seconds);
    if (config->auth_device) {
        return config->wifi_ssid && config->wifi_password &&
               strlen(config->wifi_ssid) <= 32 && strlen(config->wifi_password) <= 63 &&
               parse_uint(root, "max_monitors", 1, NM_ESP_MAX_MONITORS, &config->max_monitors) &&
               parse_uint(root, "max_pending_ping_infos", config->max_monitors, 5000,
                          &config->max_pending_ping_infos) &&
               parse_uint(root, "poll_seconds", 1, 86400, &config->poll_seconds);
    }
    if (!config->wifi_ssid || !config->wifi_password || !config->broker_uri ||
        !config->mqtt_username || !config->mqtt_password || !config->app_id || !config->auth_key ||
        !config->source || !*config->app_id || !*config->auth_key ||
        strlen(config->wifi_ssid) > 32 || strlen(config->wifi_password) > 63 ||
        strlen(config->broker_uri) > 255 || strlen(config->app_id) > 255 ||
        strlen(config->source) > 1024 ||
        !parse_uint(root, "max_monitors", 1, NM_ESP_MAX_MONITORS, &config->max_monitors) ||
        !parse_uint(root, "max_pending_ping_infos", config->max_monitors, 5000,
                    &config->max_pending_ping_infos) ||
        !parse_uint(root, "poll_seconds", 1, 86400, &config->poll_seconds))
        return false;
    uint8_t digest[32];
    size_t digest_length = 0;
    if (psa_hash_compute(PSA_ALG_SHA_256, (const uint8_t *)config->app_id,
                         strlen(config->app_id), digest, sizeof(digest),
                         &digest_length) != PSA_SUCCESS || digest_length != sizeof(digest))
        return false;
    char hash[65];
    for (size_t i = 0; i < sizeof(digest); ++i)
        snprintf(hash + i * 2, sizeof(hash) - i * 2, "%02x", digest[i]);
    size_t length = strlen(config->app_id);
    bool uuid = length >= 36 && (length == 36 || config->app_id[36] == '-');
    for (size_t i = 0; uuid && i < 36; ++i) {
        char c = config->app_id[i];
        bool hyphen = i == 8 || i == 13 || i == 18 || i == 23;
        if (hyphen ? c != '-'
                   : !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            uuid = false;
    }
    if (uuid) {
        char owner[37];
        memcpy(owner, config->app_id, 36);
        owner[36] = 0;
        for (size_t i = 0; i < 36; ++i)
            if (owner[i] >= 'A' && owner[i] <= 'F')
                owner[i] += 'a' - 'A';
        snprintf(config->routing_id, sizeof(config->routing_id), "u_%s_p_%s", owner, hash);
    } else
        snprintf(config->routing_id, sizeof(config->routing_id), "p_%s", hash);
    return true;
}
