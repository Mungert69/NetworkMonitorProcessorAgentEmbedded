#include "nm_esp.h"
#include "ota_version.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_app_desc.h"
#include "esp_crt_bundle.h"
#include "esp_https_ota.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "psa/crypto.h"

static const char *TAG = "nm_ota";
static const char *META_KEY = "fwmeta";

static bool running_pending(void)
{
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t state;
    return running && esp_ota_get_state_partition(running, &state) == ESP_OK &&
           state == ESP_OTA_IMG_PENDING_VERIFY;
}

bool nm_esp_ota_pending(void)
{
    return running_pending();
}

static const char *field(yyjson_mut_val *obj, const char *key)
{
    yyjson_mut_val *item = yyjson_mut_obj_get(obj, key);
    return yyjson_mut_is_str(item) ? yyjson_mut_get_str(item) : "";
}

static yyjson_mut_doc *load_meta(void)
{
    yyjson_mut_doc *doc = nm_esp_storage_load(META_KEY);
    if (!doc && nm_esp_storage_has_key(META_KEY))
        return NULL;
    if (!doc) {
        doc = nm_json_new();
        yyjson_mut_doc_set_root(doc, yyjson_mut_obj(doc));
    }
    if (!yyjson_mut_is_obj(yyjson_mut_doc_get_root(doc))) {
        yyjson_mut_doc_free(doc);
        return NULL;
    }
    return doc;
}

static bool clear_pending(void)
{
    yyjson_mut_doc *meta_doc = load_meta();
    yyjson_mut_val *meta = yyjson_mut_doc_get_root(meta_doc);
    if (!meta)
        return false;
    yyjson_mut_obj_remove_key(meta, "PendingVersion");
    yyjson_mut_obj_remove_key(meta, "PendingRequestId");
    yyjson_mut_obj_remove_key(meta, "PendingSha256");
    bool ok = nm_esp_storage_save(META_KEY, meta);
    yyjson_mut_doc_free(meta_doc);
    return ok;
}

static bool valid_request_id(const char *id)
{
    if (!id || strlen(id) != 36)
        return false;
    for (size_t i = 0; i < 36; ++i) {
        bool dash = i == 8 || i == 13 || i == 18 || i == 23;
        if (dash ? id[i] != '-'
                 : !((id[i] >= '0' && id[i] <= '9') || (id[i] >= 'a' && id[i] <= 'f')))
            return false;
    }
    return true;
}

bool nm_esp_ota_can_install(const char *url, const char *version, const char *sha256,
                            const char *request_id)
{
    unsigned proposed[3], accepted[3];
    if (!url || !version || !sha256 || !valid_request_id(request_id) ||
        !parse_version(version, proposed) || strlen(sha256) != 64 ||
        strncmp(url, "https://", 8) != 0 || strlen(url) > 1024 || strchr(url, '?') ||
        strchr(url, '#') || strchr(url, '@') || !esp_ota_get_next_update_partition(NULL) ||
        running_pending())
        return false;
    for (size_t i = 0; i < 64; ++i)
        if (!((sha256[i] >= '0' && sha256[i] <= '9') || (sha256[i] >= 'a' && sha256[i] <= 'f')))
            return false;
    char suffix[70];
    snprintf(suffix, sizeof(suffix), "/%s.bin", sha256);
    size_t length = strlen(url), suffix_length = strlen(suffix);
    if (length <= suffix_length + 8 || strcmp(url + length - suffix_length, suffix) != 0)
        return false;

    yyjson_mut_doc *meta_doc = load_meta();
    yyjson_mut_val *meta = yyjson_mut_doc_get_root(meta_doc);
    if (!meta)
        return false;
    bool okay = true;
    const char *accepted_version = field(meta, "AcceptedVersion");
    if (*accepted_version && !parse_version(accepted_version, accepted))
        okay = false;
    if (strcmp(field(meta, "AcceptedRequestId"), request_id) == 0 ||
        strcmp(field(meta, "PendingRequestId"), request_id) == 0)
        okay = false;
    const esp_app_desc_t *running = esp_app_get_description();
    if (!running || !ota_version_permitted(version, running->version))
        okay = false;
    yyjson_mut_doc_free(meta_doc);
    return okay;
}

bool nm_esp_ota_add_status_fields(yyjson_mut_doc *doc, yyjson_mut_val *data)
{
    if (!yyjson_mut_is_obj(data))
        return false;
    yyjson_mut_doc *meta_doc = load_meta();
    yyjson_mut_val *meta = yyjson_mut_doc_get_root(meta_doc);
    if (!meta)
        return false;
    bool ok = true;
    if (running_pending()) {
        const char *request_id = field(meta, "PendingRequestId");
        const char *version = field(meta, "PendingVersion");
        const esp_app_desc_t *running = esp_app_get_description();
        ok = valid_request_id(request_id) && running && strcmp(version, running->version) == 0 &&
             yyjson_mut_obj_add_strcpy(doc, data, "RequestId", request_id) &&
             yyjson_mut_obj_add_strcpy(doc, data, "Version", version) &&
             yyjson_mut_obj_add_strcpy(doc, data, "Status", "PendingConfirmation");
    } else {
        const char *pending_version = field(meta, "PendingVersion");
        const char *pending_id = field(meta, "PendingRequestId");
        const esp_app_desc_t *running = esp_app_get_description();
        if (running && *pending_version && valid_request_id(pending_id) &&
            strcmp(pending_version, running->version) == 0) {
            bool repaired = nm_json_put_str(meta_doc, meta, "AcceptedVersion", pending_version) &&
                            nm_json_put_str(meta_doc, meta, "AcceptedRequestId", pending_id);
            yyjson_mut_obj_remove_key(meta, "PendingVersion");
            yyjson_mut_obj_remove_key(meta, "PendingRequestId");
            yyjson_mut_obj_remove_key(meta, "PendingSha256");
            if (!repaired || !nm_esp_storage_save(META_KEY, meta))
                ok = false;
        }
        const char *confirmed = field(meta, "AcceptedRequestId");
        ok = ok && valid_request_id(confirmed) &&
             yyjson_mut_obj_add_strcpy(doc, data, "RequestId", confirmed) &&
             yyjson_mut_obj_add_strcpy(doc, data, "Version", field(meta, "AcceptedVersion")) &&
             yyjson_mut_obj_add_strcpy(doc, data, "Status", "Confirmed");
    }
    yyjson_mut_doc_free(meta_doc);
    return ok;
}

bool nm_esp_ota_confirm_from_backend(yyjson_mut_val *data)
{
    if (!running_pending() || !yyjson_mut_is_obj(data))
        return false;
    yyjson_mut_doc *meta_doc = load_meta();
    yyjson_mut_val *meta = yyjson_mut_doc_get_root(meta_doc);
    if (!meta)
        return false;
    const char *request_id = field(meta, "PendingRequestId");
    const char *version = field(meta, "PendingVersion");
    const esp_app_desc_t *running = esp_app_get_description();
    bool matches = valid_request_id(request_id) && running &&
                   strcmp(version, running->version) == 0 &&
                   strcmp(request_id, field(data, "RequestId")) == 0 &&
                   strcmp(version, field(data, "Version")) == 0;
    if (!matches) {
        yyjson_mut_doc_free(meta_doc);
        return false;
    }
    esp_err_t error = esp_ota_mark_app_valid_cancel_rollback();
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "OTA confirmation rejected error=%s", esp_err_to_name(error));
        yyjson_mut_doc_free(meta_doc);
        return false;
    }
    bool saved = nm_json_put_str(meta_doc, meta, "AcceptedVersion", version) &&
                 nm_json_put_str(meta_doc, meta, "AcceptedRequestId", request_id);
    yyjson_mut_obj_remove_key(meta, "PendingVersion");
    yyjson_mut_obj_remove_key(meta, "PendingRequestId");
    yyjson_mut_obj_remove_key(meta, "PendingSha256");
    saved = saved && nm_esp_storage_save(META_KEY, meta);
    yyjson_mut_doc_free(meta_doc);
    if (!saved)
        ESP_LOGE(TAG, "OTA confirmed but metadata persistence failed");
    else
        ESP_LOGI(TAG, "OTA confirmed by Data service");
    return true;
}

static void health_timeout(void *argument)
{
    (void)argument;
    vTaskDelay(pdMS_TO_TICKS(120000));
    if (running_pending()) {
        ESP_LOGE(TAG, "OTA health check timed out; rolling back");
        esp_err_t error = esp_ota_mark_app_invalid_rollback_and_reboot();
        ESP_LOGE(TAG, "OTA rollback failed error=%s", esp_err_to_name(error));
    }
    vTaskDelete(NULL);
}

void nm_esp_ota_start_health_watchdog(void)
{
    if (!running_pending())
        return;
    if (xTaskCreate(health_timeout, "nm_ota_health", 3072, NULL, 5, NULL) != pdPASS) {
        ESP_LOGE(TAG, "OTA health watchdog unavailable; rolling back");
        esp_ota_mark_app_invalid_rollback_and_reboot();
    }
}

static bool image_digest_matches(const esp_partition_t *partition, size_t length,
                                 const char *expected)
{
    if (!partition || length < 1024 || length > partition->size)
        return false;
    uint8_t *buffer = malloc(4096);
    if (!buffer)
        return false;
    psa_hash_operation_t sha = PSA_HASH_OPERATION_INIT;
    psa_status_t status = psa_hash_setup(&sha, PSA_ALG_SHA_256);
    for (size_t offset = 0; status == PSA_SUCCESS && offset < length; offset += 4096) {
        size_t count = length - offset < 4096 ? length - offset : 4096;
        if (esp_partition_read(partition, offset, buffer, count) != ESP_OK) {
            status = PSA_ERROR_GENERIC_ERROR;
            break;
        }
        status = psa_hash_update(&sha, buffer, count);
    }
    uint8_t digest[32];
    size_t digest_length = 0;
    if (status == PSA_SUCCESS)
        status = psa_hash_finish(&sha, digest, sizeof(digest), &digest_length);
    /* Safe after finish too; release resources on every failure path. */
    psa_hash_abort(&sha);
    free(buffer);
    if (status != PSA_SUCCESS || digest_length != sizeof(digest))
        return false;
    char actual[65];
    for (size_t i = 0; i < 32; ++i)
        snprintf(actual + 2 * i, sizeof(actual) - 2 * i, "%02x", digest[i]);
    return strcmp(actual, expected) == 0;
}

bool nm_esp_ota_install(const nm_esp_config *config, const char *url, const char *version,
                        const char *sha256, const char *request_id)
{
    if (!config || !nm_esp_ota_can_install(url, version, sha256, request_id)) {
        ESP_LOGE(TAG, "OTA rejected: invalid or stale update command");
        return false;
    }
    const esp_partition_t *target = esp_ota_get_next_update_partition(NULL);
    esp_http_client_config_t http = {
        .url = url,
        .timeout_ms = 15000,
        .buffer_size = 4096,
        .buffer_size_tx = 1024,
        .disable_auto_redirect = true,
        .keep_alive_enable = false,
    };
    if (config->ota_ca_pem && *config->ota_ca_pem)
        http.cert_pem = config->ota_ca_pem;
    else
        http.crt_bundle_attach = esp_crt_bundle_attach;
    esp_https_ota_config_t ota = {
        .http_config = &http,
        .partial_http_download = true,
        .max_http_request_size = 4096,
    };
    ESP_LOGI(TAG, "starting HTTPS OTA to inactive slot version=%s", version);
    esp_https_ota_handle_t handle = NULL;
    esp_err_t error = esp_https_ota_begin(&ota, &handle);
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "HTTPS OTA begin failed error=%s", esp_err_to_name(error));
        return false;
    }
    esp_app_desc_t descriptor = {0};
    if (esp_https_ota_get_img_desc(handle, &descriptor) != ESP_OK ||
        !memchr(descriptor.version, '\0', sizeof(descriptor.version)) ||
        strcmp(descriptor.version, version) != 0) {
        ESP_LOGE(TAG, "OTA image version does not match command");
        esp_https_ota_abort(handle);
        return false;
    }
    int64_t deadline = esp_timer_get_time() + 300000000LL;
    do {
        error = esp_https_ota_perform(handle);
    } while (error == ESP_ERR_HTTPS_OTA_IN_PROGRESS && esp_timer_get_time() < deadline);
    int length = esp_https_ota_get_image_len_read(handle);
    if (error != ESP_OK || !esp_https_ota_is_complete_data_received(handle) || length < 1024 ||
        !image_digest_matches(target, (size_t)length, sha256)) {
        ESP_LOGE(TAG, "OTA download failed or SHA-256 mismatch error=%s bytes=%d",
                 esp_err_to_name(error), length);
        esp_https_ota_abort(handle);
        return false;
    }
    yyjson_mut_doc *meta_doc = load_meta();
    yyjson_mut_val *meta = yyjson_mut_doc_get_root(meta_doc);
    bool saved = meta && nm_json_put_str(meta_doc, meta, "PendingVersion", version) &&
                 nm_json_put_str(meta_doc, meta, "PendingRequestId", request_id) &&
                 nm_json_put_str(meta_doc, meta, "PendingSha256", sha256) &&
                 nm_esp_storage_save(META_KEY, meta);
    yyjson_mut_doc_free(meta_doc);
    if (!saved) {
        ESP_LOGE(TAG, "OTA metadata save failed");
        esp_https_ota_abort(handle);
        return false;
    }
    error = esp_https_ota_finish(handle);
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "OTA image validation failed error=%s", esp_err_to_name(error));
        clear_pending();
        return false;
    }
    ESP_LOGI(TAG, "OTA image verified; rebooting into new app");
    esp_restart();
    return true;
}
