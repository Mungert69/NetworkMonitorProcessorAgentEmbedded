#include "nm_esp.h"

#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "brotli/decode.h"
#include "brotli/encode.h"

static const char *TAG = "nm_storage";
static const char *partition = "nmdata";
static const char *space = "networkmonitor";
enum { MAX_BLOB = 512 * 1024, MAX_MONITORING_JSON = 1024 * 1024, HEADER_SIZE = 12 };
static const uint8_t monitoring_magic[8] = {'N', 'M', 'S', 'B', 1, '\r', '\n', 0};

/* The codec's working storage, including its private context, must not fall
 * back to internal RAM. Encoding/decoding happens before or after NVS I/O. */
static void *codec_alloc(void *opaque, size_t size)
{
    (void)opaque;
    return nm_bulk_malloc(size);
}

static void codec_free(void *opaque, void *pointer)
{
    (void)opaque;
    free(pointer);
}

static uint32_t read_length(const uint8_t *bytes)
{
    return (uint32_t)bytes[8] | ((uint32_t)bytes[9] << 8) | ((uint32_t)bytes[10] << 16) |
           ((uint32_t)bytes[11] << 24);
}

/* Owned PSRAM buffer on success; NULL leaves the previous NVS value intact. */
static uint8_t *compress_monitoring(const char *json, size_t length, size_t *stored)
{
    if (!length || length > MAX_MONITORING_JSON)
        return NULL;
    size_t capacity = BrotliEncoderMaxCompressedSize(length);
    if (!capacity)
        return NULL;
    if (capacity > MAX_BLOB - HEADER_SIZE)
        capacity = MAX_BLOB - HEADER_SIZE;
    uint8_t *buffer = nm_bulk_malloc(HEADER_SIZE + capacity);
    if (!buffer)
        return NULL;
    BrotliEncoderState *encoder = BrotliEncoderCreateInstance(codec_alloc, codec_free, NULL);
    if (!encoder) {
        free(buffer);
        return NULL;
    }
    bool ready = BrotliEncoderSetParameter(encoder, BROTLI_PARAM_QUALITY, 0) &&
                 BrotliEncoderSetParameter(encoder, BROTLI_PARAM_MODE, BROTLI_MODE_TEXT) &&
                 BrotliEncoderSetParameter(encoder, BROTLI_PARAM_SIZE_HINT, (uint32_t)length);
    size_t available_in = length, available_out = capacity;
    const uint8_t *next_in = (const uint8_t *)json;
    uint8_t *next_out = buffer + HEADER_SIZE;
    bool ok = ready &&
              BrotliEncoderCompressStream(encoder, BROTLI_OPERATION_FINISH, &available_in, &next_in,
                                          &available_out, &next_out, NULL) &&
              BrotliEncoderIsFinished(encoder) && available_in == 0;
    BrotliEncoderDestroyInstance(encoder);
    if (!ok) {
        free(buffer);
        return NULL;
    }
    memcpy(buffer, monitoring_magic, sizeof(monitoring_magic));
    uint32_t raw = (uint32_t)length;
    for (unsigned i = 0; i < 4; ++i)
        buffer[8 + i] = (uint8_t)(raw >> (i * 8));
    *stored = HEADER_SIZE + capacity - available_out;
    return buffer;
}

/* Exact length and complete stream are required; corrupt state fails closed. */
static char *decompress_monitoring(const uint8_t *blob, size_t length, size_t *decoded)
{
    if (length <= HEADER_SIZE || memcmp(blob, monitoring_magic, sizeof(monitoring_magic)))
        return NULL;
    uint32_t raw = read_length(blob);
    if (!raw || raw > MAX_MONITORING_JSON)
        return NULL;
    char *text = nm_bulk_malloc((size_t)raw + 1);
    if (!text)
        return NULL;
    BrotliDecoderState *decoder = BrotliDecoderCreateInstance(codec_alloc, codec_free, NULL);
    if (!decoder) {
        free(text);
        return NULL;
    }
    size_t available_in = length - HEADER_SIZE, available_out = raw, total_out = 0;
    const uint8_t *next_in = blob + HEADER_SIZE;
    uint8_t *next_out = (uint8_t *)text;
    BrotliDecoderResult result = BrotliDecoderDecompressStream(
        decoder, &available_in, &next_in, &available_out, &next_out, &total_out);
    BrotliDecoderDestroyInstance(decoder);
    if (result != BROTLI_DECODER_RESULT_SUCCESS || available_in || total_out != raw) {
        free(text);
        return NULL;
    }
    text[raw] = 0;
    *decoded = raw;
    return text;
}

bool nm_esp_storage_init(void)
{
    esp_err_t error = nvs_flash_init_partition(partition);
    if (error != ESP_OK)
        ESP_LOGE(TAG, "state partition unavailable error=%s", esp_err_to_name(error));
    return error == ESP_OK;
}

/* Boot-only: remove monitor ownership/data, never firmware rollback metadata. */
bool nm_esp_storage_reset_monitoring(void)
{
    if (!nm_esp_storage_init())
        return false;
    nvs_handle_t handle;
    if (nvs_open_from_partition(partition, space, NVS_READWRITE, &handle) != ESP_OK)
        return false;
    const char *keys[] = {"monitoring", "monitors", "processor"};
    bool ok = true;
    for (unsigned i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        esp_err_t error = nvs_erase_key(handle, keys[i]);
        if (error != ESP_OK && error != ESP_ERR_NVS_NOT_FOUND)
            ok = false;
    }
    if (ok)
        ok = nvs_commit(handle) == ESP_OK;
    nvs_close(handle);
    return ok;
}

yyjson_mut_doc *nm_esp_storage_load(const char *key)
{
    nvs_handle_t handle;
    if (nvs_open_from_partition(partition, space, NVS_READONLY, &handle) != ESP_OK)
        return NULL;
    size_t size = 0;
    esp_err_t error = nvs_get_blob(handle, key, NULL, &size);
    if (error != ESP_OK || size == 0 || size > MAX_BLOB) {
        nvs_close(handle);
        return NULL;
    }
    char *text = nm_bulk_malloc(size + 1);
    if (!text) {
        nvs_close(handle);
        return NULL;
    }
    error = nvs_get_blob(handle, key, text, &size);
    nvs_close(handle);
    if (error != ESP_OK) {
        free(text);
        return NULL;
    }
    bool compressed = !strcmp(key, "monitoring") && size >= sizeof(monitoring_magic) &&
                      !memcmp(text, monitoring_magic, sizeof(monitoring_magic));
    size_t decoded = 0;
    char *json = compressed ? decompress_monitoring((const uint8_t *)text, size, &decoded) : text;
    if (!compressed)
        decoded = size;
    if (json)
        json[decoded] = 0;
    yyjson_mut_doc *value = json ? nm_json_read(json, decoded) : NULL;
    if (compressed)
        free(json);
    free(text);
    if (!value)
        ESP_LOGE(TAG, "stored JSON is invalid key=%s", key);
    return value;
}

bool nm_esp_storage_has_key(const char *key)
{
    nvs_handle_t handle;
    esp_err_t opened = nvs_open_from_partition(partition, space, NVS_READONLY, &handle);
    /* Treat I/O/type errors as possibly-present state, never permission to
     * overwrite it with a fresh empty snapshot. Only NOT_FOUND means absent. */
    if (opened != ESP_OK)
        return opened != ESP_ERR_NVS_NOT_FOUND;
    size_t size = 0;
    esp_err_t error = nvs_get_blob(handle, key, NULL, &size);
    nvs_close(handle);
    return error != ESP_ERR_NVS_NOT_FOUND;
}

bool nm_esp_storage_save(const char *key, yyjson_mut_val *value)
{
    if (!key || !value)
        return false;
    size_t raw_size = 0;
    char *text = nm_json_write(value, 0, &raw_size);
    if (!text)
        return false;
    bool monitoring = !strcmp(key, "monitoring");
    size_t raw_limit = monitoring ? MAX_MONITORING_JSON : MAX_BLOB;
    if (raw_size == 0 || raw_size > raw_limit || !nm_json_depth_ok(text, raw_size)) {
        free(text);
        ESP_LOGE(TAG, "state exceeds storage size/depth limit key=%s bytes=%zu", key, raw_size);
        return false;
    }
    size_t size = raw_size;
    uint8_t *compressed = monitoring ? compress_monitoring(text, raw_size, &size) : NULL;
    if (monitoring && !compressed) {
        ESP_LOGE(TAG, "monitoring snapshot compression failed raw_bytes=%zu", raw_size);
        free(text);
        return false;
    }
    const void *bytes = monitoring ? (const void *)compressed : (const void *)text;
    nvs_handle_t handle;
    esp_err_t error = nvs_open_from_partition(partition, space, NVS_READWRITE, &handle);
    if (error == ESP_OK) {
        error = nvs_set_blob(handle, key, bytes, size);
        if (error == ESP_OK)
            error = nvs_commit(handle);
        if (error == ESP_OK && !strcmp(key, "monitoring")) {
            /* The complete replacement is durable before retiring migration
             * inputs. Keeping both forever can exhaust the 2 MiB partition. */
            const char *legacy[] = {"monitors", "processor"};
            bool changed = false;
            for (size_t i = 0; i < sizeof(legacy) / sizeof(legacy[0]); ++i) {
                esp_err_t cleanup = nvs_erase_key(handle, legacy[i]);
                if (cleanup == ESP_OK)
                    changed = true;
                else if (cleanup != ESP_ERR_NVS_NOT_FOUND)
                    ESP_LOGW(TAG, "legacy state cleanup deferred key=%s error=%s", legacy[i],
                             esp_err_to_name(cleanup));
            }
            if (changed && nvs_commit(handle) != ESP_OK)
                ESP_LOGW(
                    TAG,
                    "legacy state cleanup commit deferred; monitoring snapshot is already durable");
        }
        nvs_close(handle);
    }
    if (error == ESP_OK && monitoring) {
        nvs_stats_t stats = {0};
        if (nvs_get_stats(partition, &stats) == ESP_OK)
            ESP_LOGI(
                TAG,
                "snapshot raw_bytes=%zu stored_bytes=%zu nvs_used_entries=%zu nvs_free_entries=%zu "
                "nvs_available_entries=%zu nvs_total_entries=%zu",
                raw_size, size, stats.used_entries, stats.free_entries, stats.available_entries,
                stats.total_entries);
        else
            ESP_LOGW(TAG,
                     "snapshot saved raw_bytes=%zu stored_bytes=%zu; NVS capacity statistics "
                     "unavailable",
                     raw_size, size);
    }
    free(compressed);
    free(text);
    if (error != ESP_OK)
        ESP_LOGE(TAG, "state save failed key=%s error=%s", key, esp_err_to_name(error));
    return error == ESP_OK;
}
