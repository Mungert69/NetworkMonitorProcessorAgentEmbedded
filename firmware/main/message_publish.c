#include "message_publish.h"
#include "brotli/encode.h"
#include "esp_random.h"
#include "mbedtls/base64.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static yyjson_mut_val *message_envelope(yyjson_mut_doc *doc, const char *source, const char *type,
                                        yyjson_mut_val *data)
{
    yyjson_mut_val *event = yyjson_mut_obj(doc);
    if (!event)
        return NULL;
    uint8_t random[16];
    esp_fill_random(random, sizeof(random));
    random[6] = (uint8_t)((random[6] & 0x0fU) | 0x40U);
    random[8] = (uint8_t)((random[8] & 0x3fU) | 0x80U);
    char id[37];
    snprintf(id, sizeof(id), "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             random[0], random[1], random[2], random[3], random[4], random[5], random[6], random[7],
             random[8], random[9], random[10], random[11], random[12], random[13], random[14],
             random[15]);
    time_t now = time(NULL);
    struct tm utc;
    char timestamp[32];
    if (!gmtime_r(&now, &utc) ||
        !strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &utc))
        strcpy(timestamp, "1970-01-01T00:00:00Z");
    if (!yyjson_mut_obj_add_strcpy(doc, event, "specversion", "") ||
        !yyjson_mut_obj_add_strcpy(doc, event, "id", id) ||
        !yyjson_mut_obj_add_strcpy(doc, event, "type", type) ||
        !yyjson_mut_obj_add_strcpy(doc, event, "source", source) ||
        !yyjson_mut_obj_add_strcpy(doc, event, "time", timestamp) ||
        !yyjson_mut_obj_add_strcpy(doc, event, "datacontenttype", "") ||
        !yyjson_mut_obj_add_val(doc, event, "data", data)) {
        return NULL;
    }
    return event;
}

static char *compressed_base64(yyjson_mut_val *data)
{
    size_t length = 0;
    char *json = nm_json_write(data, 0, &length);
    if (!json)
        return NULL;
    size_t capacity = length <= 512 * 1024 ? BrotliEncoderMaxCompressedSize(length) : 0;
    if (!capacity) {
        free(json);
        return NULL;
    }
    uint8_t *compressed = nm_bulk_malloc(capacity);
    if (!compressed) {
        free(json);
        return NULL;
    }
    bool ok = BrotliEncoderCompress(0, BROTLI_DEFAULT_WINDOW, BROTLI_MODE_TEXT, length,
                                    (const uint8_t *)json, &capacity, compressed);
    free(json);
    if (!ok || capacity > (NM_ESP_MAX_PUBLICATION - 2048) * 3 / 4) {
        free(compressed);
        return NULL;
    }
    size_t bytes = 4 * ((capacity + 2) / 3), written = 0;
    char *out = nm_bulk_malloc(bytes + 1);
    if (!out || mbedtls_base64_encode((uint8_t *)out, bytes + 1, &written, compressed, capacity)) {
        free(out);
        out = NULL;
    } else
        out[written] = 0;
    free(compressed);
    return out;
}

static char *encode_event(const nm_esp_config *config, yyjson_mut_val *data,
                          nm_message_encoding encoding, const char *type, size_t *length)
{
    if (encoding < NM_MESSAGE_JSON || encoding > NM_MESSAGE_BROTLI_TUPLE)
        return NULL;
    yyjson_mut_doc *doc = nm_json_new();
    if (!doc)
        return NULL;
    char *encoded = encoding == NM_MESSAGE_JSON ? NULL : compressed_base64(data);
    yyjson_mut_val *payload = NULL;
    if (encoding == NM_MESSAGE_JSON) {
        payload = yyjson_mut_val_mut_copy(doc, data);
    } else if (encoded && encoding == NM_MESSAGE_BROTLI_TUPLE) {
        payload = yyjson_mut_obj(doc);
        if (!yyjson_mut_obj_add_strcpy(doc, payload, "Item1", encoded) ||
            !yyjson_mut_obj_add_strcpy(doc, payload, "Item2", config->app_id))
            payload = NULL;
    } else if (encoded) {
        payload = yyjson_mut_strcpy(doc, encoded);
    }
    free(encoded);
    yyjson_mut_val *event = payload ? message_envelope(doc, config->source, type, payload) : NULL;
    char *body = event ? nm_json_write(event, 0, length) : NULL;
    yyjson_mut_doc_free(doc);
    return body;
}

size_t nm_esp_event_wire_size(const nm_esp_config *config, yyjson_mut_val *payload,
                              nm_message_encoding encoding, const char *type)
{
    size_t length = 0;
    char *body = encode_event(config, payload, encoding, type, &length);
    bool valid = body != NULL;
    free(body);
    return valid ? length : 0;
}

bool nm_esp_publish_event(const nm_esp_config *config, esp_mqtt_client_handle_t client,
                          const char *topic, yyjson_mut_val *data, nm_message_encoding encoding,
                          const char *type)
{
    size_t length = 0;
    char *body = encode_event(config, data, encoding, type, &length);
    bool ok = body && length <= NM_ESP_MAX_PUBLICATION &&
              esp_mqtt_client_publish(client, topic, body, (int)length, 1, 0) >= 0;
    free(body);
    return ok;
}
