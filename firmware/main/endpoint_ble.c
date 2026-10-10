#include "ble_buffer.h"
#include "ble_crypto.h"
#include "ble_metric.h"
#include "endpoint_internal.h"
#include "ble_scanner.h"
#include "ble_filter.h"
#include "nm_memory.h"
#include "esp_timer.h"
#ifdef ESP_PLATFORM
#include "esp_log.h"
#endif
#include "mbedtls/base64.h"
#include "psa/crypto.h"
#include <ctype.h>
#include <math.h>
#include <strings.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { BLE_KEY_MAX = 32 };
#ifdef ESP_PLATFORM
static uint32_t diagnostic_fingerprint(const uint8_t *bytes, size_t length)
{
    uint32_t hash = 2166136261U;
    for (size_t i = 0; i < length; ++i)
        hash = (hash ^ bytes[i]) * 16777619U;
    return hash;
}
#endif

typedef nm_ble_bytes byte_span;
#define aes_ecb_encrypt_block nm_ble_aes_block

static bool normalize_address(const char *input, char out[NM_BLE_ADDRESS_TEXT_SIZE])
{
    if (!input)
        return false;
    while (isspace((unsigned char)*input))
        ++input;
    size_t length = strlen(input);
    while (length && isspace((unsigned char)input[length - 1]))
        --length;
    if (length == 12) {
        for (size_t i = 0; i < 12; ++i)
            if (!isxdigit((unsigned char)input[i]))
                return false;
        size_t dst = 0;
        for (size_t i = 0; i < 12; i += 2) {
            if (i)
                out[dst++] = ':';
            out[dst++] = (char)toupper((unsigned char)input[i]);
            out[dst++] = (char)toupper((unsigned char)input[i + 1]);
        }
        out[dst] = '\0';
        return true;
    }
    if (length != 17)
        return false;
    char separator = input[2];
    if (separator != ':' && separator != '-')
        return false;
    for (size_t i = 0; i < length; ++i) {
        if ((i + 1) % 3 == 0) {
            if (input[i] != separator)
                return false;
        } else if (!isxdigit((unsigned char)input[i])) {
            return false;
        }
        out[i] = (i + 1) % 3 == 0 ? ':' : (char)toupper((unsigned char)input[i]);
    }
    out[length] = '\0';
    return true;
}

static bool next_argument(const char **cursor, char *token, size_t capacity)
{
    const char *p = *cursor;
    while (isspace((unsigned char)*p))
        ++p;
    if (!*p) {
        *cursor = p;
        return false;
    }
    size_t used = 0;
    char quote = 0;
    bool valid = true;
    while (*p && (quote || !isspace((unsigned char)*p))) {
        char c = *p++;
        if (c == '\\' && *p)
            c = *p++;
        else if (c == '\'' || c == '"') {
            if (!quote) {
                quote = c;
                continue;
            }
            if (quote == c) {
                quote = 0;
                continue;
            }
        }
        if (used + 1 < capacity)
            token[used++] = c;
        else
            valid = false;
    }
    token[used] = 0;
    if (!valid || quote)
        token[0] = 0;
    *cursor = p;
    return true;
}

/* Command schemas reject misspelled options rather than silently recording a
 * receipt duration. Bounds remain explicit; manual numeric overrides are a
 * documented ESP32 limitation. Positional text is ignored, like CliArgParser. */
static bool supported_options(const char *arguments, bool listen)
{
    const char *names[] = {"--format",          "--key",          "--payload",
                           "--manufacturer_id", "--nonce_len",    "--tag_len",
                           "--nonce_at",        "--service_uuid", "--raw_payload"};
    const char *cursor = arguments ? arguments : "";
    char token[600];
    while (next_argument(&cursor, token, sizeof(token))) {
        if (!token[0])
            return false;
        if (strncmp(token, "--", 2))
            continue;
        char *eq = strchr(token, '=');
        if (eq)
            *eq = 0;
        bool known = false;
        for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
            known = known || !strcasecmp(token, names[i]);
        known =
            known || (listen ? !strcasecmp(token, "--max_captures")
                             : (!strcasecmp(token, "--address") || !strcasecmp(token, "--metric") ||
                                !strcasecmp(token, "--metric_scale") ||
                                !strcasecmp(token, "--metric_offset")));
        if (!known)
            return false;
        if (!eq && next_argument(&cursor, token, sizeof(token))) {
            if (!token[0] || !strncmp(token, "--", 2))
                return false;
        }
    }
    return true;
}

static void normalize_metric(char *metric)
{
    size_t used = 0;
    bool separator = false;
    for (const unsigned char *p = (unsigned char *)metric; *p; ++p) {
        if ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9')) {
            if (separator && used)
                metric[used++] = '_';
            metric[used++] = (char)tolower(*p);
            separator = false;
        } else
            separator = true;
    }
    metric[used] = 0;
}

/* 0: absent, 1: found, -1: malformed or oversized. */
static int option_value(const char *arguments, const char *name, char *out, size_t capacity)
{
    if (!out || !capacity)
        return false;
    if (!arguments || !name)
        return false;
    char token[600], next[600];
    size_t name_length = strlen(name);
    const char *cursor = arguments;
    int found = 0;
    while (next_argument(&cursor, token, sizeof(token))) {
        if (!token[0])
            return -1;
        if (strncasecmp(token, name, name_length) != 0)
            continue;
        const char *value = NULL;
        if (token[name_length] == '=')
            value = token + name_length + 1;
        else if (token[name_length] == '\0' && next_argument(&cursor, next, sizeof(next)))
            value = next;
        if (token[name_length] != '=' && token[name_length] != '\0')
            continue;
        if (value) {
            size_t length = strlen(value);
            if (length >= 2 && (value[0] == '\'' || value[0] == '"') &&
                value[length - 1] == value[0]) {
                ((char *)value)[length - 1] = 0;
                ++value;
            }
        }
        if (!value || !*value || strlen(value) >= capacity || !strncmp(value, "--", 2))
            return -1;
        if (found && !strcasecmp(name, "--metric"))
            return -1;
        memcpy(out, value, strlen(value) + 1);
        found = 1; /* .NET command options use the last value. */
    }
    return found;
}

static bool parse_hex_key(const char *text, uint8_t *key, size_t *key_length)
{
    size_t length = strlen(text);
    if (length >= 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        text += 2;
        length -= 2;
    }
    if ((length & 1U) || length > BLE_KEY_MAX * 2U)
        return false;
    for (size_t i = 0; i < length; i += 2) {
        int hi = isdigit((unsigned char)text[i])    ? text[i] - '0'
                 : isxdigit((unsigned char)text[i]) ? toupper((unsigned char)text[i]) - 'A' + 10
                                                    : -1;
        int lo = isdigit((unsigned char)text[i + 1]) ? text[i + 1] - '0'
                 : isxdigit((unsigned char)text[i + 1])
                     ? toupper((unsigned char)text[i + 1]) - 'A' + 10
                     : -1;
        if (hi < 0 || lo < 0)
            return false;
        key[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    *key_length = length / 2;
    return true;
}

static bool parse_key(const char *text, uint8_t *key, size_t *key_length)
{
    *key_length = 0;
    if (!text || !*text)
        return true;
    char trimmed[128];
    size_t length = strlen(text);
    while (length && isspace((unsigned char)text[length - 1]))
        --length;
    size_t start = 0;
    while (start < length && isspace((unsigned char)text[start]))
        ++start;
    length -= start;
    if (!length)
        return true;
    if (length >= sizeof(trimmed))
        return false;
    memcpy(trimmed, text + start, length);
    trimmed[length] = '\0';

    bool all_hex = length >= 2 && trimmed[0] == '0' && (trimmed[1] == 'x' || trimmed[1] == 'X');
    if (all_hex) {
        for (size_t i = 2; i < length; ++i)
            if (!isxdigit((unsigned char)trimmed[i]))
                all_hex = false;
    } else {
        all_hex = length > 0;
        for (size_t i = 0; i < length; ++i)
            if (!isxdigit((unsigned char)trimmed[i]))
                all_hex = false;
    }
    if (all_hex && parse_hex_key(trimmed, key, key_length)) {
        /* A 16/24/32-character hexadecimal string is hex, matching .NET. */
    } else {
        size_t decoded = 0;
        int error = mbedtls_base64_decode(key, BLE_KEY_MAX, &decoded,
                                          (const unsigned char *)trimmed, length);
        if (error == 0) {
            *key_length = decoded;
        } else if (length <= BLE_KEY_MAX) {
            memcpy(key, trimmed, length);
            *key_length = length;
        } else {
            return false;
        }
    }
    return *key_length <= BLE_KEY_MAX;
}

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static bool parse_hex_payload(const char *text, uint8_t out[NM_BLE_ADVERTISEMENT_MAX],
                              size_t *length)
{
    if (!text || !length)
        return false;
    if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X'))
        text += 2;
    size_t size = strlen(text);
    if (!size || (size & 1U) || size > NM_BLE_ADVERTISEMENT_MAX * 2U)
        return false;
    for (size_t i = 0; i < size; i += 2) {
        int hi = hex_digit(text[i]), lo = hex_digit(text[i + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    *length = size / 2;
    return true;
}

/* UUIDs in 16/32-bit AD fields are little-endian; full GUID fields may be
 * exposed in Windows Guid memory order or BLE wire order. Accept both. */
static bool parse_service_uuid(const char *text, uint8_t out[16], size_t *length)
{
    *length = 0;
    if (!text || !*text)
        return true;
    if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X'))
        text += 2;
    size_t n = strlen(text);
    if (n == 4 || n == 8) {
        *length = n / 2;
        for (size_t i = 0; i < *length; ++i) {
            size_t offset = n - 2 - i * 2;
            int hi = hex_digit(text[offset]), lo = hex_digit(text[offset + 1]);
            if (hi < 0 || lo < 0)
                return false;
            out[i] = (uint8_t)((hi << 4) | lo);
        }
        return true;
    }
    if (n != 36 || text[8] != '-' || text[13] != '-' || text[18] != '-' || text[23] != '-')
        return false;
    size_t used = 0;
    for (size_t i = 0; i < n; ++i) {
        if (text[i] == '-')
            continue;
        if (i + 1 >= n || text[i + 1] == '-')
            return false;
        int hi = hex_digit(text[i]), lo = hex_digit(text[++i]);
        if (hi < 0 || lo < 0 || used >= 16)
            return false;
        out[used++] = (uint8_t)((hi << 4) | lo);
    }
    *length = used;
    return used == 16;
}

static bool service_uuid_equal(const uint8_t *value, const uint8_t *uuid, size_t length)
{
    if (length <= 4)
        return !memcmp(value, uuid, length);
    uint8_t windows[16];
    for (size_t i = 0; i < 16; ++i)
        windows[i] = uuid[i];
    windows[0] = uuid[3];
    windows[1] = uuid[2];
    windows[2] = uuid[1];
    windows[3] = uuid[0];
    windows[4] = uuid[5];
    windows[5] = uuid[4];
    windows[6] = uuid[7];
    windows[7] = uuid[6];
    if (!memcmp(value, windows, 16))
        return true;
    for (size_t i = 0; i < 16; ++i)
        if (value[i] != uuid[15 - i])
            return false;
    return true;
}

static byte_span advertisement_payload(const nm_ble_advertisement *advertisement,
                                       const char **payload_type, int company, const char *mode,
                                       const uint8_t *service_uuid, size_t service_uuid_length)
{
    if (!strcmp(mode, "raw")) {
        *payload_type = "raw";
        return (byte_span){.bytes = advertisement->data, .length = advertisement->data_length};
    }
    if (!strcmp(mode, "service")) {
        for (size_t offset = 0; offset < advertisement->data_length;) {
            size_t field = advertisement->data[offset];
            if (!field || field > advertisement->data_length - offset - 1)
                break;
            uint8_t type = advertisement->data[offset + 1];
            size_t uuid_size = type == 0x16 ? 2 : type == 0x20 ? 4 : type == 0x21 ? 16 : 0;
            if (uuid_size && field > uuid_size + 1 &&
                (!service_uuid_length ||
                 (service_uuid_length == uuid_size &&
                  service_uuid_equal(advertisement->data + offset + 2, service_uuid, uuid_size)))) {
                *payload_type = "service";
                return (byte_span){.bytes = advertisement->data + offset + 2 + uuid_size,
                                   .length = field - 1 - uuid_size};
            }
            offset += field + 1;
        }
    } else {
        const uint8_t *value = NULL;
        size_t length = 0;
        if (nm_ble_ad_field(advertisement->data, advertisement->data_length, 0xff, company, &value,
                            &length)) {
            *payload_type = "manufacturer";
            return (byte_span){.bytes = value, .length = length};
        }
    }
    /* Match .NET's fallback to raw scan data when the selected field is absent. */
    *payload_type = "raw";
    return (byte_span){.bytes = advertisement->data, .length = advertisement->data_length};
}

static bool decrypt_payload(const char *format, byte_span payload, const uint8_t *key,
                            size_t key_length, unsigned nonce_len, unsigned tag_len,
                            bool nonce_at_end, uint8_t output[NM_BLE_ADVERTISEMENT_MAX],
                            byte_span *plaintext)
{
    if (!payload.bytes || !payload.length)
        return false;
    if (!strcmp(format, "raw")) {
        *plaintext = payload;
        return true;
    }
    if (!key_length || nonce_len == 0 || nonce_len > 16 || payload.length <= nonce_len)
        return false;
    const uint8_t *nonce =
        nonce_at_end ? payload.bytes + payload.length - nonce_len : payload.bytes;
    const uint8_t *cipher = nonce_at_end ? payload.bytes : payload.bytes + nonce_len;
    size_t cipher_len = payload.length - nonce_len;
    if (!strcmp(format, "aesgcm")) {
        if (tag_len < 12 || tag_len > 16 || cipher_len <= tag_len)
            return false;
        const uint8_t *tag =
            nonce_at_end ? cipher + cipher_len - tag_len : payload.bytes + payload.length - tag_len;
        cipher_len -= tag_len;
        if (cipher_len + tag_len > NM_BLE_ADVERTISEMENT_MAX ||
            (key_length != 16 && key_length != 24 && key_length != 32))
            return false;
        uint8_t ciphertext_and_tag[NM_BLE_ADVERTISEMENT_MAX];
        memcpy(ciphertext_and_tag, cipher, cipher_len);
        memcpy(ciphertext_and_tag + cipher_len, tag, tag_len);
        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
        psa_set_key_bits(&attributes, key_length * 8);
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
        psa_algorithm_t algorithm = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, tag_len);
        psa_set_key_algorithm(&attributes, algorithm);
        mbedtls_svc_key_id_t handle = PSA_KEY_ID_NULL;
        psa_status_t status = psa_import_key(&attributes, key, key_length, &handle);
        psa_reset_key_attributes(&attributes);
        size_t output_length = 0;
        if (status == PSA_SUCCESS)
            status = psa_aead_decrypt(handle, algorithm, nonce, nonce_len, NULL, 0,
                                      ciphertext_and_tag, cipher_len + tag_len, output,
                                      NM_BLE_ADVERTISEMENT_MAX, &output_length);
        if (handle != PSA_KEY_ID_NULL)
            psa_destroy_key(handle);
        if (status != PSA_SUCCESS || output_length != cipher_len)
            return false;
    } else if (!strcmp(format, "aesctr")) {
        uint8_t counter[16] = {0}, stream[16];
        memcpy(counter, nonce, nonce_len);
        for (size_t offset = 0; offset < cipher_len; offset += 16) {
            if (!aes_ecb_encrypt_block(key, key_length, counter, stream))
                return false;
            size_t block = cipher_len - offset < 16 ? cipher_len - offset : 16;
            for (size_t i = 0; i < block; ++i)
                output[offset + i] = cipher[offset + i] ^ stream[i];
            for (int i = 15; i >= 12; --i)
                if (++counter[i])
                    break;
        }
    } else
        return false;
    *plaintext = (byte_span){.bytes = output, .length = cipher_len};
    return true;
}

static void append_text(char *out, size_t capacity, size_t *used, const char *format, ...)
{
    if (*used >= capacity)
        return;
    va_list args;
    va_start(args, format);
    int written = vsnprintf(out + *used, capacity - *used, format, args);
    va_end(args);
    if (written > 0) {
        size_t room = capacity - *used;
        *used += (size_t)written < room ? (size_t)written : room - 1;
    }
}

static size_t append_hex(char *out, size_t capacity, size_t *used, const uint8_t *bytes,
                         size_t length)
{
    size_t shown = length;
    if (shown > 24)
        shown = 24;
    for (size_t i = 0; i < shown && *used + 2 < capacity; ++i) {
        int count = snprintf(out + *used, capacity - *used, "%02X", bytes[i]);
        if (count != 2)
            break;
        *used += 2;
    }
    return shown;
}

static bool append_capture(char *out, size_t capacity, size_t *used,
                           const nm_ble_advertisement *advertisement, const char *payload_type,
                           byte_span payload)
{
    if (!out || !used || *used >= capacity || !advertisement || (payload.length && !payload.bytes))
        return false;
    int count = snprintf(out + *used, capacity - *used,
                         "\n--- Capture ---\nAddress: %s\nRSSI: %d dBm\nPayload (%s): ",
                         advertisement->address, advertisement->rssi, payload_type);
    if (count < 0 || (size_t)count >= capacity - *used)
        return false;
    *used += (size_t)count;
    for (size_t i = 0; i < payload.length; ++i) {
        count = snprintf(out + *used, capacity - *used, "%02X", payload.bytes[i]);
        if (count != 2 || (size_t)count >= capacity - *used)
            return false;
        *used += 2;
    }
    if (*used + 1 >= capacity)
        return false;
    out[(*used)++] = '\n';
    out[*used] = '\0';
    return true;
}

/* Listen is a raw view of the previous cycle; it reserves no retention. */
static nm_esp_result listen_snapshot(const nm_monitor_record *monitor,
                                     const nm_ble_snapshot *snapshot)
{
    const char *args = monitor->Args;
    while (args && isspace((unsigned char)*args))
        ++args;
    if (!args || !*args)
        args = monitor->Username;
    nm_esp_result invalid = {0};
    snprintf(invalid.status, sizeof(invalid.status), "BLE Error");
    if (!supported_options(args, true))
        return invalid;
    char raw[515] = "", mode[32] = "raw", company[32] = "", service[48] = "";
    if (option_value(args, "--raw_payload", raw, sizeof(raw)) < 0 ||
        option_value(args, "--payload", mode, sizeof(mode)) < 0 ||
        option_value(args, "--manufacturer_id", company, sizeof(company)) < 0 ||
        option_value(args, "--service_uuid", service, sizeof(service)) < 0)
        return invalid;
    for (char *p = mode; *p; ++p)
        *p = (char)tolower((unsigned char)*p);
    bool injected = *raw != 0;
    if (!injected && (!nm_ble_buffer_available() || nm_ble_snapshot_incomplete(snapshot)))
        return nm_endpoint_local_failure(0,
                                         "BLE scanner unavailable or captured history incomplete");
    uint8_t uuid[16] = {0};
    size_t uuid_length = 0;
    if (!parse_service_uuid(service, uuid, &uuid_length))
        return invalid;
    int selected_company = -1;
    if (*company) {
        char *end;
        long value = strtol(company, &end, 0);
        if (*end || value < -1 || value > 65535)
            return invalid;
        selected_company = (int)value;
        if (!strcmp(mode, "raw"))
            strcpy(mode, "manufacturer");
    }
    if (*service && !strcmp(mode, "raw"))
        strcpy(mode, "service");
    if (strcmp(mode, "raw") && strcmp(mode, "manufacturer") && strcmp(mode, "service"))
        return invalid;
    size_t count = injected ? 1 : nm_ble_snapshot_count(snapshot);
    if (count > (SIZE_MAX - 256) / 700)
        return nm_endpoint_local_failure(0, "BLE listen output size overflow");
    nm_esp_result result = {0};
    size_t used = 0, captured = 0;
#ifdef ESP_PLATFORM
    uint64_t first_id = 0, last_id = 0, first_sequence = 0, last_sequence = 0;
    int64_t first_us = 0, last_us = 0;
    size_t duplicate_ids = 0;
#endif
    size_t eligible = injected ? 1 : 0;
    if (!injected) {
        for (size_t i = 0; i < count; ++i) {
            nm_ble_advertisement item;
            uint64_t sequence;
            nm_ble_snapshot_read(snapshot, i, &item, NULL, &sequence);
            if (sequence > nm_ble_snapshot_previous(snapshot))
                ++eligible;
        }
    }
    size_t capacity = 256 + eligible * 700;
    result.detail_message = nm_bulk_calloc(capacity, 1);
    if (!result.detail_message)
        return nm_endpoint_local_failure(0, "BLE listen output allocation failed");
    for (size_t i = 0; i < count; ++i) {
        nm_ble_advertisement item = {0};
        uint64_t sequence = 0;
        int64_t received_us = 0;
        if (injected) {
            if (!parse_hex_payload(raw, item.data, &item.data_length)) {
                nm_esp_result_release(&result);
                return invalid;
            }
            strcpy(item.address, "raw_input");
        } else {
            nm_ble_snapshot_read(snapshot, i, &item, &received_us, &sequence);
            if (sequence <= nm_ble_snapshot_previous(snapshot))
                continue;
        }
        const char *type = injected ? "raw_input" : "raw";
        byte_span payload = injected ? (byte_span){item.data, item.data_length}
                                     : advertisement_payload(&item, &type, selected_company, mode,
                                                             uuid, uuid_length);
        if (!payload.length)
            continue;
        if (!append_capture(result.detail_message, capacity, &used, &item, type, payload)) {
            nm_esp_result_release(&result);
            return nm_endpoint_local_failure(0, "BLE listen output formatting failed");
        }
#ifdef ESP_PLATFORM
        if (!injected) {
            if (!captured) {
                first_id = item.capture_id;
                first_sequence = sequence;
                first_us = received_us;
            } else if (item.capture_id <= last_id)
                ++duplicate_ids;
            last_id = item.capture_id;
            last_sequence = sequence;
            last_us = received_us;
            if (captured < 3)
                ESP_LOGD("nm_ble_raw",
                         "sample monitor=%ld address=%s capture_id=%llu "
                         "sequence=%llu arrival_us=%lld fingerprint=%08lx",
                         (long)monitor->MonitorIPID, item.address,
                         (unsigned long long)item.capture_id, (unsigned long long)sequence,
                         (long long)received_us,
                         (unsigned long)diagnostic_fingerprint(item.data, item.data_length));
        }
#endif
        ++captured;
    }
#ifdef ESP_PLATFORM
    ESP_LOGD("nm_ble_raw",
             "monitor=%ld snapshot_us=%lld previous_sequence=%llu "
             "emitted=%u first_capture_id=%llu last_capture_id=%llu first_sequence=%llu "
             "last_sequence=%llu first_us=%lld last_us=%lld duplicate_capture_ids=%u",
             (long)monitor->MonitorIPID, (long long)nm_ble_snapshot_time(snapshot),
             (unsigned long long)nm_ble_snapshot_previous(snapshot), (unsigned)captured,
             (unsigned long long)first_id, (unsigned long long)last_id,
             (unsigned long long)first_sequence, (unsigned long long)last_sequence,
             (long long)first_us, (long long)last_us, (unsigned)duplicate_ids);
#endif
    append_text(result.detail_message, capacity, &used,
                "\nCaptured %zu advertisement(s). End reason: %s.", captured,
                injected ? "raw payload provided" : "processor cycle complete");
    snprintf(result.message, sizeof(result.message), "BLE listen captured %zu advertisement(s)",
             captured);
    snprintf(result.status, sizeof(result.status), "BLE listen complete");
    result.ok = true;
    return result;
}

static nm_esp_result check_snapshot(const nm_monitor_record *monitor, uint64_t timeout,
                                    const nm_ble_snapshot *snapshot)
{
    int64_t start = esp_timer_get_time();
    if (monitor && monitor->EndPointType && !strcmp(monitor->EndPointType, "blebroadcastlisten"))
        return listen_snapshot(monitor, snapshot);
    nm_ble_filter filter = {.company = -1};
    /* Targeted connects require an advertiser MAC. Raw listen returned above. */
    if (!monitor || !normalize_address(monitor->Address, filter.address)) {
        nm_esp_result invalid = {.elapsed_ms = 0};
        snprintf(invalid.status, sizeof(invalid.status), "Exception");
        snprintf(invalid.message, sizeof(invalid.message),
                 "BLE Error: Invalid or missing BLE address");
        return invalid;
    }
    char format[32] = "aesgcm", metric[64] = "pv_power";
    char company_text[32] = "";
    char mode[32] = "manufacturer", nonce_text[16] = "", tag_text[16] = "";
    char nonce_at[16] = "start", service_uuid[48] = "", raw_payload[515] = "";
    const char *arguments = monitor->Args;
    while (arguments && isspace((unsigned char)*arguments))
        ++arguments;
    if (!arguments || !*arguments)
        arguments = monitor->Username;
    nm_esp_result invalid = {.elapsed_ms = 0};
    snprintf(invalid.status, sizeof(invalid.status), "BLE Error");
    if (!supported_options(arguments, false)) {
        snprintf(invalid.message, sizeof(invalid.message), "Unknown or malformed BLE option");
        return invalid;
    }
    struct {
        const char *name;
        char *out;
        size_t capacity;
        int found;
    } options[] = {{"--format", format, sizeof(format), 0},
                   {"--metric", metric, sizeof(metric), 0},
                   {"--manufacturer_id", company_text, sizeof(company_text), 0},
                   {"--payload", mode, sizeof(mode), 0},
                   {"--nonce_len", nonce_text, sizeof(nonce_text), 0},
                   {"--tag_len", tag_text, sizeof(tag_text), 0},
                   {"--nonce_at", nonce_at, sizeof(nonce_at), 0},
                   {"--service_uuid", service_uuid, sizeof(service_uuid), 0},
                   {"--raw_payload", raw_payload, sizeof(raw_payload), 0}};
    for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
        options[i].found =
            option_value(arguments, options[i].name, options[i].out, options[i].capacity);
        if (options[i].found < 0) {
            snprintf(invalid.message, sizeof(invalid.message), "Invalid or oversized BLE option %s",
                     options[i].name);
            return invalid;
        }
    }
    char address_option[32] = "", key_option[128] = "";
    int has_address = option_value(arguments, "--address", address_option, sizeof(address_option));
    int has_key = option_value(arguments, "--key", key_option, sizeof(key_option));
    if (has_address < 0 || has_key < 0 ||
        (has_address && !normalize_address(address_option, filter.address))) {
        snprintf(invalid.message, sizeof(invalid.message), "Invalid BLE address/key option");
        return invalid;
    }
    char manual[64];
    if (option_value(arguments, "--metric_scale", manual, sizeof(manual)) ||
        option_value(arguments, "--metric_offset", manual, sizeof(manual))) {
        snprintf(invalid.status, sizeof(invalid.status), "BLE Metric Error");
        snprintf(invalid.message, sizeof(invalid.message),
                 "ESP32 metrics use automatic scale and offset; remove manual overrides");
        return invalid;
    }
    for (char *p = format; *p; ++p)
        *p = (char)tolower((unsigned char)*p);
    normalize_metric(metric);
    for (char *p = mode; *p; ++p)
        *p = (char)tolower((unsigned char)*p);
    for (char *p = nonce_at; *p; ++p)
        *p = (char)tolower((unsigned char)*p);
    const nm_ble_decoder *decoder = nm_ble_decoder_find(format);
    if (options[1].found && !decoder) {
        snprintf(invalid.status, sizeof(invalid.status), "BLE Metric Error");
        snprintf(invalid.message, sizeof(invalid.message),
                 "Selected format has no numeric decoder");
        return invalid;
    }
    if (decoder) {
        if (!options[3].found)
            snprintf(mode, sizeof(mode), "%s", decoder->service_uuid ? "service" : "manufacturer");
        if (decoder->service_uuid && !options[7].found)
            snprintf(service_uuid, sizeof(service_uuid), "%04x", decoder->service_uuid);
    }
    uint8_t key[BLE_KEY_MAX] = {0};
    size_t key_length = 0;
    if (!parse_key(has_key ? key_option : monitor->Password, key, &key_length)) {
        snprintf(
            invalid.message, sizeof(invalid.message), "%s",
            !strcmp(format, "victron")
                ? "Invalid BLE Password: Victron requires a 16-byte AES-128 key (32 hex digits)"
                : "Invalid BLE Password: expected a 16-, 24-, or 32-byte key");
        return invalid;
    }
    if (strcmp(mode, "manufacturer") && strcmp(mode, "raw") && strcmp(mode, "service")) {
        snprintf(invalid.message, sizeof(invalid.message), "Invalid BLE payload selector");
        return invalid;
    }
    uint8_t uuid[16] = {0};
    size_t uuid_length = 0;
    if (!parse_service_uuid(service_uuid, uuid, &uuid_length)) {
        snprintf(invalid.message, sizeof(invalid.message), "Invalid BLE service_uuid");
        return invalid;
    }
    uint8_t injected_bytes[NM_BLE_ADVERTISEMENT_MAX];
    size_t injected_length = 0;
    bool injected = raw_payload[0] != '\0';
    if (injected && !parse_hex_payload(raw_payload, injected_bytes, &injected_length)) {
        snprintf(invalid.message, sizeof(invalid.message), "Raw payload must be hex (even length)");
        return invalid;
    }
    unsigned nonce_len = 12, tag_len = 16;
    if (nonce_text[0]) {
        char *end = NULL;
        unsigned long parsed = strtoul(nonce_text, &end, 10);
        if (!end || *end || parsed < 1 || parsed > 16) {
            snprintf(invalid.message, sizeof(invalid.message), "Invalid BLE nonce_len");
            return invalid;
        }
        nonce_len = (unsigned)parsed;
    }
    if (tag_text[0]) {
        char *end = NULL;
        unsigned long parsed = strtoul(tag_text, &end, 10);
        if (!end || *end || parsed < 12 || parsed > 16) {
            snprintf(invalid.message, sizeof(invalid.message), "Invalid BLE tag_len");
            return invalid;
        }
        tag_len = (unsigned)parsed;
    }
    if (strcmp(nonce_at, "start") && strcmp(nonce_at, "end")) {
        snprintf(invalid.message, sizeof(invalid.message), "nonce_at must be start or end");
        return invalid;
    }
    int selected_company = -1;
    if (company_text[0]) {
        char *end = NULL;
        long parsed = strtol(company_text, &end, 0);
        if (!end || *end || parsed < -1 || parsed > 65535) {
            snprintf(invalid.message, sizeof(invalid.message), "Invalid manufacturer_id");
            return invalid;
        }
        selected_company = (int)parsed;
    }
    const char *key_error = nm_ble_decoder_key_error(decoder, key_length);
    if (key_error) {
        snprintf(invalid.message, sizeof(invalid.message), "%s", key_error);
        return invalid;
    }
    if (decoder) {
        if (decoder->manufacturer_id >= 0 && selected_company >= 0 &&
            selected_company != decoder->manufacturer_id) {
            snprintf(invalid.message, sizeof(invalid.message), "%s requires manufacturer_id 0x%04x",
                     format, decoder->manufacturer_id);
            return invalid;
        }
        selected_company = decoder->manufacturer_id;
        filter.decoder = decoder;
        filter.has_key = key_length != 0;
        filter.key_check = key[0];
        filter.company = selected_company;
        if (decoder->requires_key && !key_length) {
            snprintf(invalid.message, sizeof(invalid.message),
                     "%s AES-128 key is missing: set monitor Password to the 16-byte key (32 "
                     "hex digits)",
                     decoder->format);
            return invalid;
        }
    } else if (strcmp(format, "raw") && strcmp(format, "aesgcm") && strcmp(format, "aesctr")) {
        snprintf(invalid.message, sizeof(invalid.message), "Unsupported BLE payload format");
        return invalid;
    }
    if (!decoder && !key_length)
        snprintf(format, sizeof(format), "raw");
    if (!injected && (!nm_ble_buffer_available() || nm_ble_snapshot_incomplete(snapshot)))
        return nm_endpoint_local_failure(0,
                                         "BLE scanner unavailable or captured history incomplete");
    nm_esp_result result = {0};
    nm_ble_advertisement advertisement = {0}, last_advertisement = {0};
    double mean = 0;
    size_t samples = 0, decoded_count = 0, captured = 0;
#ifdef ESP_PLATFORM
    size_t outside_window = 0, filter_rejected = 0, payload_missing = 0;
    size_t attempted = 0, payload_runs = 0;
    uint8_t previous_payload[NM_BLE_ADVERTISEMENT_MAX];
    size_t previous_length = 0;
    uint64_t first_decoded_id = 0, last_decoded_id = 0;
#endif
    char *latest = NULL, *scratch = NULL;
    if (decoder) {
        latest = nm_bulk_calloc(8192, 1);
        scratch = nm_bulk_calloc(8192, 1);
        if (!latest || !scratch) {
            free(latest);
            free(scratch);
            return nm_endpoint_local_failure(0, "BLE decoded output allocation failed");
        }
    }
    size_t count = injected ? 1 : nm_ble_snapshot_count(snapshot);
    for (size_t i = 0; i < count; ++i) {
        if (injected) {
            memset(&advertisement, 0, sizeof(advertisement));
            memcpy(advertisement.data, injected_bytes, injected_length);
            advertisement.data_length = injected_length;
            snprintf(advertisement.address, sizeof(advertisement.address), "%s", filter.address);
        } else {
            int64_t received;
            nm_ble_snapshot_read(snapshot, i, &advertisement, &received, NULL);
            int64_t end = nm_ble_snapshot_time(snapshot);
            if (received > end || (uint64_t)(end - received) > timeout * 1000) {
#ifdef ESP_PLATFORM
                ++outside_window;
#endif
                continue;
            }
            if (!nm_ble_advertisement_matches(&advertisement, &filter)) {
#ifdef ESP_PLATFORM
                ++filter_rejected;
#endif
                continue;
            }
        }
        const char *payload_type = injected ? "raw_input" : "raw";
        byte_span payload = injected
                                ? (byte_span){advertisement.data, advertisement.data_length}
                                : advertisement_payload(&advertisement, &payload_type,
                                                        selected_company, mode, uuid, uuid_length);
        if (!payload.length) {
#ifdef ESP_PLATFORM
            ++payload_missing;
#endif
            continue;
        }
        if (!decoder) {
            last_advertisement = advertisement;
            ++captured;
            continue;
        }
#ifdef ESP_PLATFORM
        ++attempted;
        if (previous_length != payload.length ||
            memcmp(previous_payload, payload.bytes, payload.length))
            ++payload_runs;
        memcpy(previous_payload, payload.bytes, payload.length);
        previous_length = payload.length;
#endif
        nm_ble_metric_selection selection = {.requested = nm_ble_metric_canonical(metric)};
        bool ok =
            nm_ble_decoder_decode_metric(decoder, payload, payload_type, advertisement.address, key,
                                         key_length, scratch, 8192, &selection);
        if (!ok) {
            if (injected)
                snprintf(invalid.message, sizeof(invalid.message), "%.255s", scratch);
            continue;
        }
#ifdef ESP_PLATFORM
        if (!decoded_count)
            first_decoded_id = advertisement.capture_id;
        last_decoded_id = advertisement.capture_id;
#endif
        ++decoded_count;
        char *swap = latest;
        latest = scratch;
        scratch = swap;
        if (selection.matches == 1 && selection.available && isfinite(selection.value)) {
            ++samples;
            mean += (selection.value - mean) / (double)samples;
        }
    }
#ifdef ESP_PLATFORM
    if (decoder) {
        ESP_LOGD("nm_ble_decode",
                 "monitor=%ld address=%s format=%s metric=%s window_ms=%llu "
                 "snapshot=%u outside_window=%u filter_rejected=%u payload_missing=%u "
                 "attempted=%u payload_runs=%u repeated=%u decoded=%u decode_failed=%u "
                 "samples=%u metric_unavailable=%u mean=%.6f",
                 (long)monitor->MonitorIPID, filter.address, format, metric,
                 (unsigned long long)timeout, (unsigned)count, (unsigned)outside_window,
                 (unsigned)filter_rejected, (unsigned)payload_missing, (unsigned)attempted,
                 (unsigned)payload_runs, (unsigned)(attempted - payload_runs),
                 (unsigned)decoded_count, (unsigned)(attempted - decoded_count), (unsigned)samples,
                 (unsigned)(decoded_count - samples), mean);
        ESP_LOGD("nm_ble_decode",
                 "monitor=%ld metric=%s snapshot_us=%lld "
                 "first_decoded_capture_id=%llu last_decoded_capture_id=%llu",
                 (long)monitor->MonitorIPID, metric, (long long)nm_ble_snapshot_time(snapshot),
                 (unsigned long long)first_decoded_id, (unsigned long long)last_decoded_id);
    }
#endif
    free(scratch);
    result.elapsed_ms = nm_endpoint_elapsed(start);
    if (decoder) {
        if (!decoded_count) {
            free(latest);
            if (!*invalid.message)
                snprintf(invalid.message, sizeof(invalid.message),
                         "No decodable BLE advertisements in the measurement window");
            return invalid;
        }
        result.detail_message = latest;
        snprintf(result.message, sizeof(result.message), "%.255s", latest);
        if (decoder->requires_key) {
            size_t used = 0;
            result.message[0] = 0;
            const char *line = latest;
            while (*line) {
                const char *end = strchr(line, '\n');
                size_t length = end ? (size_t)(end - line) : strlen(line);
                append_text(result.message, sizeof(result.message), &used, "%s%.*s",
                            used ? "; " : "", (int)length, line);
                if (!end)
                    break;
                line = end + 1;
            }
        }
        if (!samples) {
            snprintf(result.status, sizeof(result.status), "BLE Metric Error");
            snprintf(result.message, sizeof(result.message),
                     "BLE metric %s has no usable readings in the window", metric);
            return result;
        }
        uint16_t sample;
        if (options[1].found) {
            const nm_ble_metric_encoding *encoding = nm_ble_metric_find(decoder->format, metric);
            if (!nm_ble_metric_encode(encoding, mean, &sample)) {
                snprintf(result.status, sizeof(result.status), "BLE Metric Error");
                snprintf(result.message, sizeof(result.message),
                         "BLE metric %s average is outside its published range", metric);
                return result;
            }
            result.measurement_scale = encoding->scale;
            result.measurement_offset = encoding->offset;
            result.measurement_unit = encoding->unit;
            snprintf(result.status, sizeof(result.status), "BLE v2:%s:%s", decoder->format,
                     nm_ble_metric_canonical(metric));
        } else {
            double encoded = round(mean);
            if (!isfinite(encoded) || encoded < 0 || encoded > 65534) {
                snprintf(result.status, sizeof(result.status), "BLE Metric Error");
                return result;
            }
            sample = (uint16_t)encoded;
            result.measurement_scale = 1;
            result.measurement_unit = "raw value";
            snprintf(result.status, sizeof(result.status), "BLE pv_power");
        }
        result.ok = result.has_sample = true;
        result.sample = sample;
        return result;
    }
    if (!captured) {
        snprintf(result.status, sizeof(result.status), "BLE Error");
        snprintf(result.message, sizeof(result.message),
                 "No usable BLE advertisements in the completed window");
        return result;
    }
    advertisement = last_advertisement;
    result.ok = true;
    snprintf(result.status, sizeof(result.status), "BLE broadcast received");
    const char *payload_type = injected ? "raw_input" : "raw";
    byte_span payload =
        injected ? (byte_span){.bytes = advertisement.data, .length = advertisement.data_length}
                 : advertisement_payload(&advertisement, &payload_type, selected_company, mode,
                                         uuid, uuid_length);
    uint8_t plaintext_bytes[NM_BLE_ADVERTISEMENT_MAX];
    byte_span plaintext = {0};
    bool decrypted = decrypt_payload(format, payload, key, key_length, nonce_len, tag_len,
                                     !strcmp(nonce_at, "end"), plaintext_bytes, &plaintext);
    if (!decrypted)
        plaintext = payload;
    size_t used = 0;
    append_text(result.message, sizeof(result.message), &used,
                "BLE broadcast received; address=%s rssi=%d payload(%s)=", advertisement.address,
                advertisement.rssi, payload_type);
    if (!decrypted)
        append_text(result.message, sizeof(result.message), &used, "decryption failed; raw=");
    size_t shown = append_hex(result.message, sizeof(result.message), &used, plaintext.bytes,
                              plaintext.length);
    if (shown < plaintext.length)
        append_text(result.message, sizeof(result.message), &used, "...");
    return result;
}

/* ESP32 drains probe jobs before cycle publication. Taking the published view
 * here therefore binds the same cycle even if a job spent time in the queue. */
nm_esp_result nm_endpoint_check_ble(const nm_monitor_record *monitor, uint64_t timeout)
{
    nm_ble_snapshot *snapshot = nm_ble_buffer_acquire();
    nm_esp_result result = check_snapshot(monitor, timeout, snapshot);
    nm_ble_snapshot_release(snapshot);
    return result;
}
