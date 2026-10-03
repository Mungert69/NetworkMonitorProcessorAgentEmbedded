#include "endpoint_internal.h"
#include "ble_scanner.h"
#include "ble_filter.h"
#include "nm_memory.h"
#include "esp_timer.h"
#include "mbedtls/base64.h"
#include "psa/crypto.h"
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { BLE_KEY_MAX = 32 };

static bool aes_ecb_encrypt_block(const uint8_t *key, size_t key_length,
                                  const uint8_t input[16], uint8_t output[16])
{
    if (!key || (key_length != 16 && key_length != 24 && key_length != 32))
        return false;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, key_length * 8);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECB_NO_PADDING);
    mbedtls_svc_key_id_t handle = PSA_KEY_ID_NULL;
    psa_status_t status = psa_import_key(&attributes, key, key_length, &handle);
    psa_reset_key_attributes(&attributes);
    size_t output_length = 0;
    if (status == PSA_SUCCESS)
        status = psa_cipher_encrypt(handle, PSA_ALG_ECB_NO_PADDING, input, 16,
                                    output, 16, &output_length);
    if (handle != PSA_KEY_ID_NULL)
        psa_destroy_key(handle);
    return status == PSA_SUCCESS && output_length == 16;
}

typedef struct {
    const uint8_t *bytes;
    size_t length;
} byte_span;

typedef struct {
    uint8_t record_type;
    uint16_t nonce;
    uint8_t key_check;
    byte_span cipher;
} victron_record;

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
    if (separator != ':' && separator != '-') return false;
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
    while (*p && isspace((unsigned char)*p))
        ++p;
    if (!*p) {
        *cursor = p;
        return false;
    }
    char quote = 0;
    if (*p == '\'' || *p == '"')
        quote = *p++;
    size_t used = 0;
    while (*p && (quote ? *p != quote : !isspace((unsigned char)*p))) {
        if (used + 1 < capacity)
            token[used++] = *p;
        ++p;
    }
    if (quote && *p == quote)
        ++p;
    token[used] = '\0';
    *cursor = p;
    return used > 0;
}

static bool option_value(const char *arguments, const char *name, char *out, size_t capacity)
{
    if (!out || !capacity) return false;
    if (!arguments || !name)
        return false;
    char token[600], next[600];
    size_t name_length = strlen(name);
    const char *cursor = arguments;
    while (next_argument(&cursor, token, sizeof(token))) {
        if (strncmp(token, name, name_length) != 0)
            continue;
        const char *value = NULL;
        if (token[name_length] == '=')
            value = token + name_length + 1;
        else if (token[name_length] == '\0' && next_argument(&cursor, next, sizeof(next)))
            value = next;
        if (!value || !*value || strlen(value) >= capacity)
            return false;
        memcpy(out, value, strlen(value) + 1);
        return true;
    }
    return false;
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
        int hi = isdigit((unsigned char)text[i]) ? text[i] - '0' :
                 isxdigit((unsigned char)text[i]) ? toupper((unsigned char)text[i]) - 'A' + 10 : -1;
        int lo = isdigit((unsigned char)text[i + 1]) ? text[i + 1] - '0' :
                 isxdigit((unsigned char)text[i + 1]) ? toupper((unsigned char)text[i + 1]) - 'A' + 10 : -1;
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
    if (!length || length >= sizeof(trimmed))
        return false;
    memcpy(trimmed, text + start, length);
    trimmed[length] = '\0';

    bool all_hex = length >= 2 && trimmed[0] == '0' &&
                   (trimmed[1] == 'x' || trimmed[1] == 'X');
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
    return *key_length == 0 || *key_length == 16 || *key_length == 24 || *key_length == 32;
}

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool parse_hex_payload(const char *text, uint8_t out[NM_BLE_ADVERTISEMENT_MAX],
                              size_t *length)
{
    if (!text || !length) return false;
    if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) text += 2;
    size_t size = strlen(text);
    if (!size || (size & 1U) || size > NM_BLE_ADVERTISEMENT_MAX * 2U) return false;
    for (size_t i = 0; i < size; i += 2) {
        int hi = hex_digit(text[i]), lo = hex_digit(text[i + 1]);
        if (hi < 0 || lo < 0) return false;
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
    if (!text || !*text) return true;
    if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) text += 2;
    size_t n = strlen(text);
    if (n == 4 || n == 8) {
        *length = n / 2;
        for (size_t i = 0; i < *length; ++i) {
            size_t offset = n - 2 - i * 2;
            int hi = hex_digit(text[offset]), lo = hex_digit(text[offset + 1]);
            if (hi < 0 || lo < 0) return false;
            out[i] = (uint8_t)((hi << 4) | lo);
        }
        return true;
    }
    if (n != 36 || text[8] != '-' || text[13] != '-' ||
        text[18] != '-' || text[23] != '-') return false;
    size_t used = 0;
    for (size_t i = 0; i < n; ++i) {
        if (text[i] == '-') continue;
        if (i + 1 >= n || text[i + 1] == '-') return false;
        int hi = hex_digit(text[i]), lo = hex_digit(text[++i]);
        if (hi < 0 || lo < 0 || used >= 16) return false;
        out[used++] = (uint8_t)((hi << 4) | lo);
    }
    *length = used;
    return used == 16;
}

static bool service_uuid_equal(const uint8_t *value, const uint8_t *uuid, size_t length)
{
    if (length <= 4) return !memcmp(value, uuid, length);
    uint8_t windows[16];
    for (size_t i = 0; i < 16; ++i) windows[i] = uuid[i];
    windows[0] = uuid[3]; windows[1] = uuid[2]; windows[2] = uuid[1]; windows[3] = uuid[0];
    windows[4] = uuid[5]; windows[5] = uuid[4];
    windows[6] = uuid[7]; windows[7] = uuid[6];
    if (!memcmp(value, windows, 16)) return true;
    for (size_t i = 0; i < 16; ++i) if (value[i] != uuid[15 - i]) return false;
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
            if (!field || field > advertisement->data_length - offset - 1) break;
            uint8_t type = advertisement->data[offset + 1];
            size_t uuid_size = type == 0x16 ? 2 : type == 0x20 ? 4 : type == 0x21 ? 16 : 0;
            if (uuid_size && field > uuid_size + 1 &&
                (!service_uuid_length ||
                 (service_uuid_length == uuid_size &&
                  service_uuid_equal(advertisement->data + offset + 2,
                                     service_uuid, uuid_size)))) {
                *payload_type = "service";
                return (byte_span){.bytes = advertisement->data + offset + 2 + uuid_size,
                                   .length = field - 1 - uuid_size};
            }
            offset += field + 1;
        }
    } else {
        const uint8_t *value = NULL;
        size_t length = 0;
        if (nm_ble_ad_field(advertisement->data, advertisement->data_length, 0xff,
                            company, &value, &length)) {
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
    if (!payload.bytes || !payload.length) return false;
    if (!strcmp(format, "raw")) {
        *plaintext = payload;
        return true;
    }
    if (!key_length || nonce_len == 0 || nonce_len > 16 ||
        payload.length <= nonce_len) return false;
    const uint8_t *nonce = nonce_at_end ? payload.bytes + payload.length - nonce_len : payload.bytes;
    const uint8_t *cipher = nonce_at_end ? payload.bytes : payload.bytes + nonce_len;
    size_t cipher_len = payload.length - nonce_len;
    if (!strcmp(format, "aesgcm")) {
        if (tag_len < 12 || tag_len > 16 || cipher_len <= tag_len) return false;
        const uint8_t *tag = nonce_at_end ? cipher + cipher_len - tag_len :
                                               payload.bytes + payload.length - tag_len;
        cipher_len -= tag_len;
        if (cipher_len + tag_len > NM_BLE_ADVERTISEMENT_MAX ||
            (key_length != 16 && key_length != 24 && key_length != 32)) return false;
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
        if (status != PSA_SUCCESS || output_length != cipher_len) return false;
    } else if (!strcmp(format, "aesctr")) {
        uint8_t counter[16] = {0}, stream[16];
        memcpy(counter, nonce, nonce_len);
        for (size_t offset = 0; offset < cipher_len; offset += 16) {
            if (!aes_ecb_encrypt_block(key, key_length, counter, stream)) return false;
            size_t block = cipher_len - offset < 16 ? cipher_len - offset : 16;
            for (size_t i = 0; i < block; ++i) output[offset + i] = cipher[offset + i] ^ stream[i];
            for (int i = 15; i >= 12; --i) if (++counter[i]) break;
        }
    } else return false;
    *plaintext = (byte_span){.bytes = output, .length = cipher_len};
    return true;
}

static bool extract_victron_record(byte_span payload, const char *payload_type,
                                   victron_record *record)
{
    if (!payload.bytes || payload.length < 4)
        return false;
    if (strcmp(payload_type, "raw") == 0) {
        const uint8_t *selected = NULL;
        size_t selected_length = 0;
        if (!nm_ble_ad_field(payload.bytes, payload.length, 0xff, 0x02e1,
                             &selected, &selected_length)) return false;
        payload.bytes = selected;
        payload.length = selected_length;
    }
    if (payload.length >= 2 && payload.bytes[0] == 0xE1 && payload.bytes[1] == 0x02) {
        payload.bytes += 2;
        payload.length -= 2;
    }
    if (payload.length < 4)
        return false;
    size_t offset = payload.bytes[0] == 0x10 ? 4 : 0;
    if (payload.length < offset + 5)
        return false;
    record->record_type = payload.bytes[offset];
    record->nonce = (uint16_t)payload.bytes[offset + 1] |
                    (uint16_t)((uint16_t)payload.bytes[offset + 2] << 8);
    record->key_check = payload.bytes[offset + 3];
    record->cipher.bytes = payload.bytes + offset + 4;
    record->cipher.length = payload.length - offset - 4;
    return record->cipher.length >= 1 && record->cipher.length <= 16;
}

static bool decrypt_victron(const uint8_t *key, size_t key_length, uint16_t nonce,
                            byte_span cipher, uint8_t plaintext[16])
{
    if (key_length != 16 || !cipher.bytes || !cipher.length || cipher.length > 16)
        return false;
    uint8_t counter[16] = {0}, stream[16] = {0};
    counter[0] = (uint8_t)nonce;
    counter[1] = (uint8_t)(nonce >> 8);
    if (!aes_ecb_encrypt_block(key, key_length, counter, stream))
        return false;
    for (size_t i = 0; i < cipher.length; ++i)
        plaintext[i] = cipher.bytes[i] ^ stream[i];
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

static size_t append_hex(char *out, size_t capacity, size_t *used,
                         const uint8_t *bytes, size_t length)
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
                           const nm_ble_advertisement *advertisement,
                           const char *payload_type, byte_span payload)
{
    if (!out || !used || *used >= capacity || !advertisement ||
        (payload.length && !payload.bytes)) return false;
    int count = snprintf(out + *used, capacity - *used,
                         "\n--- Capture ---\nAddress: %s\nRSSI: %d dBm\nPayload (%s): ",
                         advertisement->address, advertisement->rssi, payload_type);
    if (count < 0 || (size_t)count >= capacity - *used) return false;
    *used += (size_t)count;
    for (size_t i = 0; i < payload.length; ++i) {
        count = snprintf(out + *used, capacity - *used, "%02X", payload.bytes[i]);
        if (count != 2 || (size_t)count >= capacity - *used) return false;
        *used += 2;
    }
    if (*used + 1 >= capacity) return false;
    out[(*used)++] = '\n';
    out[*used] = '\0';
    return true;
}

static bool apply_victron(nm_esp_result *result, byte_span payload, const char *payload_type,
                          const uint8_t *key, size_t key_length, const char *metric)
{
    victron_record record;
    if (!extract_victron_record(payload, payload_type, &record))
        return false;
    if (key_length != 16 || record.key_check != key[0])
        return false;
    uint8_t plain[16] = {0};
    if (!decrypt_victron(key, key_length, record.nonce, record.cipher, plain))
        return false;
    if (record.record_type != 0x01 || record.cipher.length < 10)
        return false;

    uint16_t pv_power = (uint16_t)plain[8] | (uint16_t)((uint16_t)plain[9] << 8);
    int16_t battery_voltage_raw = (int16_t)((uint16_t)plain[2] |
                                  (uint16_t)((uint16_t)plain[3] << 8));
    int16_t battery_current_raw = (int16_t)((uint16_t)plain[4] |
                                  (uint16_t)((uint16_t)plain[5] << 8));
    uint16_t yield_raw = (uint16_t)plain[6] | (uint16_t)((uint16_t)plain[7] << 8);
    unsigned sample = pv_power;
    const char *label = NULL;
    if (!strcmp(metric, "pv_power") || !strcmp(metric, "pvpower") || !strcmp(metric, "pv")) {
        label = "pv_power";
    } else if (!strcmp(metric, "battery_voltage") || !strcmp(metric, "battery_voltage_v") ||
               !strcmp(metric, "battery_v")) {
        sample = battery_voltage_raw < 0 ? 0U : (unsigned)battery_voltage_raw;
        label = "battery_voltage";
    } else if (!strcmp(metric, "battery_current") || !strcmp(metric, "battery_current_a") ||
               !strcmp(metric, "battery_a")) {
        sample = battery_current_raw < 0 ? 0U : (unsigned)battery_current_raw;
        label = "battery_current";
    } else if (!strcmp(metric, "yield_today") || !strcmp(metric, "yield") ||
               !strcmp(metric, "yield_today_kwh")) {
        sample = yield_raw;
        label = "yield_today";
    } else if (!strcmp(metric, "load_current") || !strcmp(metric, "load_current_a") ||
               !strcmp(metric, "load_a")) {
        if (record.cipher.length >= 12) {
            unsigned load = plain[10] | ((unsigned)(plain[11] & 1U) << 8);
            if (load != 0x1ff) {
                sample = load;
                label = "load_current";
            }
        }
    }
    if (label) {
        result->elapsed_ms = sample;
        /* PingInfo.Status is interned in the backend's ushort status table.
         * Measurements belong in the numeric sample and monitor diagnostics. */
        snprintf(result->status, sizeof(result->status), "BLE %s", label);
    }
    if (!label)
        snprintf(result->status, sizeof(result->status), "BLE broadcast received");
    snprintf(result->message, sizeof(result->message),
             "Battery voltage: %.2f V; Battery current: %.1f A; Yield today: %.2f kWh; PV power: "
             "%u W; Device state: %u; Charger error: %u",
             battery_voltage_raw / 100.0, battery_current_raw / 10.0, yield_raw / 100.0, pv_power,
             plain[0], plain[1]);
    return true;
}

nm_esp_result nm_endpoint_check_ble(const nm_monitor_record *monitor, unsigned timeout)
{
    int64_t start = esp_timer_get_time();
    bool listen = monitor && monitor->EndPointType &&
                  !strcmp(monitor->EndPointType, "blebroadcastlisten");
    nm_ble_filter filter = {.company = -1};
    /* The listen endpoint scans every broadcaster. Its Address is a UI label,
     * not a radio filter; only the targeted endpoint requires a BLE MAC. */
    if (!monitor || (!listen && !normalize_address(monitor->Address, filter.address))) {
        nm_esp_result invalid = {.elapsed_ms = 0};
        snprintf(invalid.status, sizeof(invalid.status), "Exception");
        snprintf(invalid.message, sizeof(invalid.message), "BLE Error: Invalid or missing BLE address");
        return invalid;
    }
    char format[32] = "aesgcm", metric[32] = "pv_power";
    char company_text[32] = "", captures_text[32] = "";
    char mode[32] = "manufacturer", nonce_text[16] = "", tag_text[16] = "";
    char nonce_at[16] = "start", service_uuid[48] = "", raw_payload[515] = "";
    const char *arguments = monitor->Args && *monitor->Args
                                ? monitor->Args
                                : monitor->Username;
    (void)option_value(arguments, "--format", format, sizeof(format));
    (void)option_value(arguments, "--metric", metric, sizeof(metric));
    (void)option_value(arguments, "--manufacturer_id", company_text, sizeof(company_text));
    (void)option_value(arguments, "--max_captures", captures_text, sizeof(captures_text));
    (void)option_value(arguments, "--payload", mode, sizeof(mode));
    (void)option_value(arguments, "--nonce_len", nonce_text, sizeof(nonce_text));
    (void)option_value(arguments, "--tag_len", tag_text, sizeof(tag_text));
    (void)option_value(arguments, "--nonce_at", nonce_at, sizeof(nonce_at));
    (void)option_value(arguments, "--service_uuid", service_uuid, sizeof(service_uuid));
    (void)option_value(arguments, "--raw_payload", raw_payload, sizeof(raw_payload));
    for (char *p = format; *p; ++p)
        *p = (char)tolower((unsigned char)*p);
    for (char *p = metric; *p; ++p)
        *p = (char)tolower((unsigned char)*p);
    for (char *p = mode; *p; ++p) *p = (char)tolower((unsigned char)*p);
    for (char *p = nonce_at; *p; ++p) *p = (char)tolower((unsigned char)*p);
    uint8_t key[BLE_KEY_MAX] = {0};
    size_t key_length = 0;
    nm_esp_result invalid = {.elapsed_ms = 0};
    snprintf(invalid.status, sizeof(invalid.status), "BLE Error");
    if (!parse_key(monitor->Password, key, &key_length)) {
        snprintf(invalid.message, sizeof(invalid.message), "%s",
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
    if ((arguments && strstr(arguments, "--raw_payload") && !injected) ||
        (injected && !parse_hex_payload(raw_payload, injected_bytes, &injected_length))) {
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
    unsigned max_captures = listen ? 10 : 1;
    if (captures_text[0]) {
        char *end = NULL;
        unsigned long parsed = strtoul(captures_text, &end, 10);
        if (!end || *end || parsed < 1 || parsed > 50) {
            snprintf(invalid.message, sizeof(invalid.message), "max_captures must be 1..50");
            return invalid;
        }
        max_captures = (unsigned)parsed;
    }
    if (!strcmp(format, "victron")) {
        if (selected_company >= 0 && selected_company != 0x02e1) {
            snprintf(invalid.message, sizeof(invalid.message),
                     "Victron requires manufacturer_id 0x02e1");
            return invalid;
        }
        if (key_length != 16) {
            snprintf(invalid.message, sizeof(invalid.message),
                     "%s",
                     key_length ? "Victron requires a 16-byte AES-128 key in monitor Password (32 hex digits)"
                                : "Victron AES-128 key is missing: set monitor Password to the 16-byte key (32 hex digits)");
            return invalid;
        }
        filter.victron_instant = true;
        filter.key_check = key[0];
        filter.company = 0x02e1;
        selected_company = 0x02e1;
    } else if (strcmp(format, "raw") && strcmp(format, "aesgcm") && strcmp(format, "aesctr")) {
        snprintf(invalid.message, sizeof(invalid.message), "Unsupported BLE payload format");
        return invalid;
    }
    /* Non-Victron selection follows .NET's raw fallback when a manufacturer
     * field is absent. Only Victron must filter at the scan callback. */
    if (!key_length && strcmp(format, "victron")) snprintf(format, sizeof(format), "raw");
    if (injected) max_captures = 1;

    nm_ble_advertisement advertisement;
    unsigned captured = 0;
    nm_esp_result result = {0};
    size_t detail_capacity = 0, detail_used = 0;
    if (listen) {
        /* At most 50 complete BLE advertisements, each up to 255 data bytes
         * rendered as hex, plus address/RSSI/labels. Allocate the diagnostic
         * in PSRAM and keep the ordinary PingInfo status short. */
        const size_t per_capture = 700;
        if ((size_t)max_captures > (SIZE_MAX - 512) / per_capture)
            return nm_endpoint_local_failure(0, "BLE capture output size overflow");
        detail_capacity = 512 + (size_t)max_captures * per_capture;
        result.detail_message = nm_bulk_calloc(detail_capacity, 1);
        if (!result.detail_message)
            return nm_endpoint_local_failure(0, "BLE capture output allocation failed");
        append_text(result.detail_message, detail_capacity, &detail_used,
                    "BLE advertisement captures:\n");
    }
    while (captured < max_captures) {
        nm_ble_wait_result waited = NM_BLE_WAIT_FOUND;
        if (injected) {
            memset(&advertisement, 0, sizeof(advertisement));
            memcpy(advertisement.data, injected_bytes, injected_length);
            advertisement.data_length = injected_length;
            snprintf(advertisement.address, sizeof(advertisement.address), "%s",
                     filter.address[0] ? filter.address : "unknown");
        } else {
            unsigned remaining = nm_endpoint_remaining(start, timeout);
            if (!remaining) break;
            waited = nm_ble_scanner_wait(&filter, remaining, &advertisement);
        }
        result.elapsed_ms = nm_endpoint_elapsed(start);
        if (waited == NM_BLE_WAIT_UNAVAILABLE) {
            nm_esp_result_release(&result);
            return nm_endpoint_local_failure(result.elapsed_ms, "BLE scanner is not available");
        }
        if (waited == NM_BLE_WAIT_CAPACITY) {
            nm_esp_result_release(&result);
            return nm_endpoint_local_failure(result.elapsed_ms, "BLE waiter capacity is exhausted");
        }
        if (waited == NM_BLE_WAIT_TIMEOUT) break;
        const char *payload_type = injected ? "raw_input" : "raw";
        byte_span payload = injected
            ? (byte_span){.bytes = advertisement.data, .length = advertisement.data_length}
            : advertisement_payload(&advertisement, &payload_type, selected_company, mode,
                                    uuid, uuid_length);
        if (listen && strcmp(format, "victron")) {
            /* Listener mode reports the full advertisement as received. The
             * endpoint's payload selector remains useful for one-shot decode,
             * but must not hide other fields from a general scan. */
            payload = (byte_span){.bytes = advertisement.data,
                                  .length = advertisement.data_length};
            payload_type = injected ? "raw_input" : "raw";
        }
        if (!strcmp(format, "victron") &&
            !apply_victron(&result, payload, payload_type, key, key_length, metric)) {
            if (injected) {
                snprintf(invalid.message, sizeof(invalid.message), "Victron raw payload decode failed");
                nm_esp_result_release(&result);
                return invalid;
            }
            continue;
        }
        if (!strcmp(format, "victron")) {
            ++captured;
            if (listen && !append_capture(result.detail_message, detail_capacity, &detail_used,
                                           &advertisement, "raw", (byte_span){
                                               .bytes = advertisement.data,
                                               .length = advertisement.data_length})) {
                nm_esp_result_release(&result);
                return nm_endpoint_local_failure(result.elapsed_ms, "BLE capture output limit exceeded");
            }
            if (!listen) { result.ok = true; return result; }
            if (injected) break;
            continue;
        }
        ++captured;
        if (listen && !append_capture(result.detail_message, detail_capacity, &detail_used,
                                      &advertisement, payload_type, payload)) {
            nm_esp_result_release(&result);
            return nm_endpoint_local_failure(result.elapsed_ms, "BLE capture output limit exceeded");
        }
        if (!listen) {
            result.ok = true;
            snprintf(result.status, sizeof(result.status), "BLE broadcast received");
            break;
        }
    }
    if (listen) {
        result.ok = true;
        result.elapsed_ms = nm_endpoint_elapsed(start);
        snprintf(result.status, sizeof(result.status), "BLE listen complete");
        append_text(result.detail_message, detail_capacity, &detail_used,
                    "\nCaptured %u advertisement(s). End reason: %s.", captured,
                    injected ? "raw payload provided" :
                    captured == max_captures ? "capture limit reached" : "timeout");
        snprintf(result.message, sizeof(result.message), "BLE listen captured %u advertisement(s)", captured);
        return result;
    }
    if (!captured) {
        snprintf(result.status, sizeof(result.status), "BLE Error");
        snprintf(result.message, sizeof(result.message),
                 "BLE scan canceled or timed out for %s", filter.address);
        return result;
    }
    const char *payload_type = injected ? "raw_input" : "raw";
    byte_span payload = injected
        ? (byte_span){.bytes = advertisement.data, .length = advertisement.data_length}
        : advertisement_payload(&advertisement, &payload_type, selected_company, mode,
                                uuid, uuid_length);
    uint8_t plaintext_bytes[NM_BLE_ADVERTISEMENT_MAX];
    byte_span plaintext = {0};
    bool decrypted = decrypt_payload(format, payload, key, key_length, nonce_len, tag_len,
                                     !strcmp(nonce_at, "end"), plaintext_bytes, &plaintext);
    if (!decrypted) plaintext = payload;
    size_t used = 0;
    append_text(result.message, sizeof(result.message), &used,
                "BLE broadcast received; address=%s rssi=%d payload(%s)=",
                advertisement.address, advertisement.rssi, payload_type);
    if (!decrypted)
        append_text(result.message, sizeof(result.message), &used, "decryption failed; raw=");
    size_t shown = append_hex(result.message, sizeof(result.message), &used,
                              plaintext.bytes, plaintext.length);
    if (shown < plaintext.length)
        append_text(result.message, sizeof(result.message), &used, "...");
    return result;
}
