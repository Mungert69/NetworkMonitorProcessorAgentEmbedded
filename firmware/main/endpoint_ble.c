#include "ble_crypto.h"
#include "ble_metric.h"
#include "endpoint_internal.h"
#include "ble_scanner.h"
#include "ble_filter.h"
#include "nm_memory.h"
#include "esp_timer.h"
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

nm_esp_result nm_endpoint_check_ble(const nm_monitor_record *monitor, unsigned timeout)
{
    int64_t start = esp_timer_get_time();
    bool listen =
        monitor && monitor->EndPointType && !strcmp(monitor->EndPointType, "blebroadcastlisten");
    nm_ble_filter filter = {.company = -1};
    /* The listen endpoint scans every broadcaster. Its Address is a UI label,
     * not a radio filter; only the targeted endpoint requires a BLE MAC. */
    if (!monitor || (!listen && !normalize_address(monitor->Address, filter.address))) {
        nm_esp_result invalid = {.elapsed_ms = 0};
        snprintf(invalid.status, sizeof(invalid.status), "Exception");
        snprintf(invalid.message, sizeof(invalid.message),
                 "BLE Error: Invalid or missing BLE address");
        return invalid;
    }
    char format[32] = "aesgcm", metric[64] = "pv_power";
    char company_text[32] = "", captures_text[32] = "";
    char mode[32] = "manufacturer", nonce_text[16] = "", tag_text[16] = "";
    char nonce_at[16] = "start", service_uuid[48] = "", raw_payload[515] = "";
    const char *arguments = monitor->Args;
    while (arguments && isspace((unsigned char)*arguments))
        ++arguments;
    if (!arguments || !*arguments)
        arguments = monitor->Username;
    nm_esp_result invalid = {.elapsed_ms = 0};
    snprintf(invalid.status, sizeof(invalid.status), "BLE Error");
    if (!supported_options(arguments, listen)) {
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
                   {"--max_captures", captures_text, sizeof(captures_text), 0},
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
    if (options[1].found && !decoder && !listen) {
        snprintf(invalid.status, sizeof(invalid.status), "BLE Metric Error");
        snprintf(invalid.message, sizeof(invalid.message),
                 "Selected format has no numeric decoder");
        return invalid;
    }
    if (decoder) {
        if (!options[4].found)
            snprintf(mode, sizeof(mode), "%s", decoder->service_uuid ? "service" : "manufacturer");
        if (decoder->service_uuid && !options[8].found)
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
        if (!listen && decoder->requires_key && !key_length) {
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
    if (injected)
        max_captures = 1;

    nm_ble_advertisement advertisement;
    unsigned captured = 0;
    nm_esp_result result = {0};
    size_t detail_capacity = 0, detail_used = 0;
    if (listen) {
        /* At most 50 complete BLE advertisements, each up to 255 data bytes
         * rendered as hex, plus address/RSSI/labels. Allocate the diagnostic
         * in PSRAM and keep the ordinary PingInfo status short. */
        const size_t per_capture = decoder ? 9000 : 1500;
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
            if (!remaining)
                break;
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
        if (waited == NM_BLE_WAIT_TIMEOUT)
            break;
        const char *payload_type = injected ? "raw_input" : "raw";
        byte_span payload =
            injected ? (byte_span){.bytes = advertisement.data, .length = advertisement.data_length}
                     : advertisement_payload(&advertisement, &payload_type, selected_company, mode,
                                             uuid, uuid_length);
        if (decoder) {
            char *decoded = nm_bulk_calloc(8192, 1);
            if (!decoded) {
                nm_esp_result_release(&result);
                return nm_endpoint_local_failure(result.elapsed_ms,
                                                 "BLE decoded output allocation failed");
            }
            nm_ble_metric_selection selection = {.requested = nm_ble_metric_canonical(metric)};
            bool ok =
                nm_ble_decoder_decode_metric(decoder, payload, payload_type, advertisement.address,
                                             key, key_length, decoded, 8192, &selection);
            if (!ok && !listen && !injected) {
                free(decoded);
                continue;
            }
            if (!ok && !listen) {
                snprintf(invalid.message, sizeof(invalid.message), "%s", decoded);
                free(decoded);
                nm_esp_result_release(&result);
                return invalid;
            }
            ++captured;
            if (listen) {
                bool appended =
                    append_capture(result.detail_message, detail_capacity, &detail_used,
                                   &advertisement, injected ? "raw_input" : "raw",
                                   (byte_span){advertisement.data, advertisement.data_length});
                nm_ble_output output = {result.detail_message, detail_capacity, detail_used,
                                        !appended, NULL};
                nm_ble_output_append(&output, "%s%s\n", ok ? "" : "Decode error: ", decoded);
                detail_used = output.used;
                free(decoded);
                if (output.failed) {
                    nm_esp_result_release(&result);
                    return nm_endpoint_local_failure(result.elapsed_ms,
                                                     "BLE capture output limit exceeded");
                }
            } else {
                result.detail_message = decoded;
                snprintf(result.message, sizeof(result.message), "%.255s", decoded);
                if (decoder->requires_key) {
                    size_t used = 0;
                    result.message[0] = 0;
                    const char *line = decoded;
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
                if (options[1].found) {
                    const nm_ble_metric_encoding *encoding =
                        nm_ble_metric_find(decoder->format, metric);
                    uint16_t sample = 0;
                    if (selection.matches != 1 || !selection.available ||
                        !nm_ble_metric_encode(encoding, selection.value, &sample)) {
                        result.ok = false;
                        snprintf(result.status, sizeof(result.status), "BLE Metric Error");
                        snprintf(result.message, sizeof(result.message),
                                 "BLE metric %s is missing, unavailable, ambiguous or outside its "
                                 "published range",
                                 metric);
                        return result;
                    }
                    result.measurement_scale = encoding->scale;
                    result.measurement_offset = encoding->offset;
                    result.measurement_unit = encoding->unit;
                    result.sample = sample;
                    result.has_sample = true;
                    snprintf(result.status, sizeof(result.status), "BLE v2:%s:%s", decoder->format,
                             nm_ble_metric_canonical(metric));
                } else if (selection.matches) {
                    /* Legacy implicit pv_power uses scale 1 and offset 0.
                     * Use the typed reading, never parse diagnostics or clamp. */
                    double sample = round(selection.value);
                    if (selection.matches != 1 || !selection.available || !isfinite(sample) ||
                        sample < 0 || sample > 65534) {
                        snprintf(result.status, sizeof(result.status), "BLE Metric Error");
                        snprintf(result.message, sizeof(result.message),
                                 "Implicit BLE pv_power is unavailable or outside 0..65534");
                        return result;
                    }
                    result.measurement_scale = 1;
                    result.measurement_unit = "raw value";
                    result.sample = (uint16_t)sample;
                    result.has_sample = true;
                    snprintf(result.status, sizeof(result.status), "BLE pv_power");
                } else
                    snprintf(result.status, sizeof(result.status), "BLE broadcast received");
                result.ok = true;
                return result;
            }
            if (injected)
                break;
            continue;
        }
        ++captured;
        if (listen) {
            /* Retain the complete advertisement, then show/decrypt the selected
             * manufacturer/service payload as BleBroadcastListenCmdProcessor does. */
            bool appended =
                append_capture(result.detail_message, detail_capacity, &detail_used, &advertisement,
                               injected ? "raw_input" : "raw",
                               (byte_span){advertisement.data, advertisement.data_length});
            if (strcmp(mode, "raw") || strcmp(format, "raw")) {
                uint8_t plaintext_bytes[NM_BLE_ADVERTISEMENT_MAX];
                byte_span plaintext = {0};
                bool decrypted =
                    decrypt_payload(format, payload, key, key_length, nonce_len, tag_len,
                                    !strcmp(nonce_at, "end"), plaintext_bytes, &plaintext);
                if (!decrypted)
                    plaintext = payload;
                nm_ble_output output = {result.detail_message, detail_capacity, detail_used,
                                        !appended, NULL};
                nm_ble_output_append(&output, "Selected payload (%s)%s: ", payload_type,
                                     decrypted ? "" : "; decryption failed, showing raw");
                for (size_t i = 0; i < plaintext.length; ++i)
                    nm_ble_output_append(&output, "%02X", plaintext.bytes[i]);
                nm_ble_output_append(&output, "\n");
                detail_used = output.used;
                appended = !output.failed;
            }
            if (!appended) {
                nm_esp_result_release(&result);
                return nm_endpoint_local_failure(result.elapsed_ms,
                                                 "BLE capture output limit exceeded");
            }
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
                    injected                   ? "raw payload provided"
                    : captured == max_captures ? "capture limit reached"
                                               : "timeout");
        snprintf(result.message, sizeof(result.message), "BLE listen captured %u advertisement(s)",
                 captured);
        return result;
    }
    if (!captured) {
        snprintf(result.status, sizeof(result.status), "BLE Error");
        snprintf(result.message, sizeof(result.message), "BLE scan canceled or timed out for %s",
                 filter.address);
        return result;
    }
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
