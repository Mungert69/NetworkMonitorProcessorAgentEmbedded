#include "ble_payload.h"
#include "ble_filter.h"
#include "ble_crypto.h"
#include "mbedtls/base64.h"
#include "psa/crypto.h"
#include <ctype.h>
#include <stdio.h>
#include <string.h>

enum { BLE_KEY_MAX = 32 };
bool nm_ble_payload_normalize_address(const char *input, char out[NM_BLE_ADDRESS_TEXT_SIZE])
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

bool nm_ble_payload_parse_key(const char *text, uint8_t *key, size_t *key_length)
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

bool nm_ble_payload_parse_hex_payload(const char *text, uint8_t out[NM_BLE_ADVERTISEMENT_MAX],
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
bool nm_ble_payload_parse_service_uuid(const char *text, uint8_t out[16], size_t *length)
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

nm_ble_bytes nm_ble_payload_advertisement_payload(const nm_ble_advertisement *advertisement,
                                                  const char **payload_type, int company,
                                                  const char *mode, const uint8_t *service_uuid,
                                                  size_t service_uuid_length)
{
    if (!strcmp(mode, "raw")) {
        *payload_type = "raw";
        return (nm_ble_bytes){.bytes = advertisement->data, .length = advertisement->data_length};
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
                return (nm_ble_bytes){.bytes = advertisement->data + offset + 2 + uuid_size,
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
            return (nm_ble_bytes){.bytes = value, .length = length};
        }
    }
    /* Match .NET's fallback to raw scan data when the selected field is absent. */
    *payload_type = "raw";
    return (nm_ble_bytes){.bytes = advertisement->data, .length = advertisement->data_length};
}

bool nm_ble_payload_decrypt_payload(const char *format, nm_ble_bytes payload, const uint8_t *key,
                                    size_t key_length, unsigned nonce_len, unsigned tag_len,
                                    bool nonce_at_end, uint8_t output[NM_BLE_ADVERTISEMENT_MAX],
                                    nm_ble_bytes *plaintext)
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
            if (!nm_ble_aes_block(key, key_length, counter, stream))
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
    *plaintext = (nm_ble_bytes){.bytes = output, .length = cipher_len};
    return true;
}
