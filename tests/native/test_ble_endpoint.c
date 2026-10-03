/* Run production endpoint_ble.c with deterministic scanner/time and PSA/OpenSSL
 * crypto adapters. Firmware uses the ESP-IDF PSA implementation. */
#include "../../firmware/main/endpoint_ble.c"
#include <assert.h>
#include <openssl/evp.h>

typedef struct { uint8_t key[32]; size_t length; uint32_t usage, alg; } test_key;
static test_key imported_key;

void psa_set_key_type(psa_key_attributes_t *a, uint32_t value) { a->type = value; }
void psa_set_key_bits(psa_key_attributes_t *a, uint32_t value) { a->bits = value; }
void psa_set_key_usage_flags(psa_key_attributes_t *a, uint32_t value) { a->usage = value; }
void psa_set_key_algorithm(psa_key_attributes_t *a, uint32_t value) { a->alg = value; }
void psa_reset_key_attributes(psa_key_attributes_t *a) { memset(a, 0, sizeof(*a)); }
psa_status_t psa_import_key(const psa_key_attributes_t *a, const uint8_t *key,
                            size_t length, mbedtls_svc_key_id_t *handle)
{
    if (!a || !key || !handle || a->type != PSA_KEY_TYPE_AES ||
        (length != 16 && length != 24 && length != 32) || a->bits != length * 8)
        return -1;
    memcpy(imported_key.key, key, length);
    imported_key.length = length;
    imported_key.usage = a->usage;
    imported_key.alg = a->alg;
    *handle = 1;
    return PSA_SUCCESS;
}
psa_status_t psa_cipher_encrypt(mbedtls_svc_key_id_t handle, uint32_t alg,
                                const uint8_t *input, size_t input_length,
                                uint8_t *output, size_t output_size, size_t *output_length)
{
    if (handle != 1 || alg != PSA_ALG_ECB_NO_PADDING || !input || !output ||
        !output_length || input_length != 16 || output_size < 16 ||
        imported_key.usage != PSA_KEY_USAGE_ENCRYPT) return -1;
    const EVP_CIPHER *cipher = imported_key.length == 16 ? EVP_aes_128_ecb() :
                              imported_key.length == 24 ? EVP_aes_192_ecb() : EVP_aes_256_ecb();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int used = 0, final = 0;
    bool ok = EVP_EncryptInit_ex(ctx, cipher, NULL, imported_key.key, NULL) == 1 &&
              EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
              EVP_EncryptUpdate(ctx, output, &used, input, 16) == 1 &&
              EVP_EncryptFinal_ex(ctx, output + used, &final) == 1 && used + final == 16;
    EVP_CIPHER_CTX_free(ctx);
    if (ok)
        *output_length = (size_t)(used + final);
    return ok ? PSA_SUCCESS : -1;
}
psa_status_t psa_aead_decrypt(mbedtls_svc_key_id_t handle, uint32_t alg, const uint8_t *nonce,
                              size_t nonce_length, const uint8_t *aad, size_t aad_length,
                              const uint8_t *input, size_t input_length, uint8_t *output,
                              size_t output_size, size_t *output_length)
{
    (void)aad;
    size_t tag_length = alg >> 8;
    if (handle != 1 || (alg & 255) != PSA_ALG_GCM || alg != imported_key.alg || tag_length < 12 ||
        tag_length > 16 || !nonce || !input || !output || !output_length ||
        input_length < tag_length || input_length > INT_MAX || nonce_length > INT_MAX ||
        output_size < input_length - tag_length || imported_key.usage != PSA_KEY_USAGE_DECRYPT)
        return -1;
    const EVP_CIPHER *cipher = imported_key.length == 16   ? EVP_aes_128_gcm()
                               : imported_key.length == 24 ? EVP_aes_192_gcm()
                                                           : EVP_aes_256_gcm();
    size_t ciphertext_length = input_length - tag_length;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;
    int written = 0, final = 0;
    bool ok = EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_length, NULL) == 1 &&
              EVP_DecryptInit_ex(ctx, NULL, NULL, imported_key.key, nonce) == 1 &&
              (!aad_length || EVP_DecryptUpdate(ctx, NULL, &written, aad, (int)aad_length) == 1) &&
              EVP_DecryptUpdate(ctx, output, &written, input, (int)ciphertext_length) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_length,
                                  (void *)(input + ciphertext_length)) == 1 &&
              EVP_DecryptFinal_ex(ctx, output + written, &final) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (ok)
        *output_length = (size_t)(written + final);
    return ok ? PSA_SUCCESS : -1;
}
psa_status_t psa_destroy_key(mbedtls_svc_key_id_t handle)
{
    if (handle != 1) return -1;
    memset(&imported_key, 0, sizeof(imported_key));
    return PSA_SUCCESS;
}

static int64_t now_us;
static nm_ble_advertisement packets[4];
static size_t packet_count, next_packet;
static bool scanner_unavailable;

int64_t esp_timer_get_time(void) { return now_us; }
unsigned nm_endpoint_elapsed(int64_t start)
{
    return (unsigned)((now_us - start) / 1000);
}
unsigned nm_endpoint_remaining(int64_t start, unsigned timeout)
{
    unsigned spent = nm_endpoint_elapsed(start);
    return spent < timeout ? timeout - spent : 0;
}
nm_esp_result nm_endpoint_local_failure(unsigned elapsed, const char *detail)
{
    nm_esp_result result = {.elapsed_ms = elapsed, .disposition = NM_PROBE_LOCAL_FAILURE};
    snprintf(result.message, sizeof(result.message), "%s", detail);
    return result;
}
nm_ble_wait_result nm_ble_scanner_wait(const nm_ble_filter *filter, unsigned timeout,
                                       nm_ble_advertisement *item)
{
    if (scanner_unavailable) return NM_BLE_WAIT_UNAVAILABLE;
    while (next_packet < packet_count) {
        nm_ble_advertisement *candidate = &packets[next_packet++];
        now_us += 1000;
        if (nm_ble_advertisement_matches(candidate, filter)) {
            *item = *candidate;
            return NM_BLE_WAIT_FOUND;
        }
    }
    now_us += (int64_t)timeout * 1000;
    return NM_BLE_WAIT_TIMEOUT;
}

int mbedtls_base64_decode(unsigned char *out, size_t capacity, size_t *used,
                          const unsigned char *input, size_t length)
{
    if (length % 4 || length / 4 * 3 > capacity) return -1;
    int decoded = EVP_DecodeBlock(out, input, (int)length);
    if (decoded < 0) return -1;
    while (length && input[length - 1] == '=') { --length; --decoded; }
    *used = (size_t)decoded;
    return 0;
}

static void reset_packets(void)
{
    now_us = 0; packet_count = next_packet = 0; scanner_unavailable = false;
    memset(packets, 0, sizeof(packets));
}
static void add_victron_reading(const uint8_t key[16], uint8_t record_type, const uint8_t plain[12])
{
    assert(packet_count < 4);
    nm_ble_advertisement *item = &packets[packet_count++];
    snprintf(item->address, sizeof(item->address), "AA:BB:CC:DD:EE:FF");
    uint8_t counter[16] = {0x34, 0x12}, stream[16];
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 128);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECB_NO_PADDING);
    mbedtls_svc_key_id_t handle = PSA_KEY_ID_NULL;
    assert(psa_import_key(&attributes, key, 16, &handle) == PSA_SUCCESS);
    psa_reset_key_attributes(&attributes);
    size_t encrypted_length = 0;
    assert(psa_cipher_encrypt(handle, PSA_ALG_ECB_NO_PADDING, counter, sizeof(counter),
                              stream, sizeof(stream), &encrypted_length) == PSA_SUCCESS);
    assert(encrypted_length == sizeof(stream));
    assert(psa_destroy_key(handle) == PSA_SUCCESS);
    item->data[0] = 19; item->data[1] = 0xff; item->data[2] = 0xe1;
    item->data[3] = 0x02; item->data[4] = record_type;
    item->data[5] = 0x34; item->data[6] = 0x12; item->data[7] = key[0];
    for (size_t i = 0; i < 12; ++i) item->data[8 + i] = plain[i] ^ stream[i];
    item->data_length = 20;
}
static void add_victron(const uint8_t key[16], uint8_t record_type)
{
    const uint8_t plain[12] = {0, 0, 0xd2, 0x04, 0x19, 0, 0x2c, 0x01, 0x7b, 0, 0x1e, 0};
    add_victron_reading(key, record_type, plain);
}
static void test_victron(void)
{
    static const uint8_t key[16] = {0xa0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    reset_packets();
    add_victron(key, 0x02); /* VeSmart: must be ignored, not host-down or success. */
    add_victron(key, 0x01);
    nm_monitor_record monitor = {.Address = "aa-bb-cc-dd-ee-ff", .EndPointType = "blebroadcast",
        .Password = "A00102030405060708090A0B0C0D0E0F",
        .Args = "--format victron --metric pv_power", .Timeout = 100};
    nm_esp_result result = nm_endpoint_check_ble(&monitor, 100);
    assert(result.ok && !strcmp(result.status, "BLE pv_power"));
    assert(result.elapsed_ms == 123 && strstr(result.message, "PV power: 123 W"));
    assert(next_packet == 2);
    reset_packets();
    result = nm_endpoint_check_ble(&monitor, 20);
    assert(!result.ok && !strcmp(result.status, "BLE Error"));
    scanner_unavailable = true;
    result = nm_endpoint_check_ble(&monitor, 20);
    assert(result.disposition == NM_PROBE_LOCAL_FAILURE);
    reset_packets();
    add_victron(key, 0x01);
    monitor.Password = NULL;
    result = nm_endpoint_check_ble(&monitor, 20);
    assert(!result.ok && !strcmp(result.status, "BLE Error"));
    assert(strstr(result.message, "key is missing") &&
           strstr(result.message, "monitor Password") && next_packet == 0);
    monitor.Password = "ABCD";
    result = nm_endpoint_check_ble(&monitor, 20);
    assert(!result.ok && !strcmp(result.status, "BLE Error"));
    assert(strstr(result.message, "16-byte AES-128 key") && next_packet == 0);
    monitor.Password = "";
    monitor.Args = "";
    result = nm_endpoint_check_ble(&monitor, 20);
    assert(result.ok && !strcmp(result.status, "BLE broadcast received"));
    assert(strstr(result.message, "payload(manufacturer)="));
}
static void test_listen(void)
{
    reset_packets();
    static const uint8_t key[16] = {0xa0};
    add_victron(key, 0x01);
    add_victron(key, 0x01);
    nm_monitor_record monitor = {.EndPointType = "blebroadcastlisten",
                                  .Args = "--max_captures 3", .Timeout = 30};
    nm_esp_result result = nm_endpoint_check_ble(&monitor, 30);
    assert(result.ok && !strcmp(result.status, "BLE listen complete"));
    assert(strstr(result.message, "captured 2 advertisement(s)"));
    assert(result.detail_message);
    assert(strstr(result.detail_message, "Capture"));
    assert(strstr(result.detail_message, "Address: AA:BB:CC:DD:EE:FF"));
    assert(strstr(result.detail_message, "Payload (raw): 13FFE10201"));
    assert(strstr(result.detail_message, "Captured 2 advertisement(s). End reason: timeout"));
    nm_esp_result_release(&result);
    reset_packets();
    add_victron(key, 0x01);
    monitor.Address = "blebroadcastlisten"; /* Frontend-friendly display label. */
    result = nm_endpoint_check_ble(&monitor, 30);
    assert(result.ok && !strcmp(result.status, "BLE listen complete"));
    assert(strstr(result.message, "captured 1 advertisement(s)"));
    assert(result.detail_message && strstr(result.detail_message, "Capture"));
    nm_esp_result_release(&result);
}
static void test_aes_vectors(void)
{
    uint8_t out[255];
    byte_span plaintext;
    static const uint8_t gcm_payload[] = {
        0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, /* nonce */
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9,
        0x71, 0xb2, 0xfe, 0x78, 0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
        0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf};
    uint8_t zero_key[16] = {0};
    for (unsigned tag_length = 12; tag_length <= 16; ++tag_length) {
        size_t length = 12 + 16 + tag_length;
        assert(decrypt_payload("aesgcm", (byte_span){gcm_payload, length}, zero_key, 16, 12,
                               tag_length, false, out, &plaintext));
        assert(plaintext.length == 16);
        for (size_t i = 0; i < 16; ++i)
            assert(plaintext.bytes[i] == 0);
        uint8_t corrupt[sizeof(gcm_payload)];
        memcpy(corrupt, gcm_payload, length);
        corrupt[length - 1] ^= 1;
        assert(!decrypt_payload("aesgcm", (byte_span){corrupt, length}, zero_key, 16, 12,
                                tag_length, false, out, &plaintext));
    }
    assert(decrypt_payload("aesgcm", (byte_span){gcm_payload, sizeof(gcm_payload)}, zero_key, 16,
                           12, 16, false, out, &plaintext));
    assert(plaintext.length == 16);
    for (size_t i = 0; i < plaintext.length; ++i)
        assert(plaintext.bytes[i] == 0);
    uint8_t bad[sizeof(gcm_payload)];
    memcpy(bad, gcm_payload, sizeof(bad));
    bad[sizeof(bad) - 1] ^= 1;
    assert(!decrypt_payload("aesgcm", (byte_span){bad, sizeof(bad)}, zero_key, 16, 12, 16, false,
                            out, &plaintext));
    static const uint8_t ctr_key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    static const uint8_t ctr_payload[32] = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff,
        0x87,0x4d,0x61,0x91,0xb6,0x20,0xe3,0x26,0x1b,0xef,0x68,0x64,0x99,0x0d,0xb6,0xce};
    static const uint8_t ctr_plain[16] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
    assert(decrypt_payload("aesctr", (byte_span){ctr_payload, sizeof(ctr_payload)},
                           ctr_key, 16, 16, 16, false, out, &plaintext));
    assert(plaintext.length == 16 && !memcmp(plaintext.bytes, ctr_plain, 16));
}
static void test_service_and_raw_override(void)
{
    uint8_t uuid[16] = {0}; size_t uuid_length = 0;
    assert(parse_service_uuid("180F", uuid, &uuid_length));
    assert(uuid_length == 2 && uuid[0] == 0x0f && uuid[1] == 0x18);
    assert(parse_service_uuid("00112233-4455-6677-8899-AABBCCDDEEFF", uuid, &uuid_length));
    assert(uuid_length == 16 && uuid[0] == 0 && uuid[15] == 0xff);
    nm_ble_advertisement guid_service = {.data_length = 19,
        .data = {18, 0x21, 0x33,0x22,0x11,0x00, 0x55,0x44, 0x77,0x66,
                 0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff, 0x42}};
    const char *guid_type = "raw";
    byte_span guid_selected = advertisement_payload(&guid_service, &guid_type, -1,
                                                     "service", uuid, uuid_length);
    assert(!strcmp(guid_type, "service") && guid_selected.length == 1 &&
           guid_selected.bytes[0] == 0x42);
    assert(!parse_service_uuid("bad-uuid", uuid, &uuid_length));
    assert(parse_service_uuid("180F", uuid, &uuid_length));
    nm_ble_advertisement service = {.address = "AA:BB:CC:DD:EE:FF",
                                    .data = {5, 0x16, 0x0f, 0x18, 0x42, 0x43},
                                    .data_length = 6};
    const char *type = "raw";
    byte_span selected = advertisement_payload(&service, &type, -1, "service", uuid, uuid_length);
    assert(!strcmp(type, "service") && selected.length == 2 &&
           selected.bytes[0] == 0x42 && selected.bytes[1] == 0x43);
    uuid[0] = 0x00;
    selected = advertisement_payload(&service, &type, -1, "service", uuid, uuid_length);
    assert(!strcmp(type, "raw") && selected.length == service.data_length);

    reset_packets(); scanner_unavailable = true;
    nm_monitor_record monitor = {.Address = "AA:BB:CC:DD:EE:FF", .EndPointType = "blebroadcast",
                                 .Args = "--format raw --raw_payload 0xAABBCC", .Timeout = 100};
    nm_esp_result result = nm_endpoint_check_ble(&monitor, 100);
    assert(result.ok && strstr(result.message, "payload(raw_input)=AABBCC"));
    assert(next_packet == 0); /* No scanner call for a supplied payload. */
    reset_packets(); add_victron((const uint8_t[16]){0xa0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15}, 0x01);
    char args[128] = "--format victron --raw_payload 0x";
    size_t used = strlen(args);
    for (size_t i = 2; i < packets[0].data_length; ++i) {
        int written = snprintf(args + used, sizeof(args) - used, "%02X", packets[0].data[i]);
        assert(written == 2 && used + 2 < sizeof(args));
        used += 2;
    }
    monitor.Password = "A00102030405060708090A0B0C0D0E0F";
    monitor.Args = args;
    result = nm_endpoint_check_ble(&monitor, 100);
    assert(result.ok && !strcmp(result.status, "BLE pv_power"));
    assert(next_packet == 0);
    monitor.Address = NULL;
    monitor.EndPointType = "blebroadcastlisten";
    monitor.Password = "";
    monitor.Args = "--raw_payload AABBCC";
    result = nm_endpoint_check_ble(&monitor, 100);
    assert(result.ok && strstr(result.message, "captured 1 advertisement(s)"));
    assert(result.detail_message && strstr(result.detail_message, "raw payload provided"));
    assert(strstr(result.detail_message, "Payload (raw_input): AABBCC"));
    nm_esp_result_release(&result);
}
static void test_changing_metric_readings(void)
{
    static const uint8_t key[16] = {0xa0, 1, 2, 3, 4, 5, 6, 7,
                                    8, 9, 10, 11, 12, 13, 14, 15};
    const uint8_t readings[][12] = {{0, 0, 0x57, 0x05, 25, 0, 0x2c, 0x01, 123, 0, 30, 0},
                                    {0, 0, 0x58, 0x05, 26, 0, 0x2d, 0x01, 0xc8, 0x01, 31, 0}};
    const struct {
        const char *metric, *status;
        unsigned values[2];
    } cases[] = {{"pv_power", "BLE pv_power", {123, 456}},
                 {"pvpower", "BLE pv_power", {123, 456}},
                 {"pv", "BLE pv_power", {123, 456}},
                 {"battery_voltage", "BLE battery_voltage", {1367, 1368}},
                 {"battery_voltage_v", "BLE battery_voltage", {1367, 1368}},
                 {"battery_v", "BLE battery_voltage", {1367, 1368}},
                 {"battery_current", "BLE battery_current", {25, 26}},
                 {"battery_current_a", "BLE battery_current", {25, 26}},
                 {"battery_a", "BLE battery_current", {25, 26}},
                 {"yield_today", "BLE yield_today", {300, 301}},
                 {"yield", "BLE yield_today", {300, 301}},
                 {"yield_today_kwh", "BLE yield_today", {300, 301}},
                 {"load_current", "BLE load_current", {30, 31}},
                 {"load_current_a", "BLE load_current", {30, 31}},
                 {"load_a", "BLE load_current", {30, 31}}};
    const char *details[] = {
        "Battery voltage: 13.67 V; Battery current: 2.5 A; Yield today: 3.00 kWh; PV power: 123 W",
        "Battery voltage: 13.68 V; Battery current: 2.6 A; Yield today: 3.01 kWh; PV power: 456 W"};
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        char arguments[96];
        int written =
            snprintf(arguments, sizeof(arguments), "--format victron --metric %s", cases[i].metric);
        assert(written > 0 && (size_t)written < sizeof(arguments));
        nm_monitor_record monitor = {.Address = "AA:BB:CC:DD:EE:FF",
                                     .EndPointType = "blebroadcast",
                                     .Password = "A00102030405060708090A0B0C0D0E0F",
                                     .Args = arguments,
                                     .Timeout = 100};
        for (size_t sample = 0; sample < 2; ++sample) {
            reset_packets();
            add_victron_reading(key, 0x01, readings[sample]);
            nm_esp_result result = nm_endpoint_check_ble(&monitor, 100);
            assert(result.ok && !strcmp(result.status, cases[i].status));
            assert(result.elapsed_ms == cases[i].values[sample]);
            assert(strstr(result.message, details[sample]));
            nm_esp_result_release(&result);
        }
    }
}

int main(void)
{
    test_victron();
    test_listen();
    test_aes_vectors();
    test_service_and_raw_override();
    test_changing_metric_readings();
    puts("BLE endpoint/decryption tests passed");
    return 0;
}
