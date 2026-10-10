/* Run production endpoint_ble.c with deterministic scanner/time and PSA/OpenSSL
 * crypto adapters. Firmware uses the ESP-IDF PSA implementation. */
#include "../../firmware/main/endpoint_ble.c"
#include <assert.h>
#include "ble_decoder_internal.h"
#include <openssl/evp.h>

static int64_t now_us;
static nm_ble_advertisement packets[4];
static size_t packet_count;
static bool scanner_unavailable;

int64_t esp_timer_get_time(void)
{
    return now_us;
}
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
static nm_esp_result run_ble(const nm_monitor_record *monitor, uint64_t timeout)
{
    nm_ble_buffer_reset();
    nm_ble_buffer_set_available(!scanner_unavailable);
    for (size_t i = 0; i < packet_count; ++i)
        nm_ble_buffer_receive(&packets[i], now_us);
    nm_ble_buffer_complete_cycle(now_us);
    return nm_endpoint_check_ble(monitor, timeout);
}

int mbedtls_base64_decode(unsigned char *out, size_t capacity, size_t *used,
                          const unsigned char *input, size_t length)
{
    if (length % 4 || length / 4 * 3 > capacity)
        return -1;
    int decoded = EVP_DecodeBlock(out, input, (int)length);
    if (decoded < 0)
        return -1;
    while (length && input[length - 1] == '=') {
        --length;
        --decoded;
    }
    *used = (size_t)decoded;
    return 0;
}

static void reset_packets(void)
{
    now_us = 0;
    packet_count = 0;
    scanner_unavailable = false;
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
    assert(psa_cipher_encrypt(handle, PSA_ALG_ECB_NO_PADDING, counter, sizeof(counter), stream,
                              sizeof(stream), &encrypted_length) == PSA_SUCCESS);
    assert(encrypted_length == sizeof(stream));
    assert(psa_destroy_key(handle) == PSA_SUCCESS);
    item->data[0] = 19;
    item->data[1] = 0xff;
    item->data[2] = 0xe1;
    item->data[3] = 0x02;
    item->data[4] = record_type;
    item->data[5] = 0x34;
    item->data[6] = 0x12;
    item->data[7] = key[0];
    for (size_t i = 0; i < 12; ++i)
        item->data[8 + i] = plain[i] ^ stream[i];
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
    add_victron(key, 0x07); /* Unsupported GX record must be ignored. */
    add_victron(key, 0x01);
    nm_monitor_record monitor = {.Address = "aa-bb-cc-dd-ee-ff",
                                 .EndPointType = "blebroadcast",
                                 .Password = "A00102030405060708090A0B0C0D0E0F",
                                 .Args = "--format victron --metric pv_power",
                                 .Timeout = 100};
    nm_esp_result result = run_ble(&monitor, 100);
    assert(result.ok && !strcmp(result.status, "BLE v2:victron:pv_power"));
    assert(result.has_sample && result.sample == 123 && strstr(result.message, "PV power: 123 W"));
    reset_packets();
    nm_esp_result_release(&result);
    result = run_ble(&monitor, 20);
    assert(!result.ok && !strcmp(result.status, "BLE Error"));
    scanner_unavailable = true;
    nm_esp_result_release(&result);
    result = run_ble(&monitor, 20);
    assert(result.disposition == NM_PROBE_LOCAL_FAILURE);
    reset_packets();
    add_victron(key, 0x01);
    monitor.Password = NULL;
    nm_esp_result_release(&result);
    result = run_ble(&monitor, 20);
    assert(!result.ok && !strcmp(result.status, "BLE Error"));
    assert(strstr(result.message, "key is missing") && strstr(result.message, "monitor Password"));
    monitor.Password = "ABCD";
    nm_esp_result_release(&result);
    result = run_ble(&monitor, 20);
    assert(!result.ok && !strcmp(result.status, "BLE Error"));
    assert(strstr(result.message, "16-byte AES-128 key"));
    monitor.Password = "";
    monitor.Args = "";
    nm_esp_result_release(&result);
    result = run_ble(&monitor, 20);
    assert(result.ok && !strcmp(result.status, "BLE broadcast received"));
    assert(strstr(result.message, "payload(manufacturer)="));
}
static void test_listen(void)
{
    reset_packets();
    static const uint8_t key[16] = {0xa0};
    add_victron(key, 0x01);
    add_victron(key, 0x01);
    packets[1].data[packets[1].data_length - 1] ^= 1; /* Distinct raw captures. */
    nm_monitor_record monitor = {
        .EndPointType = "blebroadcastlisten", .Args = "--max_captures 3", .Timeout = 30};
    nm_esp_result result = run_ble(&monitor, 30);
    assert(result.ok && !strcmp(result.status, "BLE listen complete"));
    assert(strstr(result.message, "captured 2 advertisement(s)"));
    assert(result.detail_message);
    assert(strstr(result.detail_message, "Capture"));
    assert(strstr(result.detail_message, "Address: AA:BB:CC:DD:EE:FF"));
    assert(strstr(result.detail_message, "Payload (raw): 13FFE10201"));
    assert(strstr(result.detail_message,
                  "Captured 2 advertisement(s). End reason: processor cycle complete"));
    nm_esp_result_release(&result);
    reset_packets();
    add_victron(key, 0x01);
    monitor.Address = "blebroadcastlisten"; /* Frontend-friendly display label. */
    nm_esp_result_release(&result);
    result = run_ble(&monitor, 30);
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
    static const uint8_t ctr_key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    static const uint8_t ctr_payload[32] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                                            0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
                                            0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
                                            0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce};
    static const uint8_t ctr_plain[16] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                                          0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    assert(decrypt_payload("aesctr", (byte_span){ctr_payload, sizeof(ctr_payload)}, ctr_key, 16, 16,
                           16, false, out, &plaintext));
    assert(plaintext.length == 16 && !memcmp(plaintext.bytes, ctr_plain, 16));
}
static void test_service_and_raw_override(void)
{
    uint8_t uuid[16] = {0};
    size_t uuid_length = 0;
    assert(parse_service_uuid("180F", uuid, &uuid_length));
    assert(uuid_length == 2 && uuid[0] == 0x0f && uuid[1] == 0x18);
    assert(parse_service_uuid("00112233-4455-6677-8899-AABBCCDDEEFF", uuid, &uuid_length));
    assert(uuid_length == 16 && uuid[0] == 0 && uuid[15] == 0xff);
    nm_ble_advertisement guid_service = {.data_length = 19,
                                         .data = {18, 0x21, 0x33, 0x22, 0x11, 0x00, 0x55, 0x44,
                                                  0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                                                  0xee, 0xff, 0x42}};
    const char *guid_type = "raw";
    byte_span guid_selected =
        advertisement_payload(&guid_service, &guid_type, -1, "service", uuid, uuid_length);
    assert(!strcmp(guid_type, "service") && guid_selected.length == 1 &&
           guid_selected.bytes[0] == 0x42);
    assert(!parse_service_uuid("bad-uuid", uuid, &uuid_length));
    assert(parse_service_uuid("180F", uuid, &uuid_length));
    nm_ble_advertisement service = {.address = "AA:BB:CC:DD:EE:FF",
                                    .data = {5, 0x16, 0x0f, 0x18, 0x42, 0x43},
                                    .data_length = 6};
    const char *type = "raw";
    byte_span selected = advertisement_payload(&service, &type, -1, "service", uuid, uuid_length);
    assert(!strcmp(type, "service") && selected.length == 2 && selected.bytes[0] == 0x42 &&
           selected.bytes[1] == 0x43);
    uuid[0] = 0x00;
    selected = advertisement_payload(&service, &type, -1, "service", uuid, uuid_length);
    assert(!strcmp(type, "raw") && selected.length == service.data_length);

    reset_packets();
    scanner_unavailable = true;
    nm_monitor_record monitor = {.Address = "AA:BB:CC:DD:EE:FF",
                                 .EndPointType = "blebroadcast",
                                 .Args = "--format raw --raw_payload 0xAABBCC",
                                 .Timeout = 100};
    nm_esp_result result = run_ble(&monitor, 100);
    assert(result.ok && strstr(result.message, "payload(raw_input)=AABBCC"));
    reset_packets();
    add_victron((const uint8_t[16]){0xa0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, 0x01);
    char args[128] = "--format victron --raw_payload 0x";
    size_t used = strlen(args);
    for (size_t i = 2; i < packets[0].data_length; ++i) {
        int written = snprintf(args + used, sizeof(args) - used, "%02X", packets[0].data[i]);
        assert(written == 2 && used + 2 < sizeof(args));
        used += 2;
    }
    monitor.Password = "A00102030405060708090A0B0C0D0E0F";
    monitor.Args = args;
    nm_esp_result_release(&result);
    result = run_ble(&monitor, 100);
    assert(result.ok && !strcmp(result.status, "BLE pv_power"));
    monitor.Address = NULL;
    monitor.EndPointType = "blebroadcastlisten";
    monitor.Password = "";
    monitor.Args = "--raw_payload AABBCC";
    nm_esp_result_release(&result);
    result = run_ble(&monitor, 100);
    assert(result.ok && strstr(result.message, "captured 1 advertisement(s)"));
    assert(result.detail_message && strstr(result.detail_message, "raw payload provided"));
    assert(strstr(result.detail_message, "Payload (raw_input): AABBCC"));
    nm_esp_result_release(&result);
}
static void test_changing_metric_readings(void)
{
    static const uint8_t key[16] = {0xa0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
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
            nm_esp_result result = run_ble(&monitor, 100);
            char status[96];
            snprintf(status, sizeof(status), "BLE v2:victron:%s",
                     nm_ble_metric_canonical(cases[i].metric));
            assert(result.ok && !strcmp(result.status, status));
            const nm_ble_metric_encoding *encoding = nm_ble_metric_find("victron", cases[i].metric);
            double divisor = strstr(cases[i].status, "voltage") || strstr(cases[i].status, "yield")
                                 ? 100
                             : strstr(cases[i].status, "current") ? 10
                                                                  : 1;
            uint16_t encoded;
            assert(nm_ble_metric_encode(encoding, cases[i].values[sample] / divisor, &encoded));
            assert(result.has_sample && result.sample == encoded);
            assert(strstr(result.message, details[sample]));
            nm_esp_result_release(&result);
        }
    }
}

static size_t from_hex(const char *hex, uint8_t bytes[255])
{
    size_t n = 0;
    assert(parse_hex_payload(hex, bytes, &n));
    return n;
}
static void test_protocol_decoders(void)
{
    char output[8192];
    uint8_t bytes[255], key[32];
    size_t length, key_length;
    const nm_ble_decoder *ruuvi = nm_ble_decoder_find("RUUVI"),
                         *bthome = nm_ble_decoder_find("bthome");
    assert(ruuvi && bthome && !nm_ble_decoder_find("unknown"));
    assert(nm_ble_decoder_key_error(ruuvi, 16));
    length = from_hex("0512FC5394C37C0004FFFC040CAC364200CDCBB8334C884F", bytes);
    assert(nm_ble_decoder_decode(ruuvi, (nm_ble_bytes){bytes, length}, "raw_input", "device", NULL,
                                 0, output, sizeof(output)));
    assert(strstr(output, "Temperature: 24.3") && strstr(output, "Humidity: 53.49") &&
           strstr(output, "Pressure: 100044"));
    assert(strstr(output, "Acceleration Y: -0.004") &&
           strstr(output, "Device MAC: CB:B8:33:4C:88:4F"));
    memset(bytes + 1, 255, 23);
    bytes[1] = 128;
    bytes[2] = 0;
    assert(nm_ble_decoder_decode(ruuvi, (nm_ble_bytes){bytes, length}, "raw_input", "device", NULL,
                                 0, output, sizeof(output)));
    assert(strstr(output, "Temperature: NA") && strstr(output, "Battery voltage: NA") &&
           strstr(output, "Device MAC: NA"));
    length = from_hex("D2FC41E445F3C9962B332211006C7C4519", bytes);
    assert(parse_key("231D39C1D7CC1AB1AEE224CD096DB932", key, &key_length));
    assert(nm_ble_decoder_decode(bthome, (nm_ble_bytes){bytes, length}, "raw_input",
                                 "54:48:E6:8F:80:A5", key, key_length, output, sizeof(output)));
    assert(strstr(output, "Temperature: 25.06 °C") && strstr(output, "Humidity: 50.55 %") &&
           strstr(output, "Encryption counter: 1122867"));
    const char *addresses[] = {"54:48:E6:8F:80:A6", "unknown"};
    for (size_t i = 0; i < 2; i++) {
        assert(!nm_ble_decoder_decode(bthome, (nm_ble_bytes){bytes, length}, "raw_input",
                                      addresses[i], key, key_length, output, sizeof(output)));
        assert(!strstr(output, "Temperature:") && !strstr(output, "Humidity:"));
    }
    bytes[length - 1] ^= 1;
    assert(!nm_ble_decoder_decode(bthome, (nm_ble_bytes){bytes, length}, "raw_input",
                                  "54:48:E6:8F:80:A5", key, key_length, output, sizeof(output)));
    assert(strstr(output, "authentication failed") && !strstr(output, "Temperature:"));
    const char *bad[] = {"4002", "400F02", "40010153", "405302C0AF", "403BE0"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        length = from_hex(bad[i], bytes);
        assert(!nm_ble_decoder_decode(bthome, (nm_ble_bytes){bytes, length}, "raw_input", "device",
                                      NULL, 0, output, sizeof(output)));
        assert(!strstr(output, "Battery:") && !strstr(output, "BLE protocol:"));
    }
    length = from_hex("4002C40902D0073A013C0203530268695402ABCD", bytes);
    assert(nm_ble_decoder_decode(bthome, (nm_ble_bytes){bytes, length}, "raw_input", "device", NULL,
                                 0, output, sizeof(output)));
    assert(strstr(output, "Temperature: 25 °C") && strstr(output, "Temperature 2: 20 °C") &&
           strstr(output, "Button: press") && strstr(output, "Dimmer: rotate right 3 steps") &&
           strstr(output, "Text: hi") && strstr(output, "Raw: ABCD"));
    length = from_hex("4002C409EE", bytes);
    assert(nm_ble_decoder_decode(bthome, (nm_ble_bytes){bytes, length}, "raw_input", "device", NULL,
                                 0, output, sizeof(output)));
    assert(strstr(output, "Temperature: 25 °C") && strstr(output, "Unsupported BTHome object"));
    assert(!nm_ble_decoder_decode(bthome, (nm_ble_bytes){bytes, length}, "raw_input", "device",
                                  NULL, 0, output, 8));
}
static void test_victron_layouts(void)
{
    const struct {
        uint8_t type;
        unsigned size;
        const char *name;
    } devices[] = {{1, 10, "Battery voltage"}, {2, 15, "Battery monitor"},
                   {3, 11, "Inverter"},        {4, 10, "DC/DC converter"},
                   {5, 16, "SmartLithium"},    {6, 12, "Inverter RS"},
                   {8, 13, "AC charger"},      {9, 15, "Smart Battery Protect"},
                   {10, 16, "Lynx Smart BMS"}, {11, 14, "Multi RS"},
                   {12, 13, "VE.Bus"},         {13, 11, "DC energy meter"},
                   {15, 14, "Orion XS"}};
    uint8_t plain[16] = {0}, frame[26], stream[16], nonce[16] = {0x34, 0x12}, key[16] = {0};
    char output[8192];
    assert(nm_ble_aes_block(key, 16, nonce, stream));
    const nm_ble_decoder *d = nm_ble_decoder_find("victron");
    for (size_t i = 0; i < sizeof(devices) / sizeof(devices[0]); i++) {
        const unsigned n = devices[i].size;
        frame[0] = 0xe1;
        frame[1] = 2;
        frame[2] = devices[i].type;
        frame[3] = 0x34;
        frame[4] = 0x12;
        frame[5] = 0;
        for (unsigned j = 0; j < n; j++)
            frame[6 + j] = plain[j] ^ stream[j];
        assert(nm_ble_decoder_decode(d, (nm_ble_bytes){frame, n + 6}, "manufacturer", "device", key,
                                     16, output, sizeof(output)));
        assert(strstr(output, devices[i].name));
        nm_ble_bytes selected;
        assert(nm_ble_decoder_select(d, (nm_ble_bytes){frame, n + 6}, "manufacturer", &selected));
        assert(d->accepts(selected, true, 0) && !d->accepts(selected, true, 1));
        memmove(frame + 6, frame + 2, n + 4);
        frame[2] = 0x10;
        frame[3] = 0;
        frame[4] = 0;
        frame[5] = 0;
        assert(nm_ble_decoder_decode(d, (nm_ble_bytes){frame, n + 10}, "manufacturer", "device",
                                     key, 16, output, sizeof(output)));
        assert(strstr(output, devices[i].name));
        nm_ble_output out = {output, sizeof(output), 0, false, NULL};
        assert(!nm_ble_victron_record_decode(devices[i].type, (nm_ble_bytes){plain, n - 1}, &out));
        assert(strstr(output, "too short"));
    }
    {
        uint8_t data[255];
        size_t n = from_hex("093412D2045802D8D90700", data);
        nm_ble_output out = {output, sizeof(output), 0, false, NULL};
        assert(nm_ble_victron_record_decode(0x03, (nm_ble_bytes){data, n}, &out));
        assert(strstr(output, "Battery voltage: 12.34 V"));
        assert(strstr(output, "AC apparent power: 600 VA"));
        assert(strstr(output, "AC voltage: 230.00 V"));
        assert(strstr(output, "AC current: 1.5 A"));
    }
    {
        uint8_t data[255];
        size_t n = from_hex("03002805D5FD00000080", data);
        nm_ble_output out = {output, sizeof(output), 0, false, NULL};
        assert(nm_ble_victron_record_decode(0x04, (nm_ble_bytes){data, n}, &out));
        assert(strstr(output, "Input voltage: 13.20 V"));
        assert(strstr(output, "Output voltage: -5.55 V"));
        assert(strstr(output, "Off reason: 2147483648"));
    }
    {
        uint8_t data[255];
        size_t n = from_hex("0000D204E9FFC801D20438FF", data);
        nm_ble_output out = {output, sizeof(output), 0, false, NULL};
        assert(nm_ble_victron_record_decode(0x06, (nm_ble_bytes){data, n}, &out));
        assert(strstr(output, "Battery current: -2.3 A"));
        assert(strstr(output, "PV power: 456 W"));
        assert(strstr(output, "Yield today: 12.34 kWh"));
        assert(strstr(output, "AC out power: -200 W"));
    }
    {
        uint8_t data[255];
        size_t n = from_hex("000028E5018C2503F06504C10A", data);
        nm_ble_output out = {output, sizeof(output), 0, false, NULL};
        assert(nm_ble_victron_record_decode(0x08, (nm_ble_bytes){data, n}, &out));
        assert(strstr(output, "Battery voltage 1: 13.20 V"));
        assert(strstr(output, "Battery current 1: 1.5 A"));
        assert(strstr(output, "Battery voltage 2: 14.20 V"));
        assert(strstr(output, "Battery current 2: 2.5 A"));
        assert(strstr(output, "Battery voltage 3: 15.20 V"));
        assert(strstr(output, "Battery current 3: 3.5 A"));
        assert(strstr(output, "Battery temperature: 25 °C"));
        assert(strstr(output, "AC current: 2.1 A"));
    }
    {
        uint8_t data[255];
        size_t n = from_hex("0104073412785685FF600900000080", data);
        nm_ble_output out = {output, sizeof(output), 0, false, NULL};
        assert(nm_ble_victron_record_decode(0x09, (nm_ble_bytes){data, n}, &out));
        assert(strstr(output, "Device state: 1"));
        assert(strstr(output, "Output state: 4"));
        assert(strstr(output, "Error code: 7"));
        assert(strstr(output, "Alarm reason: 4660"));
        assert(strstr(output, "Warning reason: 22136"));
        assert(strstr(output, "Input voltage: -1.23 V"));
        assert(strstr(output, "Output voltage: 24.00 V"));
        assert(strstr(output, "Off reason: 2147483648"));
    }
    {
        uint8_t data[255];
        size_t n = from_hex("053C00D20485FF01800100D2BB070041", data);
        nm_ble_output out = {output, sizeof(output), 0, false, NULL};
        assert(nm_ble_victron_record_decode(0x0a, (nm_ble_bytes){data, n}, &out));
        assert(strstr(output, "BMS error: 5"));
        assert(strstr(output, "Time to go: 60 min"));
        assert(strstr(output, "Battery voltage: 12.34 V"));
        assert(strstr(output, "Battery current: -12.3 A"));
        assert(strstr(output, "IO status: 32769"));
        assert(strstr(output, "Warnings/alarms: 131073"));
        assert(strstr(output, "State of charge: 75.6 %"));
        assert(strstr(output, "Consumed Ah: -12.3 Ah"));
        assert(strstr(output, "Battery temperature: 25 °C"));
    }
    {
        uint8_t data[255];
        size_t n = from_hex("000085FFD244D4FEF40158022D00", data);
        nm_ble_output out = {output, sizeof(output), 0, false, NULL};
        assert(nm_ble_victron_record_decode(0x0b, (nm_ble_bytes){data, n}, &out));
        assert(strstr(output, "Battery current: -12.3 A"));
        assert(strstr(output, "Battery voltage: 12.34 V"));
        assert(strstr(output, "Active AC input: 1"));
        assert(strstr(output, "AC in power: -300 W"));
        assert(strstr(output, "AC out power: 500 W"));
        assert(strstr(output, "PV power: 600 W"));
        assert(strstr(output, "Yield today: 0.45 kWh"));
    }
    {
        uint8_t data[255];
        size_t n = from_hex("F7FFD2040000C409B8ECFF", data);
        nm_ble_output out = {output, sizeof(output), 0, false, NULL};
        assert(nm_ble_victron_record_decode(0x0d, (nm_ble_bytes){data, n}, &out));
        assert(strstr(output, "Monitor mode: -9"));
        assert(strstr(output, "Battery voltage: 12.34 V"));
        assert(strstr(output, "Aux voltage: 25.00 V"));
        assert(strstr(output, "Battery current: -1.234 A"));
    }
    {
        uint8_t data[255];
        size_t n = from_hex("03002805E0FF78052D0000000080", data);
        nm_ble_output out = {output, sizeof(output), 0, false, NULL};
        assert(nm_ble_victron_record_decode(0x0f, (nm_ble_bytes){data, n}, &out));
        assert(strstr(output, "Output voltage: 13.20 V"));
        assert(strstr(output, "Output current: -3.2 A"));
        assert(strstr(output, "Input voltage: 14.00 V"));
        assert(strstr(output, "Input current: 4.5 A"));
        assert(strstr(output, "Off reason: 2147483648"));
    }
}
static void test_sensor_endpoints(void)
{
    reset_packets();
    nm_ble_advertisement *a = &packets[packet_count++];
    strcpy(a->address, "54:48:E6:8F:80:A5");
    a->data_length = from_hex("0A16D2FC4002C409037713", a->data);
    nm_monitor_record monitor = {.Address = "54:48:E6:8F:80:A5",
                                 .EndPointType = "blebroadcast",
                                 .Args = "--format bthome --metric temperature"};
    nm_esp_result result = run_ble(&monitor, 100);
    assert(result.ok && result.detail_message &&
           strstr(result.detail_message, "Temperature: 25 °C") &&
           strstr(result.detail_message, "Humidity: 49.83 %"));
    nm_esp_result_release(&result);
    reset_packets();
    a = &packets[packet_count++];
    strcpy(a->address, "AA:BB:CC:DD:EE:FF");
    a->data_length = from_hex("1BFF99040512FC5394C37C0004FFFC040CAC364200CDCBB8334C884F", a->data);
    monitor.Address = a->address;
    monitor.Args = "--format ruuvi --metric temperature";
    result = run_ble(&monitor, 100);
    assert(result.ok && strstr(result.detail_message, "RuuviTag"));
    nm_esp_result_release(&result);
    reset_packets();
    add_victron((uint8_t[16]){0}, 1);
    monitor.Address = NULL;
    monitor.EndPointType = "blebroadcastlisten";
    monitor.Args = "--format victron";
    result = run_ble(&monitor, 100);
    assert(result.ok && strstr(result.detail_message, "Payload (raw):") &&
           !strstr(result.detail_message, "Decode error:") && strstr(result.message, "captured 1"));
    nm_esp_result_release(&result);
    reset_packets();
    monitor.Args = "--format bthome --raw_payload D2FC41E445F3C9962B332211006C7C4519";
    monitor.Password = "231D39C1D7CC1AB1AEE224CD096DB932";
    result = run_ble(&monitor, 100);
    assert(result.ok && strstr(result.detail_message, "Payload (raw_input): D2FC41") &&
           !strstr(result.detail_message, "Temperature:"));
    nm_esp_result_release(&result);
}

static void test_invalid_options(void)
{
    nm_monitor_record monitor = {.Address = "AA:BB:CC:DD:EE:FF", .EndPointType = "blebroadcast"};
    const char *invalid[] = {"--format", "--format bthome --service_uuid",
                             "--format bthome --payload 'unterminated",
                             "--format this-format-is-too-long-for-the-bounded-option-buffer",
                             "--format ruuvi --max_captures 51"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        reset_packets();
        monitor.Args = (char *)invalid[i];
        nm_esp_result result = run_ble(&monitor, 100);
        assert(!result.ok);
        nm_esp_result_release(&result);
    }
    reset_packets();
    monitor.Args = "--format ruuvi --metric temperature";
    monitor.Password = "00000000000000000000000000000000";
    nm_esp_result result = run_ble(&monitor, 100);
    assert(!result.ok && strstr(result.message, "unencrypted"));
    nm_esp_result_release(&result);
}

static void test_automatic_signed_metrics(void)
{
    nm_monitor_record monitor = {.Address = "AA:BB:CC:DD:EE:FF",
                                 .EndPointType = "blebroadcast",
                                 .Args =
                                     "--format bthome --metric temperature --raw_payload 40020CFE",
                                 .Timeout = 100};
    nm_esp_result result = run_ble(&monitor, 100);
    assert(result.ok && !strcmp(result.status, "BLE v2:bthome:temperature"));
    const nm_ble_metric_encoding *e = nm_ble_metric_find("bthome", "temperature");
    assert(fabs(result.sample * e->scale + e->offset - (-5)) <= e->scale / 2);
    nm_esp_result_release(&result);
    monitor.Args = "--format bthome --metric missing --raw_payload 40020CFE";
    result = run_ble(&monitor, 100);
    assert(!result.ok && !strcmp(result.status, "BLE Metric Error"));
    nm_esp_result_release(&result);
}
static void test_implicit_metric_and_args(void)
{
    static const uint8_t key[16] = {0xa0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    nm_monitor_record monitor = {.Address = "AA:BB:CC:DD:EE:FF",
                                 .EndPointType = "blebroadcast",
                                 .Password = "A00102030405060708090A0B0C0D0E0F",
                                 .Args = "--format victron"};
    reset_packets();
    add_victron(key, 0x01);
    nm_esp_result result = run_ble(&monitor, 100);
    assert(result.ok && result.has_sample && result.sample == 123);
    assert(!strcmp(result.status, "BLE pv_power"));
    nm_esp_result_release(&result);
    reset_packets();
    uint8_t unavailable[12] = {0, 0, 0xd2, 0x04, 0x19, 0, 0x2c, 0x01, 0xff, 0xff, 0x1e, 0};
    add_victron_reading(key, 0x01, unavailable);
    result = run_ble(&monitor, 100);
    assert(!result.ok && !result.has_sample && !strcmp(result.status, "BLE Metric Error"));
    nm_esp_result_release(&result);
    const char *valid[] = {
        "--FORMAT=BTHOME --METRIC=temperature --RAW_PAYLOAD=40020CFE",
        "--format='bthome' --metric='Temperature' --raw_payload='40020CFE'",
        "--format raw --format bthome --metric temperature --raw_payload 40020CFE"};
    monitor.Password = NULL;
    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i) {
        reset_packets();
        monitor.Args = (char *)valid[i];
        result = run_ble(&monitor, 100);
        assert(result.ok && result.has_sample &&
               !strcmp(result.status, "BLE v2:bthome:temperature"));
        nm_esp_result_release(&result);
    }
    monitor.Args = "   ";
    monitor.Username = (char *)valid[0];
    result = run_ble(&monitor, 100);
    assert(result.ok && result.has_sample);
    nm_esp_result_release(&result);
    monitor.Username = NULL;
    const char *invalid[] = {"--format bthome --metirc temperature",
                             "--format bthome --metric temperature --metric humidity",
                             "--format bthome --metric", "--format bthome --max_captures 2"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        reset_packets();
        monitor.Args = (char *)invalid[i];
        result = run_ble(&monitor, 100);
        assert(!result.ok);
        nm_esp_result_release(&result);
    }
    monitor.EndPointType = "blebroadcastlisten";
    monitor.Password = "00000000000000000000000000000000";
    monitor.Args =
        "--format aesgcm --raw_payload "
        "0000000000000000000000000388DACE60B6A392F328C2B971B2FE78AB6E47D42CEC13BDF53A67B21257BDDF";
    result = run_ble(&monitor, 100);
    assert(result.ok && !result.has_sample && result.detail_message);
    assert(strstr(result.detail_message, "Payload (raw_input): 0000000000000000000000000388DACE"));
    nm_esp_result_release(&result);
    monitor.Args =
        "--format aesgcm --raw_payload "
        "0000000000000000000000000388DACE60B6A392F328C2B971B2FE78AB6E47D42CEC13BDF53A67B21257BDDE";
    result = run_ble(&monitor, 100);
    assert(result.ok && strstr(result.detail_message, "Payload (raw_input):"));
    nm_esp_result_release(&result);
    monitor.Password = NULL;
    monitor.Args = "--format bthome --metric temperature";
    result = run_ble(&monitor, 100);
    assert(!result.ok);
    nm_esp_result_release(&result);
    reset_packets();
    monitor.Args = "--format raw --max_captures 1";
    result = run_ble(&monitor, 70009);
    assert(result.ok && !result.has_sample && result.elapsed_ms == 0);
    assert(nm_esp_result_sample("blebroadcastlisten", &result) == 0);
    nm_esp_result_release(&result);
}

static void test_window_averaging(void)
{
    static const uint8_t key[16] = {0xa0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    const uint8_t low[12] = {0, 0, 0x14, 0x05, 0xf5, 0xff, 0, 0, 10, 0, 0, 0};
    const uint8_t high[12] = {0, 0, 0x28, 0x05, 0xf7, 0xff, 0, 0, 30, 0, 0, 0};
    reset_packets();
    add_victron_reading(key, 1, low);
    add_victron_reading(key, 1, high);
    nm_ble_buffer_reset();
    nm_ble_buffer_set_available(true);
    nm_ble_buffer_rules_begin();
    assert(nm_ble_buffer_protect(packets[0].address, 70000));
    assert(nm_ble_buffer_receive(&packets[1], 0)); /* excluded: 70s plus 1us old */
    assert(nm_ble_buffer_receive(&packets[0], 1)); /* included: exact boundary */
    assert(nm_ble_buffer_receive(&packets[1], 60000001));
    assert(nm_ble_buffer_complete_cycle(70000001));
    nm_monitor_record monitor = {.Address = "AA:BB:CC:DD:EE:FF",
                                 .EndPointType = "blebroadcast",
                                 .Password = "A00102030405060708090A0B0C0D0E0F",
                                 .Args = "--format victron --metric battery_current"};
    nm_esp_result result = nm_endpoint_check_ble(&monitor, 70000);
    uint16_t expected;
    assert(nm_ble_metric_encode(nm_ble_metric_find("victron", "battery_current"), -1.0, &expected));
    assert(result.ok && result.sample == expected);
    assert(
        strstr(result.detail_message, "Battery current: -0.9 A")); /* latest, not averaged text */
    nm_esp_result_release(&result);
    monitor.Args = "--format victron --metric battery_voltage";
    result = nm_endpoint_check_ble(&monitor, 70000);
    assert(nm_ble_metric_encode(nm_ble_metric_find("victron", "battery_voltage"), 13.1, &expected));
    assert(result.ok && result.sample == expected);
    nm_esp_result_release(&result);
    monitor.EndPointType = "blebroadcastlisten";
    monitor.Args = NULL;
    result = nm_endpoint_check_ble(&monitor, 1);
    assert(result.ok && strstr(result.message, "captured 3 advertisement"));
    nm_esp_result_release(&result);
    assert(nm_ble_buffer_complete_cycle(80000000));
    result = nm_endpoint_check_ble(&monitor, 1);
    assert(result.ok && strstr(result.message, "captured 0 advertisement"));
    nm_esp_result_release(&result);
    /* More than the previous capture cap, legacy cap is ignored. */
    monitor.Args = "--format victron --max_captures 1";
    for (int i = 0; i < 80; ++i) {
        /* Distinct raw payloads bypass the deliberate one-second repeat filter. */
        packets[0].data[packets[0].data_length - 1] = (uint8_t)i;
        assert(nm_ble_buffer_receive(&packets[0], 80000000 + i));
    }
    assert(nm_ble_buffer_complete_cycle(90000000));
    result = nm_endpoint_check_ble(&monitor, 1);
    assert(result.ok && strstr(result.message, "captured 80 advertisement"));
    nm_esp_result_release(&result);
    monitor.EndPointType = "blebroadcast";
    monitor.Args = "--format victron --metric pv_power";
    assert(nm_ble_buffer_complete_cycle(300000000));
    result = nm_endpoint_check_ble(&monitor, 70000);
    assert(!result.ok && !result.has_sample);
    nm_esp_result_release(&result);
    nm_ble_buffer_reset();
}

int main(void)
{
    test_window_averaging();
    test_implicit_metric_and_args();
    test_automatic_signed_metrics();
    test_invalid_options();
    test_protocol_decoders();
    test_victron_layouts();
    test_sensor_endpoints();
    test_victron();
    test_listen();
    test_aes_vectors();
    test_service_and_raw_override();
    test_changing_metric_readings();
    nm_ble_buffer_reset();
    puts("BLE endpoint/decryption tests passed");
    return 0;
}
