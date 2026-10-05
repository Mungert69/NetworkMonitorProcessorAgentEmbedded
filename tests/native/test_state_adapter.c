/* Link the ACTUAL firmware/main/{state,monitor_model,monitor_schedule}.c and
 * third_party/yyjson/src/yyjson.c. No firmware implementation is replaced.
 * Host dependencies: libbrotlienc, libbrotlidec, libbrotlicommon, libcrypto, m.
 * Compile with -D_POSIX_C_SOURCE=200809L and include tests/stubs first.
 * The optional argv[1] selects one named test. No ESP-IDF or broker needed.
 * Standalone build (from the repository root; also works in the cached
 * nm-http-test-builder image with the repository mounted read-only):
 * cc -std=c17 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Wpedantic -Werror \
 *   -Itests/stubs -Ifirmware/main -Ithird_party/yyjson/src \
 *   tests/native/test_state_adapter.c firmware/main/state.c firmware/main/message_publish.c \
 *   firmware/main/monitor_model.c firmware/main/monitor_numbers.c firmware/main/monitor_schedule.c
 * \
 *   third_party/yyjson/src/yyjson.c \
 *   -lbrotlienc -lbrotlidec -lbrotlicommon -lcrypto -lm -o /tmp/test_state_adapter
 */
#include "nm_esp.h"
#include "message_publish.h"
#include "nm_probe_pool.h"
#include "esp_random.h"
#include "mbedtls/base64.h"
#include <brotli/decode.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x)                                                                                   \
    do {                                                                                           \
        if (!(x)) {                                                                                \
            fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #x);                                \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)
#define GET yyjson_mut_obj_get
#define ROOT yyjson_mut_doc_get_root
#define AT yyjson_mut_arr_get
#define SIZE yyjson_mut_arr_size
#define HIGH_ID UINT64_C(9007199254740993)

static struct {
    const char *key;
    yyjson_mut_doc *doc;
} storage[] = {{"monitoring", NULL}, {"processor", NULL}, {"monitors", NULL}};
static unsigned save_calls, fail_save_at, probe_count;
static bool cycle_active;
static unsigned cycle_save_baseline;
static nm_probe_executor *observed_executor;
static uint32_t random_state;
static yyjson_mut_doc *probes[64];
static nm_esp_result endpoint_result;
struct nm_test_mqtt_client {
    bool fail_alert, fail_data;
};
static struct nm_test_mqtt_client broker;
static struct {
    char *topic, *body;
    bool accepted;
} messages[512];
static size_t message_count;
static nm_esp_config config;

static yyjson_mut_doc *parse(const char *json)
{
    yyjson_mut_doc *d = nm_json_read(json, strlen(json));
    CHECK(d);
    return d;
}
static size_t slot(const char *key)
{
    for (size_t i = 0; i < sizeof(storage) / sizeof(*storage); ++i)
        if (!strcmp(key, storage[i].key))
            return i;
    CHECK(false);
    return 0;
}
/* Round-trip exactly as NVS would: no borrowed values or strings survive. */
static yyjson_mut_doc *clone_serialized(yyjson_mut_val *value)
{
    char *json = yyjson_mut_val_write(value, 0, NULL);
    CHECK(json);
    yyjson_mut_doc *copy = parse(json);
    free(json);
    return copy;
}
bool nm_esp_storage_has_key(const char *key)
{
    return storage[slot(key)].doc != NULL;
}
yyjson_mut_doc *nm_esp_storage_load(const char *key)
{
    yyjson_mut_doc *d = storage[slot(key)].doc;
    return d ? clone_serialized(ROOT(d)) : NULL;
}
bool nm_esp_storage_save(const char *key, yyjson_mut_val *value)
{
    if (cycle_active) {
        CHECK(save_calls == cycle_save_baseline);
        CHECK(!observed_executor || observed_executor->in_flight(observed_executor->context) == 0);
    }
    ++save_calls;
    if (fail_save_at && save_calls == fail_save_at)
        return false;
    yyjson_mut_doc *copy = clone_serialized(value);
    size_t i = slot(key);
    yyjson_mut_doc_free(storage[i].doc);
    storage[i].doc = copy;
    return true;
}
uint32_t esp_random(void)
{
    random_state = random_state * UINT32_C(1664525) + UINT32_C(1013904223);
    return random_state;
}
void esp_fill_random(void *buffer, size_t length)
{
    unsigned char *p = buffer;
    for (size_t i = 0; i < length; ++i)
        p[i] = (unsigned char)(esp_random() >> 24);
}
bool nm_esp_endpoint_supported(const char *type)
{
    return type && (!strcmp(type, "http") || !strcmp(type, "nmap") ||
                    !strcmp(type, "blebroadcastlisten") || !strcmp(type, "blebroadcast"));
}
nm_esp_result nm_esp_endpoint_run(const nm_monitor_record *monitor)
{
    CHECK(!cycle_active || save_calls == cycle_save_baseline);
    CHECK(probe_count < sizeof(probes) / sizeof(*probes));
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    CHECK(doc);
    yyjson_mut_doc_set_root(doc, nm_record_encode(doc, &monitor->base));
    CHECK(ROOT(doc));
    probes[probe_count++] = doc;
    return endpoint_result;
}
int esp_mqtt_client_publish(esp_mqtt_client_handle_t client, const char *topic, const char *data,
                            int len, int qos, int retain)
{
    CHECK(client == &broker && qos == 1 && retain == 0);
    CHECK(len > 0 && len <= NM_ESP_MAX_PUBLICATION && (size_t)len == strlen(data));
    CHECK(message_count < sizeof(messages) / sizeof(*messages));
    if (cycle_active &&
        (!strcmp(topic, "processor/out/data") || !strcmp(topic, "processor/out/status-alerts")))
        CHECK(save_calls == cycle_save_baseline);
    bool failed = (!strcmp(topic, "processor/out/data") && broker.fail_data) ||
                  (!strcmp(topic, "processor/out/status-alerts") && broker.fail_alert);
    messages[message_count].topic = strdup(topic);
    messages[message_count].body = strndup(data, (size_t)len);
    CHECK(messages[message_count].topic && messages[message_count].body);
    messages[message_count++].accepted = !failed;
    return failed ? -1 : (int)message_count;
}
static void clear_messages(void)
{
    for (size_t i = 0; i < message_count; ++i) {
        free(messages[i].topic);
        free(messages[i].body);
    }
    message_count = 0;
}
static void cleanup(void)
{
    clear_messages();
    for (size_t i = 0; i < sizeof(storage) / sizeof(*storage); ++i) {
        yyjson_mut_doc_free(storage[i].doc);
        storage[i].doc = NULL;
    }
    for (unsigned i = 0; i < probe_count; ++i)
        yyjson_mut_doc_free(probes[i]);
    probe_count = 0;
    yyjson_mut_doc_free(config.doc);
    memset(&config, 0, sizeof(config));
}
static void reset(void)
{
    cleanup();
    save_calls = fail_save_at = 0;
    cycle_active = false;
    observed_executor = NULL;
    random_state = 1;
    memset(&broker, 0, sizeof(broker));
    endpoint_result =
        (nm_esp_result){.ok = true, .elapsed_ms = 23, .status = "OK", .message = "reachable"};
    config.doc = parse("{}");
    config.root = ROOT(config.doc);
    config.app_id = "test-app";
    config.auth_key = "test-auth";
    config.source = "host-adapter";
    config.max_monitors = 50;
    config.max_pending_ping_infos = 1000;
}
static yyjson_mut_val *stored(void)
{
    CHECK(storage[0].doc);
    return ROOT(storage[0].doc);
}
static yyjson_mut_val *data(void)
{
    return GET(stored(), "ProcessorData");
}
static yyjson_mut_val *info(void)
{
    return AT(GET(data(), "MonitorPingInfos"), 0);
}
static uint64_t number(yyjson_mut_val *obj, const char *key)
{
    yyjson_mut_val *v = GET(obj, key);
    CHECK(yyjson_mut_is_int(v));
    return yyjson_mut_get_uint(v);
}
static void equal(yyjson_mut_val *a, yyjson_mut_val *b)
{
    CHECK(a && b && yyjson_mut_equals(a, b));
}
static bool cycle(nm_esp_state *s)
{
    cycle_save_baseline = save_calls;
    cycle_active = true;
    bool ok = nm_esp_state_cycle(s, &config, &broker);
    cycle_active = false;
    CHECK(save_calls == cycle_save_baseline + 1);
    return ok;
}
static nm_esp_state *initialized(const char *request)
{
    nm_esp_state *s = nm_esp_state_new(&config);
    CHECK(s);
    yyjson_mut_doc *d = parse(request);
    CHECK(nm_esp_state_init(s, &config, ROOT(d)));
    yyjson_mut_doc_free(d);
    /* Explicit durable fixture baseline, not part of runtime initialization. */
    CHECK(nm_esp_state_save(s));
    return s;
}
static const char *one_enabled = "{\"MonitorIPs\":[{\"ID\":7,\"Address\":\"example.test\","
                                 "\"EndPointType\":\"http\",\"Enabled\":true}]}";
static const char *one_disabled = "{\"MonitorIPs\":[{\"ID\":7,\"Address\":\"example.test\","
                                  "\"EndPointType\":\"http\",\"Enabled\":false}]}";
static size_t topic_count(const char *topic, bool accepted)
{
    size_t n = 0;
    for (size_t i = 0; i < message_count; ++i)
        if (!strcmp(messages[i].topic, topic) && messages[i].accepted == accepted)
            ++n;
    return n;
}
/* Decode the body captured at the MQTT boundary, independently of the encoder. */
static yyjson_mut_doc *decode(size_t index)
{
    CHECK(index < message_count);
    yyjson_mut_doc *event = parse(messages[index].body);
    yyjson_mut_val *root = ROOT(event), *payload = GET(root, "data");
    CHECK(yyjson_mut_equals_str(GET(root, "source"), config.source));
    CHECK(yyjson_mut_equals_str(GET(root, "type"), "ProcessorDataObj"));
    const char *id = yyjson_mut_get_str(GET(root, "id"));
    CHECK(id && strlen(id) == 36 && id[14] == '4' && strchr("89ab", id[19]));
    CHECK(yyjson_mut_get_len(GET(root, "time")) == 20);
    if (!strcmp(messages[index].topic, "processor/out/data")) {
        CHECK(yyjson_mut_equals_str(GET(payload, "Item2"), config.app_id));
        payload = GET(payload, "Item1");
    }
    const char *encoded = yyjson_mut_get_str(payload);
    CHECK(encoded);
    size_t len = strlen(encoded);
    CHECK(len && len % 4 == 0 && len < NM_ESP_MAX_PUBLICATION);
    unsigned char *compressed = malloc(len);
    CHECK(compressed);
    int bytes = EVP_DecodeBlock(compressed, (const unsigned char *)encoded, (int)len);
    CHECK(bytes > 0);
    if (encoded[len - 1] == '=')
        --bytes;
    if (encoded[len - 2] == '=')
        --bytes;
    size_t capacity = 512 * 1024;
    unsigned char *json = malloc(capacity);
    CHECK(json);
    CHECK(BrotliDecoderDecompress((size_t)bytes, compressed, &capacity, json) ==
          BROTLI_DECODER_RESULT_SUCCESS);
    yyjson_mut_doc *d = nm_json_read((const char *)json, capacity);
    CHECK(d);
    CHECK(yyjson_mut_equals_str(GET(ROOT(d), "AppID"), config.app_id));
    CHECK(yyjson_mut_equals_str(GET(ROOT(d), "AuthKey"), config.auth_key));
    free(json);
    free(compressed);
    yyjson_mut_doc_free(event);
    return d;
}
static void test_base64(void)
{
    static const char *plain[] = {"", "f", "fo", "foo", "foob", "fooba", "foobar"};
    static const char *encoded[] = {"", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy"};
    for (size_t i = 0; i < sizeof(plain) / sizeof(*plain); ++i) {
        unsigned char out[32] = {0};
        size_t n = 999;
        CHECK(!mbedtls_base64_encode(out, sizeof(out), &n, (const unsigned char *)plain[i],
                                     strlen(plain[i])));
        CHECK(n == strlen(encoded[i]) && !strcmp((char *)out, encoded[i]));
    }
    size_t n = 0;
    CHECK(mbedtls_base64_encode(NULL, 0, &n, (const unsigned char *)"f", 1) ==
          MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL);
    CHECK(n == 5);
}
static void test_storage_clones(void)
{
    reset();
    yyjson_mut_doc *d = parse("{\"nested\":{\"text\":\"original\"}}");
    CHECK(nm_esp_storage_save("processor", ROOT(d)));
    CHECK(nm_json_put_str(d, GET(ROOT(d), "nested"), "text", "changed"));
    yyjson_mut_doc_free(d);
    d = nm_esp_storage_load("processor");
    CHECK(yyjson_mut_equals_str(GET(GET(ROOT(d), "nested"), "text"), "original"));
    CHECK(nm_json_put_str(d, GET(ROOT(d), "nested"), "text", "load changed"));
    yyjson_mut_doc *again = nm_esp_storage_load("processor");
    CHECK(yyjson_mut_equals_str(GET(GET(ROOT(again), "nested"), "text"), "original"));
    yyjson_mut_doc_free(d);
    yyjson_mut_doc_free(again);
}
static void test_legacy_migration(void)
{
    reset();
    storage[1].doc = parse("{\"PiIDKey\":4294967295,\"PingInfos\":[{\"ID\":9007199254740993,"
                           "\"MonitorPingInfoID\":7,\"Status\":\"legacy\"}],\"MonitorPingInfos\":[{"
                           "\"MonitorIPID\":7,\"Enabled\":false,\"EndPointType\":\"http\"}]}");
    storage[2].doc = parse(
        "[{\"ID\":7,\"Address\":\"legacy.test\",\"EndPointType\":\"http\",\"Enabled\":false}]");
    fail_save_at = 1;
    nm_esp_state *s = nm_esp_state_new(&config);
    CHECK(s && !storage[0].doc && save_calls == 0);
    CHECK(!cycle(s)); /* migration is first saved at cycle completion */
    CHECK(!storage[0].doc);
    fail_save_at = 0;
    clear_messages();
    CHECK(cycle(s));
    CHECK(number(data(), "PiIDKey") == UINT32_MAX);
    CHECK(number(AT(GET(data(), "PingInfos"), 0), "ID") == HIGH_ID);
    CHECK(nm_esp_state_monitor_count(s) == SIZE(ROOT(storage[2].doc)));
    yyjson_mut_doc *snapshot = clone_serialized(stored());
    /* Once migrated, the snapshot takes precedence over stale legacy keys. */
    yyjson_mut_doc_free(storage[1].doc);
    storage[1].doc = parse("{}");
    nm_esp_state_free(s);
    unsigned saves = save_calls;
    s = nm_esp_state_new(&config);
    CHECK(s && save_calls == saves);
    CHECK(nm_esp_state_save(s));
    equal(stored(), ROOT(snapshot));
    yyjson_mut_doc_free(snapshot);
    nm_esp_state_free(s);
}
static void test_orphan_boot_refused(void)
{
    for (unsigned variant = 0; variant < 3; ++variant) {
        reset();
        storage[1].doc = parse("{\"PiIDKey\":2,\"PingInfos\":[{\"ID\":9007199254740993,"
                               "\"MonitorPingInfoID\":7}],\"MonitorPingInfos\":[]}");
        if (variant == 1)
            storage[2].doc = parse("[{\"ID\":8,\"Address\":\"unrelated.test\",\"EndPointType\":"
                                   "\"http\",\"Enabled\":false}]");
        if (variant == 2) {
            /* Apply the same fail-closed rule to an already migrated snapshot. */
            yyjson_mut_doc *legacy = storage[1].doc;
            storage[1].doc = NULL;
            nm_esp_state *s = nm_esp_state_new(&config);
            CHECK(s);
            CHECK(nm_esp_state_save(s)); /* construct the already-migrated fixture */
            nm_esp_state_free(s);
            CHECK(nm_json_put(
                storage[0].doc, GET(stored(), "ProcessorData"), "PingInfos",
                yyjson_mut_val_mut_copy(storage[0].doc, GET(ROOT(legacy), "PingInfos"))));
            storage[1].doc = legacy;
        }
        yyjson_mut_doc *before[3] = {NULL};
        for (size_t i = 0; i < 3; ++i)
            if (storage[i].doc)
                before[i] = clone_serialized(ROOT(storage[i].doc));
        unsigned saves = save_calls;
        CHECK(!nm_esp_state_new(&config));
        CHECK(save_calls == saves && probe_count == 0 && message_count == 0);
        for (size_t i = 0; i < 3; ++i) {
            if (before[i])
                equal(ROOT(storage[i].doc), ROOT(before[i]));
            else
                CHECK(!storage[i].doc);
            yyjson_mut_doc_free(before[i]);
        }
    }
}
static void test_saved_host_rebuilds_parent(void)
{
    reset();
    storage[1].doc =
        parse("{\"PiIDKey\":2,\"PingInfos\":[{\"ID\":9007199254740993,\"MonitorPingInfoID\":7,"
              "\"Status\":\"legacy\"}],\"MonitorPingInfos\":[]}");
    storage[2].doc = parse(
        "[{\"ID\":7,\"Address\":\"recovered.test\",\"EndPointType\":\"http\",\"Enabled\":false}]");
    yyjson_mut_doc *pending = clone_serialized(GET(ROOT(storage[1].doc), "PingInfos"));
    nm_esp_state *s = nm_esp_state_new(&config);
    CHECK(s);
    CHECK(!storage[0].doc); /* migration does not write at boot */
    CHECK(cycle(s) && probe_count == 0 && message_count == 1);
    CHECK(SIZE(GET(data(), "MonitorPingInfos")) == 1 && number(info(), "MonitorIPID") == 7);
    CHECK(yyjson_mut_equals_str(GET(info(), "Address"), "recovered.test"));
    equal(GET(data(), "PingInfos"), ROOT(pending));
    yyjson_mut_doc *wire = decode(0);
    equal(GET(ROOT(wire), "PingInfos"), ROOT(pending));
    equal(AT(GET(ROOT(wire), "MonitorPingInfos"), 0), info());
    yyjson_mut_doc_free(wire);
    nm_esp_state_free(s);
    /* Once rebuilt, the aggregate alone is sufficient even without a host. */
    CHECK(yyjson_mut_arr_clear(GET(stored(), "MonitorIPs")));
    s = nm_esp_state_new(&config);
    CHECK(s);
    clear_messages();
    CHECK(cycle(s) && probe_count == 0 && message_count == 1);
    wire = decode(0);
    equal(GET(ROOT(wire), "PingInfos"), ROOT(pending));
    yyjson_mut_doc_free(wire);
    yyjson_mut_doc *ack = parse("{\"RemovePingInfos\":[{\"ID\":9007199254740993}]}");
    unsigned saves = save_calls;
    CHECK(nm_esp_state_ack(s, ROOT(ack)) && save_calls == saves);
    clear_messages();
    CHECK(cycle(s) && SIZE(GET(data(), "PingInfos")) == 0);
    yyjson_mut_doc_free(ack);
    yyjson_mut_doc_free(pending);
    nm_esp_state_free(s);
}
static void test_fresh_disabled(void)
{
    reset();
    nm_esp_state *s = initialized(one_disabled);
    CHECK(number(data(), "PiIDKey") == 1 && SIZE(GET(data(), "PingInfos")) == 0);
    CHECK(SIZE(GET(data(), "MonitorPingInfos")) == 1);
    CHECK(number(info(), "Timeout") == 59000 && number(info(), "RoundTripTimeMinimum") == 9999);
    CHECK(number(info(), "PacketsSent") == 0);
    CHECK(yyjson_mut_is_null(GET(GET(info(), "MonitorStatus"), "IsUp")));
    CHECK(yyjson_mut_is_null(GET(GET(info(), "MonitorStatus"), "EventTime")));
    CHECK(cycle(s) && probe_count == 0 && message_count == 1);
    yyjson_mut_doc *wire = decode(0);
    equal(AT(GET(ROOT(wire), "MonitorPingInfos"), 0), info());
    CHECK(SIZE(GET(ROOT(wire), "PingInfos")) == 0);
    yyjson_mut_doc_free(wire);
    nm_esp_state_free(s);
}
static void test_live_defaults(void)
{
    reset();
    nm_esp_state *s = initialized(one_enabled);
    CHECK(cycle(s) && probe_count == 1);
    CHECK(number(ROOT(probes[0]), "Timeout") == 59000);
    CHECK(yyjson_mut_equals_str(GET(ROOT(probes[0]), "Host"), "example.test"));
    CHECK(number(info(), "PacketsSent") == 1 && number(info(), "PacketsRecieved") == 1);
    CHECK(SIZE(GET(data(), "PingInfos")) == 1 && number(data(), "PiIDKey") == 2);
    CHECK(topic_count("processor/out/status-alerts", true) == 1 &&
          topic_count("processor/out/data", true) == 1);
    for (size_t i = 0; i < message_count; ++i) {
        yyjson_mut_doc *wire = decode(i);
        if (!strcmp(messages[i].topic, "processor/out/data")) {
            equal(GET(ROOT(wire), "PingInfos"), GET(data(), "PingInfos"));
            CHECK(number(AT(GET(ROOT(wire), "PingInfos"), 0), "RoundTripTime") == 23);
        } else {
            yyjson_mut_val *alert = AT(GET(ROOT(wire), "MonitorStatusAlerts"), 0);
            CHECK(number(alert, "ID") == 7 && yyjson_mut_is_true(GET(alert, "IsUp")));
            CHECK(number(alert, "Timeout") == 59000);
        }
        yyjson_mut_doc_free(wire);
    }
    /* Broker acceptance alone must not acknowledge a sample. */
    CHECK(SIZE(GET(data(), "PingInfos")) == 1);
    clear_messages();
    endpoint_result.ok = false;
    endpoint_result.elapsed_ms = 80000;
    CHECK(cycle(s) && probe_count == 2);
    CHECK(number(info(), "PacketsLost") == 1 &&
          number(GET(info(), "MonitorStatus"), "DownCount") == 1);
    CHECK(number(AT(GET(data(), "PingInfos"), 1), "RoundTripTime") == UINT16_MAX);
    nm_esp_state_free(s);
}
static void test_independent_publish_failures(void)
{
    for (unsigned mode = 0; mode < 3; ++mode) {
        reset();
        nm_esp_state *s = initialized(one_enabled);
        broker.fail_alert = mode != 1;
        broker.fail_data = mode != 0;
        CHECK(!cycle(s));
        CHECK(probe_count == 1 && SIZE(GET(data(), "PingInfos")) == 1);
        CHECK(topic_count("processor/out/status-alerts", !broker.fail_alert) == 1);
        CHECK(topic_count("processor/out/data", !broker.fail_data) == 1);
        for (size_t i = 0; i < message_count; ++i)
            yyjson_mut_doc_free(decode(i));
        clear_messages();
        broker.fail_alert = broker.fail_data = false;
        config.max_pending_ping_infos = 1; /* Retry without taking another sample. */
        CHECK(cycle(s) && probe_count == 1 && SIZE(GET(data(), "PingInfos")) == 1);
        CHECK(topic_count("processor/out/status-alerts", true) == 1 &&
              topic_count("processor/out/data", true) == 1);
        nm_esp_state_free(s);
    }
}
static nm_esp_state *seed_pings_with_status(size_t count, uint64_t first, bool large)
{
    nm_esp_state *s = initialized(one_disabled);
    nm_esp_state_free(s);
    yyjson_mut_doc *d = storage[0].doc;
    for (size_t i = 0; i < count; ++i) {
        yyjson_mut_val *p = yyjson_mut_obj(d);
        CHECK(yyjson_mut_obj_add_uint(d, p, "ID", first + i));
        CHECK(yyjson_mut_obj_add_int(d, p, "MonitorPingInfoID", 7));
        CHECK(yyjson_mut_obj_add_uint(d, p, "RoundTripTime", 23));
        char status[1025] = "pending fixture";
        if (large) {
            uint32_t seed = (uint32_t)i + 1;
            for (size_t byte = 0; byte < sizeof(status) - 1; ++byte) {
                seed = seed * UINT32_C(1664525) + UINT32_C(1013904223);
                status[byte] = (char)('a' + (seed >> 24) % 26);
            }
            status[sizeof(status) - 1] = 0;
        }
        CHECK(yyjson_mut_obj_add_strcpy(d, p, "Status", status));
        CHECK(yyjson_mut_arr_append(GET(data(), "PingInfos"), p));
    }
    s = nm_esp_state_new(&config);
    CHECK(s);
    return s;
}
static nm_esp_state *seed_pings(size_t count, uint64_t first)
{
    return seed_pings_with_status(count, first, false);
}
static void test_publication_size_split(void)
{
    reset();
    nm_esp_state *s = seed_pings_with_status(500, HIGH_ID, true);
    CHECK(cycle(s));
    CHECK(topic_count("processor/out/data", true) > 1);
    bool seen[500] = {false};
    size_t total = 0;
    for (size_t i = 0; i < message_count; ++i) {
        CHECK(strlen(messages[i].body) <= NM_ESP_MAX_PUBLICATION);
        yyjson_mut_doc *wire = decode(i);
        yyjson_mut_val *pings = GET(ROOT(wire), "PingInfos");
        for (size_t j = 0; j < SIZE(pings); ++j) {
            uint64_t id = number(AT(pings, j), "ID");
            CHECK(id >= HIGH_ID && id < HIGH_ID + 500);
            CHECK(!seen[id - HIGH_ID]);
            seen[id - HIGH_ID] = true;
            ++total;
        }
        yyjson_mut_doc_free(wire);
    }
    CHECK(total == 500 && SIZE(GET(data(), "PingInfos")) == 500);
    nm_esp_state_free(s);
}
static void test_batch_500(void)
{
    reset();
    nm_esp_state *s = seed_pings(500, HIGH_ID);
    yyjson_mut_doc *before = clone_serialized(data());
    CHECK(cycle(s) && probe_count == 0);
    CHECK(topic_count("processor/out/data", true) >= 1 && message_count >= 1);
    bool seen[500] = {false};
    size_t total = 0;
    for (size_t i = 0; i < message_count; ++i) {
        yyjson_mut_doc *wire = decode(i);
        yyjson_mut_val *pings = GET(ROOT(wire), "PingInfos");
        CHECK(SIZE(pings) <= 500);
        CHECK(SIZE(GET(ROOT(wire), "MonitorPingInfos")) >= 1);
        CHECK(number(AT(GET(ROOT(wire), "MonitorPingInfos"), 0), "MonitorIPID") == 7);
        for (size_t j = 0; j < SIZE(pings); ++j) {
            uint64_t id = number(AT(pings, j), "ID");
            CHECK(id >= HIGH_ID && id < HIGH_ID + 500);
            size_t offset = (size_t)(id - HIGH_ID);
            CHECK(!seen[offset]);
            seen[offset] = true;
            ++total;
            equal(AT(pings, j), AT(GET(ROOT(before), "PingInfos"), offset));
        }
        yyjson_mut_doc_free(wire);
    }
    CHECK(total == 500);
    equal(data(), ROOT(before));
    CHECK(nm_esp_state_save(s));
    equal(data(), ROOT(before));
    yyjson_mut_doc_free(before);
    nm_esp_state_free(s);
}
static void test_zero_monitors_retry(void)
{
    reset();
    nm_esp_state *s = initialized(one_enabled);
    broker.fail_data = true;
    CHECK(!cycle(s));
    yyjson_mut_doc *updates = parse("[{\"ID\":7,\"Delete\":true}]");
    CHECK(nm_esp_state_updates(s, &config, ROOT(updates)));
    yyjson_mut_doc_free(updates);
    CHECK(nm_esp_state_monitor_count(s) == 0);
    clear_messages();
    broker.fail_data = false;
    CHECK(cycle(s) && probe_count == 1);
    CHECK(topic_count("processor/out/data", true) == 1);
    for (size_t i = 0; i < message_count; ++i) {
        yyjson_mut_doc *wire = decode(i);
        if (!strcmp(messages[i].topic, "processor/out/data")) {
            CHECK(SIZE(GET(ROOT(wire), "PingInfos")) == 1);
            CHECK(SIZE(GET(ROOT(wire), "RemoveMonitorPingInfoIDs")) == 1);
        }
        yyjson_mut_doc_free(wire);
    }
    CHECK(SIZE(GET(data(), "PingInfos")) == 1);
    nm_esp_state_free(s);
    reset();
    s = nm_esp_state_new(&config);
    CHECK(s && cycle(s));
    CHECK(probe_count == 0 && message_count == 1);
    yyjson_mut_doc *wire = decode(0);
    CHECK(SIZE(GET(ROOT(wire), "PingInfos")) == 0);
    yyjson_mut_doc_free(wire);
    nm_esp_state_free(s);
}
static void test_storage_failure(void)
{
    reset();
    nm_esp_state *s = initialized(one_enabled);
    yyjson_mut_doc *before = clone_serialized(stored());
    for (unsigned attempt = 1; attempt <= 2; ++attempt) {
        fail_save_at = save_calls + 1;
        clear_messages();
        CHECK(!cycle(s));
        CHECK(probe_count == attempt);
        equal(stored(), ROOT(before)); /* failed NVS write retains old snapshot */
        bool saw_data = false;
        for (size_t i = 0; i < message_count; ++i) {
            if (strcmp(messages[i].topic, "processor/out/data"))
                continue;
            yyjson_mut_doc *wire = decode(i);
            CHECK(SIZE(GET(ROOT(wire), "PingInfos")) == attempt);
            yyjson_mut_doc_free(wire);
            saw_data = true;
        }
        CHECK(saw_data); /* live results survive and delivery still proceeds */
    }
    fail_save_at = 0;
    clear_messages();
    CHECK(cycle(s));
    CHECK(SIZE(GET(data(), "PingInfos")) == 3);
    yyjson_mut_doc_free(before);
    before = clone_serialized(stored());
    yyjson_mut_doc *ack = parse("{\"RemovePingInfos\":[{\"ID\":1}]}");
    unsigned saves = save_calls;
    fail_save_at = saves + 1;
    CHECK(nm_esp_state_ack(s, ROOT(ack)) && save_calls == saves);
    equal(stored(), ROOT(before));
    clear_messages();
    CHECK(!cycle(s)); /* save fails, but RAM acknowledgement is not undone */
    equal(stored(), ROOT(before));
    fail_save_at = 0;
    clear_messages();
    CHECK(cycle(s));
    CHECK(SIZE(GET(data(), "PingInfos")) == 4); /* five probes, one acknowledged */
    for (size_t i = 0; i < SIZE(GET(data(), "PingInfos")); ++i)
        CHECK(number(AT(GET(data(), "PingInfos"), i), "ID") != 1);
    yyjson_mut_doc_free(ack);
    yyjson_mut_doc_free(before);
    nm_esp_state_free(s);
}
static void test_high_ids(void)
{
    reset();
    nm_esp_state *s = seed_pings(2, HIGH_ID);
    nm_esp_state_free(s);
    CHECK(nm_json_put(storage[0].doc, AT(GET(data(), "PingInfos"), 1), "ID",
                      yyjson_mut_uint(storage[0].doc, UINT64_MAX)));
    s = nm_esp_state_new(&config);
    CHECK(s && cycle(s));
    yyjson_mut_doc *wire = decode(0);
    CHECK(number(AT(GET(ROOT(wire), "PingInfos"), 0), "ID") == HIGH_ID);
    CHECK(number(AT(GET(ROOT(wire), "PingInfos"), 1), "ID") == UINT64_MAX);
    yyjson_mut_doc_free(wire);
    yyjson_mut_doc *ack = parse("{\"RemovePingInfos\":[{\"ID\":9007199254740992}]}");
    CHECK(nm_esp_state_ack(s, ROOT(ack)) && SIZE(GET(data(), "PingInfos")) == 2);
    yyjson_mut_doc_free(ack);
    ack = parse("{\"RemovePingInfos\":[{\"ID\":9007199254740993}]}");
    unsigned saves = save_calls;
    CHECK(nm_esp_state_ack(s, ROOT(ack)) && save_calls == saves);
    CHECK(SIZE(GET(data(), "PingInfos")) == 2); /* not durable until the cycle */
    clear_messages();
    CHECK(cycle(s) && SIZE(GET(data(), "PingInfos")) == 1);
    CHECK(number(AT(GET(data(), "PingInfos"), 0), "ID") == UINT64_MAX);
    yyjson_mut_doc_free(ack);
    nm_esp_state_free(s);
    s = nm_esp_state_new(&config);
    CHECK(s && nm_esp_state_save(s));
    CHECK(number(AT(GET(data(), "PingInfos"), 0), "ID") == UINT64_MAX);
    ack = parse("{\"RemovePingInfos\":[{\"ID\":18446744073709551615}]}");
    saves = save_calls;
    CHECK(nm_esp_state_ack(s, ROOT(ack)) && save_calls == saves);
    clear_messages();
    CHECK(cycle(s) && SIZE(GET(data(), "PingInfos")) == 0);
    yyjson_mut_doc_free(ack);
    nm_esp_state_free(s);
}
struct yield_context {
    nm_esp_state *state;
    unsigned calls;
    bool stop;
};
static bool yield_commands(void *opaque)
{
    struct yield_context *ctx = opaque;
    ++ctx->calls;
    if (ctx->calls == 1) {
        CHECK(probe_count == 0);
        return true;
    }
    if (ctx->calls > 3 || (ctx->stop && ctx->calls >= 2))
        return !ctx->stop; /* publication command checkpoints */
    CHECK(probe_count == 1 && SIZE(GET(data(), "PingInfos")) == 0);
    if (ctx->stop)
        return false;
    if (ctx->calls == 2) {
        yyjson_mut_doc *updates =
            parse("[{\"ID\":8,\"Delete\":true},{\"ID\":9,\"Address\":\"changed.test\","
                  "\"EndPointType\":\"http\",\"Enabled\":true,\"Timeout\":1234}]");
        CHECK(nm_esp_state_updates(ctx->state, &config, ROOT(updates)));
        yyjson_mut_doc_free(updates);
    }
    return true;
}
static void test_yield_between_probes(void)
{
    for (unsigned stop = 0; stop < 2; ++stop) {
        reset();
        nm_esp_state *s =
            initialized("{\"MonitorIPs\":[{\"ID\":7,\"Address\":\"first.test\",\"EndPointType\":"
                        "\"http\",\"Enabled\":true},{\"ID\":8,\"Address\":\"second.test\","
                        "\"EndPointType\":\"http\",\"Enabled\":true},{\"ID\":9,\"Address\":\"third."
                        "test\",\"EndPointType\":\"http\",\"Enabled\":true}]}");
        struct yield_context ctx = {.state = s, .stop = stop != 0};
        nm_esp_state_set_yield(s, yield_commands, &ctx);
        CHECK(cycle(s) == !stop);
        CHECK(ctx.calls >= (stop ? 2u : 3u) && probe_count == (stop ? 1u : 2u));
        if (!stop) {
            CHECK(number(ROOT(probes[1]), "MonitorIPID") == 9);
            CHECK(number(ROOT(probes[1]), "Timeout") == 1234);
            CHECK(yyjson_mut_equals_str(GET(ROOT(probes[1]), "Address"), "changed.test"));
        }
        CHECK(SIZE(GET(data(), "PingInfos")) == probe_count);
        nm_esp_state_free(s);
    }
}
static void test_message_publication(void)
{
    reset();
    yyjson_mut_doc *payload = parse("{\"ID\":18446744073709551615,\"Nullable\":null}");
    CHECK(yyjson_mut_obj_add_strcpy(payload, ROOT(payload), "AppID", config.app_id));
    CHECK(yyjson_mut_obj_add_strcpy(payload, ROOT(payload), "AuthKey", config.auth_key));
    for (unsigned mode = NM_MESSAGE_JSON; mode <= NM_MESSAGE_BROTLI_TUPLE; ++mode) {
        clear_messages();
        const char *topic =
            mode == NM_MESSAGE_BROTLI_TUPLE ? "processor/out/data" : "processor/out/status-alerts";
        CHECK(nm_esp_publish_event(&config, &broker, topic, ROOT(payload),
                                   (nm_message_encoding)mode, "ProcessorDataObj"));
        CHECK(message_count == 1);
        yyjson_mut_doc *event = parse(messages[0].body);
        CHECK(yyjson_mut_equals_str(GET(ROOT(event), "specversion"), ""));
        CHECK(yyjson_mut_equals_str(GET(ROOT(event), "datacontenttype"), ""));
        CHECK(yyjson_mut_equals_str(GET(ROOT(event), "type"), "ProcessorDataObj"));
        CHECK(yyjson_mut_equals_str(GET(ROOT(event), "source"), config.source));
        if (mode == NM_MESSAGE_JSON)
            equal(GET(ROOT(event), "data"), ROOT(payload));
        else {
            yyjson_mut_doc *decoded = decode(0);
            equal(ROOT(decoded), ROOT(payload));
            yyjson_mut_doc_free(decoded);
        }
        yyjson_mut_doc_free(event);
    }
    clear_messages();
    CHECK(!nm_esp_publish_event(&config, &broker, "processor/out/data", ROOT(payload),
                                (nm_message_encoding)99, "ProcessorDataObj"));
    CHECK(message_count == 0);
    broker.fail_data = true;
    CHECK(!nm_esp_publish_event(&config, &broker, "processor/out/data", ROOT(payload),
                                NM_MESSAGE_BROTLI_TUPLE, "ProcessorDataObj"));
    CHECK(message_count == 1 && !messages[0].accepted);
    /* Publishing never transfers or edits the caller's document. */
    CHECK(number(ROOT(payload), "ID") == UINT64_MAX &&
          yyjson_mut_is_null(GET(ROOT(payload), "Nullable")));
    yyjson_mut_doc_free(payload);

    clear_messages();
    payload = yyjson_mut_doc_new(NULL);
    CHECK(payload);
    char *oversized = malloc(512 * 1024 + 2);
    CHECK(oversized);
    memset(oversized, 'x', 512 * 1024 + 1);
    oversized[512 * 1024 + 1] = 0;
    yyjson_mut_doc_set_root(payload, yyjson_mut_strcpy(payload, oversized));
    free(oversized);
    CHECK(ROOT(payload));
    CHECK(!nm_esp_publish_event(&config, &broker, "processor/out/data", ROOT(payload),
                                NM_MESSAGE_JSON, "ProcessorDataObj"));
    CHECK(!nm_esp_publish_event(&config, &broker, "processor/out/data", ROOT(payload),
                                NM_MESSAGE_BROTLI_TUPLE, "ProcessorDataObj"));
    CHECK(message_count == 0);
    yyjson_mut_doc_free(payload);
}

/* Deterministic fake probe executor. It records submitted monitor ids and
 * answers them immediately (optionally last-in-first-out) so the concurrent
 * cycle path is exercised without real tasks or timing. */
struct fake_executor {
    int capacity;
    nm_probe_reply queue[256];
    size_t head, tail;
    bool lifo, fail_submit;
    unsigned submits;
    bool local_failure;
    unsigned delayed_polls;
};
static bool fake_submit(void *context, int32_t monitor_id, uint64_t generation,
                        const nm_monitor_record *monitor)
{
    struct fake_executor *f = context;
    (void)monitor;
    CHECK(!cycle_active || save_calls == cycle_save_baseline);
    if (f->fail_submit)
        return false;
    CHECK(f->tail - f->head < (size_t)f->capacity);
    CHECK(f->tail < sizeof(f->queue) / sizeof(*f->queue));
    f->queue[f->tail++] = (nm_probe_reply){.monitor_id = monitor_id, .generation = generation};
    ++f->submits;
    return true;
}
static bool fake_poll(void *context, nm_probe_reply *reply, uint32_t timeout_ms)
{
    CHECK(!cycle_active || save_calls == cycle_save_baseline);
    (void)timeout_ms;
    struct fake_executor *f = context;
    if (f->head == f->tail)
        return false;
    if (f->delayed_polls) {
        --f->delayed_polls;
        return false;
    }
    *reply = f->lifo ? f->queue[--f->tail] : f->queue[f->head++];
    reply->result = endpoint_result;
    if (f->local_failure)
        reply->result =
            (nm_esp_result){.disposition = NM_PROBE_LOCAL_FAILURE, .message = "injected OOM"};
    return true;
}
static int fake_in_flight(const void *context)
{
    return (int)(((const struct fake_executor *)context)->tail -
                 ((const struct fake_executor *)context)->head);
}
static void fake_destroy(void *context)
{
    if (observed_executor && observed_executor->context == context)
        observed_executor = NULL;
    free(context);
}
static nm_probe_executor *fake_executor_new(int capacity, bool lifo, bool fail_submit)
{
    struct fake_executor *f = calloc(1, sizeof(*f));
    CHECK(f);
    f->capacity = capacity;
    f->lifo = lifo;
    f->fail_submit = fail_submit;
    nm_probe_executor *e = calloc(1, sizeof(*e));
    CHECK(e);
    e->capacity = capacity;
    e->submit = fake_submit;
    e->poll = fake_poll;
    e->in_flight = fake_in_flight;
    e->destroy = fake_destroy;
    e->context = f;
    observed_executor = e;
    return e;
}
static yyjson_mut_val *info_by_id(int32_t id)
{
    yyjson_mut_val *arr = GET(data(), "MonitorPingInfos");
    for (size_t i = 0; i < SIZE(arr); ++i)
        if (number(AT(arr, i), "MonitorIPID") == (uint64_t)id)
            return AT(arr, i);
    return NULL;
}
static const char *three_enabled =
    "{\"MonitorIPs\":[{\"ID\":7,\"Address\":\"a.test\",\"EndPointType\":\"http\",\"Enabled\":true},"
    "{\"ID\":8,\"Address\":\"b.test\",\"EndPointType\":\"http\",\"Enabled\":true},"
    "{\"ID\":9,\"Address\":\"c.test\",\"EndPointType\":\"http\",\"Enabled\":true}]}";
/* Every enabled monitor is probed once and committed, in both reply orders. */
static void test_concurrent_probes(void)
{
    const int capacities[] = {1, 4, 8};
    for (unsigned mode = 0; mode < 6; ++mode) {
        reset();
        nm_esp_state *s = initialized(three_enabled);
        nm_esp_state_set_probe_executor(
            s, fake_executor_new(capacities[mode / 2], mode % 2 != 0, false));
        CHECK(cycle(s));
        CHECK(probe_count == 0); /* endpoint ran in the executor, not inline */
        CHECK(SIZE(GET(data(), "PingInfos")) == 3);
        for (int32_t id = 7; id <= 9; ++id) {
            yyjson_mut_val *m = info_by_id(id);
            CHECK(m && number(m, "PacketsSent") == 1 && number(m, "PacketsRecieved") == 1);
        }
        nm_esp_state_free(s);
    }
}
struct concurrent_yield {
    unsigned calls, allow;
};
static bool concurrent_yield_cb(void *opaque)
{
    struct concurrent_yield *y = opaque;
    return ++y->calls <= y->allow;
}
/* yield() gates dispatch; in-flight probes are still reaped before returning. */
static void test_concurrent_yield(void)
{
    for (unsigned allow = 0; allow < 3; ++allow) {
        reset();
        struct concurrent_yield y = {.allow = allow};
        nm_esp_state *s = initialized(three_enabled);
        nm_esp_state_set_yield(s, concurrent_yield_cb, &y);
        nm_esp_state_set_probe_executor(s, fake_executor_new(2, false, false));
        CHECK(!cycle(s)); /* cancelled publication, accepted probes still drained */
        CHECK(SIZE(GET(data(), "PingInfos")) == (allow == 0 ? 0 : allow));
        nm_esp_state_free(s);
    }
}
/* The pending-ping limit pauses dispatch without losing an in-flight probe. */
static void test_concurrent_pending_limit(void)
{
    reset();
    config.max_pending_ping_infos = 1;
    nm_esp_state *s = initialized(three_enabled);
    nm_esp_state_set_probe_executor(s, fake_executor_new(2, false, false));
    CHECK(cycle(s));
    CHECK(SIZE(GET(data(), "PingInfos")) == 1);
    nm_esp_state_free(s);
}
/* A refused submission fails the cycle closed and commits nothing. */
static void test_concurrent_submit_failure(void)
{
    reset();
    nm_esp_state *s = initialized(three_enabled);
    nm_esp_state_set_probe_executor(s, fake_executor_new(2, false, true));
    CHECK(!cycle(s));
    CHECK(SIZE(GET(data(), "PingInfos")) == 0);
    nm_esp_state_free(s);
}
static void test_local_failure(void)
{
    for (unsigned concurrent = 0; concurrent < 2; ++concurrent) {
        reset();
        nm_esp_state *s = initialized(three_enabled);
        nm_probe_executor *e = NULL;
        if (concurrent) {
            e = fake_executor_new(2, false, false);
            ((struct fake_executor *)e->context)->local_failure = true;
            nm_esp_state_set_probe_executor(s, e);
        }
        endpoint_result = (nm_esp_result){.disposition = NM_PROBE_LOCAL_FAILURE};
        CHECK(!cycle(s));
        CHECK(SIZE(GET(data(), "PingInfos")) == 0);
        for (int32_t id = 7; id <= 9; ++id) {
            CHECK(number(info_by_id(id), "PacketsSent") == 0);
            CHECK(number(info_by_id(id), "PacketsLost") == 0);
            CHECK(number(GET(info_by_id(id), "MonitorStatus"), "DownCount") == 0);
        }
        if (e) {
            CHECK(e->in_flight(e->context) == 0);
            ((struct fake_executor *)e->context)->local_failure = false;
        }
        endpoint_result = (nm_esp_result){.ok = true, .status = "OK"};
        CHECK(cycle(s)); /* later scheduled cycle recovers, no busy retry */
        CHECK(SIZE(GET(data(), "PingInfos")) == 3);
        nm_esp_state_free(s);
    }
}
struct changing_host {
    nm_esp_state *state;
    struct fake_executor *executor;
    bool changed;
};
static bool change_during_wait(void *context)
{
    struct changing_host *c = context;
    if (c->executor->submits == 2 && c->executor->delayed_polls < 3 && !c->changed) {
        yyjson_mut_doc *request = parse(three_enabled);
        CHECK(nm_esp_state_init(c->state, &config, ROOT(request)));
        yyjson_mut_doc_free(request);
        c->changed = true;
    }
    return true;
}
static void test_configuration_during_wait(void)
{
    reset();
    nm_esp_state *s = initialized(three_enabled);
    nm_probe_executor *e = fake_executor_new(2, false, false);
    struct fake_executor *f = e->context;
    f->delayed_polls = 3;
    struct changing_host c = {.state = s, .executor = f};
    nm_esp_state_set_probe_executor(s, e);
    nm_esp_state_set_yield(s, change_during_wait, &c);
    CHECK(cycle(s));
    CHECK(c.changed);
    CHECK(f->submits == 2 && e->in_flight(e->context) == 0);
    CHECK(SIZE(GET(data(), "PingInfos")) == 0);
    nm_esp_state_set_yield(s, NULL, NULL);
    CHECK(cycle(s));
    CHECK(SIZE(GET(data(), "PingInfos")) == 3);
    nm_esp_state_free(s);
}
static void host_cycles(unsigned count)
{
    reset();
    config.max_monitors = count;
    config.max_pending_ping_infos = count * 10;
    yyjson_mut_doc *request = nm_json_new();
    CHECK(request);
    yyjson_mut_val *root = yyjson_mut_obj(request), *hosts = yyjson_mut_arr(request);
    yyjson_mut_doc_set_root(request, root);
    CHECK(root && hosts && yyjson_mut_obj_add_val(request, root, "MonitorIPs", hosts));
    for (int id = 100; id < 100 + (int)count; ++id) {
        yyjson_mut_val *host = yyjson_mut_obj(request);
        CHECK(host && yyjson_mut_obj_add_int(request, host, "ID", id));
        CHECK(yyjson_mut_obj_add_str(request, host, "Address", "example.test"));
        CHECK(yyjson_mut_obj_add_str(request, host, "EndPointType", "http"));
        CHECK(yyjson_mut_obj_add_bool(request, host, "Enabled", true));
        CHECK(yyjson_mut_obj_add_str(request, host, "Username", ""));
        CHECK(yyjson_mut_obj_add_str(request, host, "Password", ""));
        CHECK(yyjson_mut_arr_append(hosts, host));
    }
    nm_esp_state *s = nm_esp_state_new(&config);
    CHECK(s);
    CHECK(nm_esp_state_init(s, &config, root));
    yyjson_mut_doc_free(request);
    nm_probe_executor *e = fake_executor_new(8, true, false);
    nm_esp_state_set_probe_executor(s, e);
    for (unsigned iteration = 0; iteration < 10; ++iteration) {
        CHECK(cycle(s));
        CHECK(SIZE(GET(data(), "PingInfos")) == count * (iteration + 1));
        CHECK(e->in_flight(e->context) == 0);
        if (iteration == 0 && count == 50) {
            CHECK(topic_count("processor/out/data", true) == 1);
            for (size_t i = 0; i < message_count; ++i) {
                if (strcmp(messages[i].topic, "processor/out/data"))
                    continue;
                yyjson_mut_doc *wire = decode(i);
                CHECK(SIZE(GET(ROOT(wire), "MonitorPingInfos")) == 50);
                CHECK(SIZE(GET(ROOT(wire), "PingInfos")) == 50);
                yyjson_mut_doc_free(wire);
            }
        }
        clear_messages();
        struct fake_executor *f = e->context;
        f->head = f->tail = 0;
    }
    for (int id = 100; id < 100 + (int)count; ++id)
        CHECK(number(info_by_id(id), "PacketsSent") == 10);
    CHECK(cycle(s)); /* full backlog pauses, never discards samples */
    CHECK(SIZE(GET(data(), "PingInfos")) == count * 10);
    nm_esp_state_free(s);
}
static void test_fifty_host_cycles(void)
{
    host_cycles(50);
}
static void test_150_host_cycles(void)
{
    host_cycles(150);
}
struct publication_change {
    nm_esp_state *state;
    unsigned seen;
    bool reset, applied;
};
static bool change_during_publication(void *opaque)
{
    struct publication_change *c = opaque;
    /* Every publication must give the consumer an opportunity before the next. */
    CHECK(message_count <= c->seen + 1);
    c->seen = message_count;
    if ((c->applied && c->reset) || !message_count ||
        strcmp(messages[message_count - 1].topic, "processor/out/data"))
        return true;
    c->applied = true;
    if (c->reset) {
        yyjson_mut_doc *init = parse("{\"TotalReset\":true,\"MonitorIPs\":[]}");
        CHECK(nm_esp_state_init(c->state, &config, ROOT(init)));
        yyjson_mut_doc_free(init);
    } else {
        yyjson_mut_doc *ack = parse("{\"RemovePingInfos\":[]}");
        yyjson_mut_doc *published = decode(message_count - 1);
        yyjson_mut_val *pings = GET(ROOT(published), "PingInfos");
        for (size_t i = 0; i < SIZE(pings); ++i) {
            yyjson_mut_val *item = yyjson_mut_obj(ack);
            CHECK(yyjson_mut_obj_add_val(ack, item, "ID",
                                         yyjson_mut_val_mut_copy(ack, GET(AT(pings, i), "ID"))));
            CHECK(yyjson_mut_arr_append(GET(ROOT(ack), "RemovePingInfos"), item));
        }
        CHECK(nm_esp_state_ack(c->state, ROOT(ack)));
        yyjson_mut_doc_free(published);
        yyjson_mut_doc_free(ack);
    }
    return true;
}
static void test_publication_commands(void)
{
    for (unsigned reset_model = 0; reset_model < 2; ++reset_model) {
        reset();
        nm_esp_state *s = initialized(three_enabled);
        struct publication_change c = {.state = s, .reset = reset_model != 0};
        nm_esp_state_set_yield(s, change_during_publication, &c);
        CHECK(cycle(s) == !reset_model);
        /* Publication-time commands reach this cycle's subsequent snapshot. */
        CHECK(c.applied && SIZE(GET(data(), "PingInfos")) == 0);
        /* Publishing the old snapshot must never restore acknowledged data. */
        CHECK(nm_esp_state_save(s));
        CHECK(SIZE(GET(data(), "PingInfos")) == 0);
        nm_esp_state_free(s);
    }
}

static void test_commands_ram_only(void)
{
    reset();
    nm_esp_state *s = nm_esp_state_new(&config);
    CHECK(s && save_calls == 0 && !storage[0].doc);
    yyjson_mut_doc *request = parse(one_disabled);
    CHECK(nm_esp_state_init(s, &config, ROOT(request)));
    yyjson_mut_doc_free(request);
    request = parse(
        "[{\"ID\":7,\"Address\":\"changed.test\",\"EndPointType\":\"http\",\"Enabled\":false}]");
    CHECK(nm_esp_state_updates(s, &config, ROOT(request)));
    yyjson_mut_doc_free(request);
    request = parse("[7]");
    CHECK(nm_esp_state_alert(s, &config, &broker, "processorResetAlerts", ROOT(request)));
    CHECK(nm_esp_state_alert(s, &config, &broker, "processorAlertFlag", ROOT(request)));
    CHECK(nm_esp_state_alert(s, &config, &broker, "processorAlertSent", ROOT(request)));
    yyjson_mut_doc_free(request);
    request = parse("{\"IsLoggedInWebsite\":true,\"IsHostsAdded\":true}");
    CHECK(nm_esp_state_user_event(s, ROOT(request)));
    yyjson_mut_doc_free(request);
    request = parse("{\"RemovePingInfos\":[{\"ID\":123}]}");
    CHECK(nm_esp_state_ack(s, ROOT(request)));
    yyjson_mut_doc_free(request);
    CHECK(save_calls == 0 && !storage[0].doc && nm_esp_state_monitor_count(s) == 1);
    clear_messages();
    CHECK(cycle(s) && save_calls == 1 && probe_count == 0);
    CHECK(yyjson_mut_equals_str(GET(info(), "Address"), "changed.test"));
    CHECK(yyjson_mut_is_true(GET(GET(info(), "MonitorStatus"), "AlertFlag")));
    CHECK(yyjson_mut_is_true(GET(GET(info(), "MonitorStatus"), "AlertSent")));
    clear_messages();
    CHECK(cycle(s) && save_calls == 2); /* unchanged cycles still save once */
    nm_esp_state_free(s);
}

static void test_reboot_between_cycles(void)
{
    reset();
    nm_esp_state *s = seed_pings(1, HIGH_ID);
    unsigned saves = save_calls;
    yyjson_mut_doc *ack = parse("{\"RemovePingInfos\":[{\"ID\":9007199254740993}]}");
    CHECK(nm_esp_state_ack(s, ROOT(ack)) && save_calls == saves);
    nm_esp_state_free(s); /* power loss before next cycle: acknowledgement is not saved */
    s = nm_esp_state_new(&config);
    CHECK(s && save_calls == saves);
    CHECK(cycle(s) && SIZE(GET(data(), "PingInfos")) == 1);
    yyjson_mut_doc *wire = decode(0);
    CHECK(number(AT(GET(ROOT(wire), "PingInfos"), 0), "ID") == HIGH_ID);
    yyjson_mut_doc_free(wire); /* same ID replayed, no fabricated new sample */
    CHECK(nm_esp_state_ack(s, ROOT(ack)));
    clear_messages();
    CHECK(cycle(s) && SIZE(GET(data(), "PingInfos")) == 0);
    nm_esp_state_free(s);
    s = nm_esp_state_new(&config);
    CHECK(s);
    clear_messages();
    CHECK(cycle(s) && SIZE(GET(data(), "PingInfos")) == 0);
    /* A monitor added since the last cycle is likewise intentionally volatile. */
    yyjson_mut_doc *updates = parse(
        "[{\"ID\":8,\"Address\":\"unsaved.test\",\"EndPointType\":\"http\",\"Enabled\":false}]");
    saves = save_calls;
    CHECK(nm_esp_state_updates(s, &config, ROOT(updates)));
    CHECK(nm_esp_state_monitor_count(s) == 2 && save_calls == saves);
    nm_esp_state_free(s);
    s = nm_esp_state_new(&config);
    CHECK(s && nm_esp_state_monitor_count(s) == 1 && save_calls == saves);
    nm_esp_state_free(s);
    yyjson_mut_doc_free(updates);
    yyjson_mut_doc_free(ack);
}

static void test_registration_handoff_snapshot(void)
{
    reset();
    nm_esp_state *s = nm_esp_state_new(&config);
    CHECK(s);
    yyjson_mut_doc *reply = parse("{\"TotalReset\":true,\"MonitorIPs\":[]}");
    CHECK(nm_esp_state_init(s, &config, ROOT(reply)));
    CHECK(nm_esp_state_monitor_count(s) == 0);
    yyjson_mut_doc_free(reply);
    reply = parse("{\"TotalReset\":true,\"MonitorIPs\":[{\"ID\":7,\"Address\":\"handoff.test\","
                  "\"EndPointType\":\"http\",\"Enabled\":false}]}");
    CHECK(nm_esp_state_init(s, &config, ROOT(reply)));
    fail_save_at = save_calls + 1;
    CHECK(!nm_esp_state_save(s));
    CHECK(nm_esp_state_monitor_count(s) == 1);
    fail_save_at = 0;
    CHECK(nm_esp_state_save(s));
    nm_esp_state_free(s);
    s = nm_esp_state_new(&config); /* Enrollment client hands over to runtime. */
    CHECK(s && nm_esp_state_monitor_count(s) == 1);
    CHECK(probe_count == 0);
    nm_esp_state_free(s);
    yyjson_mut_doc_free(reply);
}

/* Actual sequential/concurrent state publication: durations scale once,
 * sensor values bypass timing scale, failure retains 65535 and counters. */
static void test_measurement_samples(void)
{
    const char *types[] = {"http", "nmap", "blebroadcastlisten", "blebroadcast"};
    for (unsigned concurrent = 0; concurrent < 2; ++concurrent)
        for (size_t t = 0; t < sizeof(types) / sizeof(types[0]); ++t) {
            reset();
            char init[256];
            snprintf(init, sizeof(init),
                     "{\"MonitorIPs\":[{\"ID\":7,\"Address\":\"example.test\","
                     "\"EndPointType\":\"%s\",\"Enabled\":true}]}",
                     types[t]);
            nm_esp_state *s = initialized(init);
            if (concurrent)
                nm_esp_state_set_probe_executor(s, fake_executor_new(1, false, false));
            bool sensor = !strcmp(types[t], "blebroadcast");
            bool extended = !strcmp(types[t], "nmap") || !strcmp(types[t], "blebroadcastlisten");
            endpoint_result.elapsed_ms = extended || sensor ? 70009 : 1234;
            endpoint_result.has_sample = sensor;
            endpoint_result.sample = 32123;
            uint16_t expected = sensor ? 32123 : extended ? 7000 : 1234;
            CHECK(cycle(s));
            CHECK(number(info(), "PacketsRecieved") == 1);
            CHECK(number(AT(GET(data(), "PingInfos"), 0), "RoundTripTime") == expected);
            CHECK(yyjson_mut_get_num(GET(info(), "RoundTripTimeAverage")) == expected);
            bool sent = false;
            for (size_t m = 0; m < message_count; ++m) {
                if (strcmp(messages[m].topic, "processor/out/data"))
                    continue;
                yyjson_mut_doc *wire = decode(m);
                CHECK(number(AT(GET(ROOT(wire), "PingInfos"), 0), "RoundTripTime") == expected);
                yyjson_mut_doc_free(wire);
                sent = true;
            }
            CHECK(sent);
            clear_messages();
            endpoint_result.ok = false;
            CHECK(cycle(s));
            CHECK(number(AT(GET(data(), "PingInfos"), 1), "RoundTripTime") == UINT16_MAX);
            CHECK(number(info(), "PacketsLost") == 1);
            nm_esp_state_free(s);
        }
}

int main(int argc, char **argv)
{
    const struct {
        const char *name;
        void (*run)(void);
    } tests[] = {{"measurement_samples", test_measurement_samples},
                 {"base64", test_base64},
                 {"registration_handoff_snapshot", test_registration_handoff_snapshot},
                 {"commands_ram_only", test_commands_ram_only},
                 {"reboot_between_cycles", test_reboot_between_cycles},
                 {"message_publication", test_message_publication},
                 {"storage_clones", test_storage_clones},
                 {"legacy_migration", test_legacy_migration},
                 {"fresh_disabled", test_fresh_disabled},
                 {"orphan_boot_refused", test_orphan_boot_refused},
                 {"saved_host_rebuilds_parent", test_saved_host_rebuilds_parent},
                 {"live_defaults", test_live_defaults},
                 {"independent_publish_failures", test_independent_publish_failures},
                 {"batch_500", test_batch_500},
                 {"publication_size_split", test_publication_size_split},
                 {"zero_monitors_retry", test_zero_monitors_retry},
                 {"storage_failure", test_storage_failure},
                 {"high_ids", test_high_ids},
                 {"yield_between_probes", test_yield_between_probes},
                 {"concurrent_probes", test_concurrent_probes},
                 {"concurrent_yield", test_concurrent_yield},
                 {"concurrent_pending_limit", test_concurrent_pending_limit},
                 {"concurrent_submit_failure", test_concurrent_submit_failure},
                 {"local_failure", test_local_failure},
                 {"configuration_during_wait", test_configuration_during_wait},
                 {"fifty_host_cycles", test_fifty_host_cycles},
                 {"150_host_cycles", test_150_host_cycles},
                 {"publication_commands", test_publication_commands}};
    unsigned ran = 0;
    for (size_t i = 0; i < sizeof(tests) / sizeof(*tests); ++i) {
        if (argc > 1 && strcmp(argv[1], tests[i].name))
            continue;
        tests[i].run();
        cleanup();
        printf("PASS %s\n", tests[i].name);
        ++ran;
    }
    CHECK(ran);
    printf("%u state adapter tests passed\n", ran);
    return 0;
}
