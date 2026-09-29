/* Tests the real storage adapter, mocking only the NVS boundary. */
#include "nm_esp.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "brotli/decode.h"
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
#define ROOT yyjson_mut_doc_get_root
enum { MONITORING, MONITORS, PROCESSOR, OTA, KEY_COUNT };
static const char *const keys[] = {"monitoring", "monitors", "processor", "ota"};
struct blob {
    unsigned char *bytes;
    size_t length;
};
/* Staged and durable copies expose which successful commit established data.
 * This models the API's durability contract, not NVS flash internals. */
static struct blob durable[KEY_COUNT], staged[KEY_COUNT];
static bool opened;
static nvs_open_mode_t open_mode;
static esp_err_t open_error, get_error, set_error, erase_error[KEY_COUNT], init_error;
static unsigned commits, fail_commit_at, get_calls, fail_read_at;
static char operations[128];
static size_t operation_count;

static void record(char op)
{
    CHECK(operation_count + 1 < sizeof(operations));
    operations[operation_count++] = op;
    operations[operation_count] = 0;
}
static size_t key_index(const char *key)
{
    for (size_t i = 0; i < KEY_COUNT; ++i)
        if (!strcmp(key, keys[i]))
            return i;
    CHECK(false);
    return 0;
}
static void clear_blob(struct blob *b)
{
    free(b->bytes);
    *b = (struct blob){0};
}
static void put_blob(struct blob *b, const void *bytes, size_t length)
{
    unsigned char *copy = malloc(length + 1);
    CHECK(copy);
    if (length)
        memcpy(copy, bytes, length);
    copy[length] = 0;
    clear_blob(b);
    b->bytes = copy;
    b->length = length;
}
static void copy_blobs(struct blob *dst, const struct blob *src)
{
    for (size_t i = 0; i < KEY_COUNT; ++i) {
        if (src[i].bytes)
            put_blob(&dst[i], src[i].bytes, src[i].length);
        else
            clear_blob(&dst[i]);
    }
}
static void seed(size_t key, const char *json)
{
    put_blob(&durable[key], json, strlen(json));
}
static void reset(void)
{
    CHECK(!opened);
    for (size_t i = 0; i < KEY_COUNT; ++i) {
        clear_blob(&durable[i]);
        clear_blob(&staged[i]);
        erase_error[i] = ESP_OK;
    }
    open_error = get_error = set_error = init_error = ESP_OK;
    commits = fail_commit_at = get_calls = fail_read_at = 0;
    operation_count = 0;
    operations[0] = 0;
}
static void expect_ops(const char *expected)
{
    CHECK(!strcmp(operations, expected));
    CHECK(!opened);
}
static void expect_blob(size_t key, const char *json)
{
    CHECK(durable[key].bytes && durable[key].length == strlen(json));
    CHECK(!memcmp(durable[key].bytes, json, strlen(json)));
}
static void expect_monitoring(const char *json)
{
    const struct blob *blob = &durable[MONITORING];
    size_t length = strlen(json);
    CHECK(blob->bytes && blob->length > 12 && blob->length <= 512 * 1024);
    CHECK(!memcmp(blob->bytes, "NMSB\x01\r\n\0", 8));
    uint32_t stored_length = (uint32_t)blob->bytes[8] | ((uint32_t)blob->bytes[9] << 8) |
                             ((uint32_t)blob->bytes[10] << 16) | ((uint32_t)blob->bytes[11] << 24);
    CHECK(stored_length == length);
    char *decoded = malloc(length + 1);
    CHECK(decoded);
    size_t produced = length;
    CHECK(BrotliDecoderDecompress(blob->length - 12, blob->bytes + 12, &produced,
                                  (uint8_t *)decoded) == BROTLI_DECODER_RESULT_SUCCESS);
    CHECK(produced == length && !memcmp(decoded, json, length));
    free(decoded);
}
const char *esp_err_to_name(esp_err_t error)
{
    return error == ESP_OK ? "ESP_OK" : "injected NVS error";
}
esp_err_t nvs_flash_init_partition(const char *partition)
{
    CHECK(!strcmp(partition, "nmdata"));
    record('I');
    return init_error;
}
esp_err_t nvs_get_stats(const char *partition, nvs_stats_t *stats)
{
    CHECK(!strcmp(partition, "nmdata") && stats && !opened);
    *stats = (nvs_stats_t){.used_entries = durable[MONITORING].bytes ? 1 : 0,
                           .free_entries = 100,
                           .available_entries = 100,
                           .total_entries = 101};
    return ESP_OK;
}
esp_err_t nvs_open_from_partition(const char *partition, const char *name, nvs_open_mode_t mode,
                                  nvs_handle_t *handle)
{
    CHECK(!opened && !strcmp(partition, "nmdata") && !strcmp(name, "networkmonitor"));
    CHECK(mode == NVS_READONLY || mode == NVS_READWRITE);
    record(mode == NVS_READONLY ? 'R' : 'W');
    if (open_error != ESP_OK)
        return open_error;
    opened = true;
    open_mode = mode;
    *handle = 42;
    copy_blobs(staged, durable);
    return ESP_OK;
}
static void valid_handle(nvs_handle_t h)
{
    CHECK(opened && h == 42);
}
esp_err_t nvs_get_blob(nvs_handle_t h, const char *key, void *value, size_t *length)
{
    valid_handle(h);
    CHECK(length);
    record(value ? 'G' : 'Q');
    ++get_calls;
    if (get_error != ESP_OK)
        return get_error;
    if (fail_read_at == get_calls)
        return ESP_FAIL;
    struct blob *b = &staged[key_index(key)];
    if (!b->bytes)
        return ESP_ERR_NVS_NOT_FOUND;
    if (!value) {
        *length = b->length;
        return ESP_OK;
    }
    if (*length < b->length) {
        *length = b->length;
        return ESP_ERR_NVS_INVALID_LENGTH;
    }
    memcpy(value, b->bytes, b->length);
    *length = b->length;
    return ESP_OK;
}
esp_err_t nvs_set_blob(nvs_handle_t h, const char *key, const void *value, size_t length)
{
    valid_handle(h);
    CHECK(open_mode == NVS_READWRITE && value);
    record('S');
    if (set_error != ESP_OK)
        return set_error;
    put_blob(&staged[key_index(key)], value, length);
    return ESP_OK;
}
esp_err_t nvs_erase_key(nvs_handle_t h, const char *key)
{
    valid_handle(h);
    CHECK(open_mode == NVS_READWRITE);
    size_t i = key_index(key);
    record((char)('a' + i));
    if (erase_error[i] != ESP_OK)
        return erase_error[i];
    if (!staged[i].bytes)
        return ESP_ERR_NVS_NOT_FOUND;
    clear_blob(&staged[i]);
    return ESP_OK;
}
esp_err_t nvs_commit(nvs_handle_t h)
{
    valid_handle(h);
    CHECK(open_mode == NVS_READWRITE);
    record('C');
    if (++commits == fail_commit_at)
        return ESP_FAIL;
    copy_blobs(durable, staged);
    return ESP_OK;
}
void nvs_close(nvs_handle_t h)
{
    valid_handle(h);
    record('X');
    opened = false;
    for (size_t i = 0; i < KEY_COUNT; ++i)
        clear_blob(&staged[i]);
}
static yyjson_mut_doc *parse(const char *json)
{
    yyjson_mut_doc *d = nm_json_read(json, strlen(json));
    CHECK(d);
    return d;
}
static bool save(const char *key, const char *json)
{
    yyjson_mut_doc *d = parse(json);
    bool ok = nm_esp_storage_save(key, ROOT(d));
    yyjson_mut_doc_free(d);
    return ok;
}
static void seed_old(void)
{
    seed(MONITORING, "{\"old\":true}");
    seed(MONITORS, "[7]");
    seed(PROCESSOR, "{\"legacy\":true}");
    seed(OTA, "{\"rollback\":true}");
}
static void old_intact(void)
{
    expect_blob(MONITORING, "{\"old\":true}");
    expect_blob(MONITORS, "[7]");
    expect_blob(PROCESSOR, "{\"legacy\":true}");
}
static void test_primary_failures(void)
{
    reset();
    seed_old();
    open_error = ESP_FAIL;
    CHECK(!save("monitoring", "{\"new\":true}"));
    expect_ops("W");
    old_intact();
    reset();
    seed_old();
    set_error = ESP_FAIL;
    CHECK(!save("monitoring", "{\"new\":true}"));
    expect_ops("WSX");
    old_intact();
    reset();
    seed_old();
    fail_commit_at = 1;
    CHECK(!save("monitoring", "{\"new\":true}"));
    expect_ops("WSCX");
    old_intact();
}
static void test_retire_after_commit(void)
{
    reset();
    seed_old();
    CHECK(save("monitoring", "{\"new\":true}"));
    expect_ops("WSCbcCX"); /* Primary commit, legacy erases, cleanup commit. */
    expect_monitoring("{\"new\":true}");
    CHECK(!durable[MONITORS].bytes && !durable[PROCESSOR].bytes);
    expect_blob(OTA, "{\"rollback\":true}");
    reset();
    CHECK(save("monitoring", "{}"));
    expect_ops("WSCbcX"); /* NOT_FOUND needs no cleanup commit. */
    reset();
    seed_old();
    CHECK(save("processor", "{}"));
    expect_ops("WSCX");
    expect_blob(MONITORS, "[7]");
    expect_blob(MONITORING, "{\"old\":true}");
}
static void test_cleanup_failures(void)
{
    for (size_t failed = MONITORS; failed <= PROCESSOR; ++failed) {
        reset();
        seed_old();
        erase_error[failed] = ESP_FAIL;
        CHECK(save("monitoring", "{\"new\":true}"));
        expect_ops("WSCbcCX");
        expect_monitoring("{\"new\":true}");
        CHECK(durable[failed].bytes);
        CHECK(!durable[failed == MONITORS ? PROCESSOR : MONITORS].bytes);
    }
    reset();
    seed_old();
    erase_error[MONITORS] = erase_error[PROCESSOR] = ESP_FAIL;
    CHECK(save("monitoring", "{\"new\":true}"));
    expect_ops("WSCbcX");
    expect_monitoring("{\"new\":true}");
    expect_blob(MONITORS, "[7]");
    expect_blob(PROCESSOR, "{\"legacy\":true}");
    reset();
    seed_old();
    fail_commit_at = 2;
    CHECK(save("monitoring", "{\"new\":true}"));
    expect_ops("WSCbcCX");
    expect_monitoring("{\"new\":true}");
    expect_blob(MONITORS, "[7]");
    expect_blob(PROCESSOR, "{\"legacy\":true}");
    yyjson_mut_doc *loaded = nm_esp_storage_load("monitoring");
    CHECK(loaded);
    CHECK(yyjson_mut_is_true(yyjson_mut_obj_get(ROOT(loaded), "new")));
    yyjson_mut_doc_free(loaded);
}
static void test_has_key_fail_closed(void)
{
    const esp_err_t errors[] = {ESP_ERR_NVS_NOT_FOUND, ESP_FAIL, ESP_ERR_NVS_TYPE_MISMATCH,
                                ESP_ERR_NVS_INVALID_LENGTH};
    for (size_t i = 0; i < sizeof(errors) / sizeof(*errors); ++i) {
        reset();
        open_error = errors[i];
        CHECK(nm_esp_storage_has_key("monitoring") == (errors[i] != ESP_ERR_NVS_NOT_FOUND));
        expect_ops("R");
        reset();
        get_error = errors[i];
        CHECK(nm_esp_storage_has_key("monitoring") == (errors[i] != ESP_ERR_NVS_NOT_FOUND));
        expect_ops("RQX");
    }
    reset();
    CHECK(!nm_esp_storage_has_key("monitoring"));
    expect_ops("RQX");
    reset();
    seed(MONITORING, "");
    CHECK(nm_esp_storage_has_key("monitoring"));
    expect_ops("RQX");
    reset();
    seed(MONITORING, "invalid JSON");
    CHECK(nm_esp_storage_has_key("monitoring"));
    expect_ops("RQX");
}
static void test_raw_u64_roundtrip(void)
{
    static const char json[] =
        "{\"ID\":9007199254740993,\"Max\":18446744073709551615,\"Counter\":4294967295}";
    reset();
    CHECK(save("monitoring", json));
    expect_ops("WSCbcX");
    expect_monitoring(json);
    yyjson_mut_doc *d = nm_esp_storage_load("monitoring");
    CHECK(d);
    yyjson_mut_val *id = yyjson_mut_obj_get(ROOT(d), "ID"),
                   *max = yyjson_mut_obj_get(ROOT(d), "Max");
    CHECK(yyjson_mut_is_uint(id) && yyjson_mut_get_uint(id) == UINT64_C(9007199254740993));
    CHECK(yyjson_mut_is_uint(max) && yyjson_mut_get_uint(max) == UINT64_MAX);
    CHECK(yyjson_mut_get_uint(yyjson_mut_obj_get(ROOT(d), "Counter")) == UINT32_MAX);
    /* Returned document owns bytes independently of NVS storage. */
    seed(MONITORING, "{}");
    CHECK(yyjson_mut_get_uint(max) == UINT64_MAX);
    CHECK(nm_esp_storage_save("monitoring", ROOT(d)));
    yyjson_mut_doc_free(d);
    expect_monitoring(json);
}
static void test_load_errors(void)
{
    reset();
    open_error = ESP_FAIL;
    CHECK(!nm_esp_storage_load("monitoring"));
    expect_ops("R");
    reset();
    CHECK(!nm_esp_storage_load("monitoring"));
    expect_ops("RQX");
    reset();
    seed(MONITORING, "");
    CHECK(!nm_esp_storage_load("monitoring"));
    expect_ops("RQX");
    reset();
    seed(MONITORING, "{");
    CHECK(!nm_esp_storage_load("monitoring"));
    expect_ops("RQGX");
    reset();
    seed(MONITORING, "{}");
    fail_read_at = 2;
    CHECK(!nm_esp_storage_load("monitoring"));
    expect_ops("RQGX");
}
static void test_compressed_state_validation(void)
{
    reset();
    seed(MONITORING, "{\"legacy\":true}");
    yyjson_mut_doc *legacy = nm_esp_storage_load("monitoring");
    CHECK(legacy && yyjson_mut_is_true(yyjson_mut_obj_get(ROOT(legacy), "legacy")));
    yyjson_mut_doc_free(legacy);
    CHECK(save("monitoring", "{\"new\":true}"));
    expect_monitoring("{\"new\":true}");
    struct blob good = {0};
    put_blob(&good, durable[MONITORING].bytes, durable[MONITORING].length);

    /* A truncated stream, impossible decoded size, or trailing data cannot
     * become partially parsed monitoring state. */
    put_blob(&durable[MONITORING], good.bytes, good.length - 1);
    CHECK(!nm_esp_storage_load("monitoring"));
    put_blob(&durable[MONITORING], good.bytes, good.length);
    durable[MONITORING].bytes[8] = 0xff;
    durable[MONITORING].bytes[9] = 0xff;
    durable[MONITORING].bytes[10] = 0xff;
    durable[MONITORING].bytes[11] = 0x7f;
    CHECK(!nm_esp_storage_load("monitoring"));
    put_blob(&durable[MONITORING], good.bytes, good.length);
    durable[MONITORING].bytes[good.length] = 1;
    durable[MONITORING].length++;
    CHECK(!nm_esp_storage_load("monitoring"));
    put_blob(&durable[MONITORING], good.bytes, good.length);
    durable[MONITORING].bytes[12] ^= 0xff;
    CHECK(!nm_esp_storage_load("monitoring"));
    clear_blob(&good);
}
static void test_large_compressed_snapshot(void)
{
    reset();
    const size_t length = 600 * 1024;
    char *json = malloc(length + 12);
    CHECK(json);
    memcpy(json, "{\"data\":\"", 9);
    memset(json + 9, 'a', length);
    memcpy(json + 9 + length, "\"}", 3);
    CHECK(save("monitoring", json));
    CHECK(durable[MONITORING].length < 512 * 1024);
    expect_monitoring(json);
    yyjson_mut_doc *loaded = nm_esp_storage_load("monitoring");
    CHECK(loaded);
    yyjson_mut_val *field = yyjson_mut_obj_get(ROOT(loaded), "data");
    CHECK(yyjson_mut_is_str(field) && yyjson_mut_get_len(field) == length);
    yyjson_mut_doc_free(loaded);
    free(json);
}
static void test_init_and_reset(void)
{
    reset();
    init_error = ESP_FAIL;
    CHECK(!nm_esp_storage_init());
    expect_ops("I");
    reset();
    seed_old();
    CHECK(nm_esp_storage_reset_monitoring());
    expect_ops("IWabcCX");
    CHECK(!durable[MONITORING].bytes && !durable[MONITORS].bytes && !durable[PROCESSOR].bytes);
    expect_blob(OTA, "{\"rollback\":true}");
}
int main(void)
{
    test_primary_failures();
    test_retire_after_commit();
    test_cleanup_failures();
    test_has_key_fail_closed();
    test_raw_u64_roundtrip();
    test_load_errors();
    test_compressed_state_validation();
    test_large_compressed_snapshot();
    test_init_and_reset();
    reset();
    puts("9 real storage adapter tests passed");
    return 0;
}
