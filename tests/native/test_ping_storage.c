#include "ping_storage.h"
#include "sd_card.h"
#include "nvs.h"
#include "nvs_flash.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(x)                                                                                   \
    do {                                                                                           \
        if (!(x)) {                                                                                \
            fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #x);                                \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)
static char directory[] = "/tmp/nm-ping-storage-XXXXXX";
static bool use_sd, fail_set, fail_commit, fail_sync, fail_truncate, fail_stats, opened;
static char *blobs[NM_PING_NVS_PAGES + 1], *staged;
static size_t staged_slot;
const char *nm_sd_card_mount(yyjson_mut_val *settings, const char *identity)
{
    (void)settings;
    CHECK(!strcmp(identity, "test"));
    return use_sd ? directory : NULL;
}
bool nm_sd_card_space(uint64_t *bytes)
{
    *bytes = UINT64_C(16) * 1024 * 1024;
    return !fail_stats;
}
int __real_fsync(int fd);
int __wrap_fsync(int fd)
{
    return fail_sync ? -1 : __real_fsync(fd);
}
int __real_ftruncate(int fd, off_t length);
int __wrap_ftruncate(int fd, off_t length)
{
    return fail_truncate ? -1 : __real_ftruncate(fd, length);
}
esp_err_t nvs_get_stats(const char *partition, nvs_stats_t *stats)
{
    CHECK(!strcmp(partition, "nmdata"));
    *stats = (nvs_stats_t){.available_entries = 30000};
    return fail_stats ? ESP_FAIL : ESP_OK;
}
esp_err_t nvs_open_from_partition(const char *partition, const char *space, nvs_open_mode_t mode,
                                  nvs_handle_t *handle)
{
    (void)mode;
    CHECK(!opened && !strcmp(partition, "nmdata") && !strcmp(space, "nmpings"));
    opened = true;
    *handle = 1;
    return ESP_OK;
}
static size_t slot(const char *key)
{
    CHECK(key[0] == 'p');
    char *end;
    unsigned long n = strtoul(key + 1, &end, 10);
    CHECK(!*end && n <= NM_PING_NVS_PAGES);
    return (size_t)n;
}
esp_err_t nvs_get_blob(nvs_handle_t handle, const char *key, void *value, size_t *length)
{
    CHECK(opened && handle == 1);
    char *text = blobs[slot(key)];
    if (!text)
        return ESP_ERR_NVS_NOT_FOUND;
    size_t size = strlen(text);
    if (value) {
        CHECK(*length >= size);
        memcpy(value, text, size);
    }
    *length = size;
    return ESP_OK;
}
esp_err_t nvs_set_blob(nvs_handle_t handle, const char *key, const void *value, size_t length)
{
    CHECK(opened && handle == 1 && !staged);
    if (fail_set)
        return ESP_FAIL;
    staged = malloc(length + 1);
    CHECK(staged);
    memcpy(staged, value, length);
    staged[length] = 0;
    staged_slot = slot(key);
    return ESP_OK;
}
esp_err_t nvs_erase_key(nvs_handle_t handle, const char *key)
{
    CHECK(opened && handle == 1);
    free(blobs[slot(key)]);
    blobs[slot(key)] = NULL;
    return ESP_OK;
}
esp_err_t nvs_commit(nvs_handle_t handle)
{
    CHECK(opened && handle == 1);
    if (fail_commit)
        return ESP_FAIL;
    if (staged) {
        free(blobs[staged_slot]);
        blobs[staged_slot] = staged;
        staged = NULL;
    }
    return ESP_OK;
}
void nvs_close(nvs_handle_t handle)
{
    CHECK(opened && handle == 1);
    opened = false;
    free(staged);
    staged = NULL;
}
static yyjson_mut_doc *parse(const char *text)
{
    yyjson_mut_doc *doc = nm_json_read(text, strlen(text));
    CHECK(doc);
    return doc;
}
static void test_store(bool sd)
{
    use_sd = sd;
    CHECK(nm_ping_storage_init(NULL, "test"));
    CHECK(nm_ping_storage_selected() == (sd ? NM_PING_STORAGE_SD : NM_PING_STORAGE_NVS));
    nm_ping_storage_begin(1, 0, 0);
    nm_ping_storage_capacity space = nm_ping_storage_space();
    CHECK(space.healthy && space.free_bytes > space.reserve_bytes);
    fail_stats = true;
    CHECK(!nm_ping_storage_space().healthy);
    fail_stats = false;
    yyjson_mut_doc *doc =
        parse("{\"Epoch\":1,\"Page\":0,\"PingInfos\":[{\"ID\":18446744073709551615}]}");
    CHECK(nm_ping_storage_write(1, 0, yyjson_mut_doc_get_root(doc)));
    yyjson_mut_doc *read = nm_ping_storage_read(1, 0);
    CHECK(read && yyjson_mut_equals(yyjson_mut_doc_get_root(doc), yyjson_mut_doc_get_root(read)));
    yyjson_mut_doc_free(read);
    if (sd) {
        fail_sync = true;
        CHECK(!nm_ping_storage_write(1, 1, yyjson_mut_doc_get_root(doc)));
        fail_sync = false;
        fail_truncate = true;
        CHECK(!nm_ping_storage_write(1, 1, yyjson_mut_doc_get_root(doc)));
        fail_truncate = false;
    } else {
        fail_set = true;
        CHECK(!nm_ping_storage_write(1, 0, yyjson_mut_doc_get_root(doc)));
        fail_set = false;
        fail_commit = true;
        CHECK(!nm_ping_storage_write(1, 0, yyjson_mut_doc_get_root(doc)));
        fail_commit = false;
    }
    read = nm_ping_storage_read(1, 0);
    CHECK(read && yyjson_mut_equals(yyjson_mut_doc_get_root(doc), yyjson_mut_doc_get_root(read)));
    yyjson_mut_doc_free(read);
    nm_ping_storage_collect(1, 0, 1);
    read = nm_ping_storage_read(1, 0);
    CHECK(read); /* Reclamation must preserve every committed live page. */
    yyjson_mut_doc_free(read);
    CHECK(nm_ping_storage_delete(1, 0));
    if (sd)
        nm_ping_storage_collect(1, 1, 1);
    CHECK(!nm_ping_storage_read(1, 0));
    CHECK(nm_ping_storage_delete(1, 0));
    if (!sd) {
        yyjson_mut_doc *newer = parse("{\"Epoch\":2,\"Page\":64,\"PingInfos\":[]}");
        CHECK(nm_ping_storage_write(2, 64, yyjson_mut_doc_get_root(newer)));
        CHECK(nm_ping_storage_delete(1, 0));
        read = nm_ping_storage_read(2, 64);
        CHECK(read);
        yyjson_mut_doc_free(read);
        CHECK(nm_ping_storage_delete(2, 64));
        yyjson_mut_doc_free(newer);
    }
    yyjson_mut_doc_free(doc);
}

static void test_sd_segments(void)
{
    use_sd = true;
    CHECK(nm_ping_storage_init(NULL, "test"));
    nm_ping_storage_begin(123, 0, 0);
    yyjson_mut_doc *doc = parse("{\"Epoch\":123,\"Page\":0,\"PingInfos\":[]}");
    yyjson_mut_val *root = yyjson_mut_doc_get_root(doc);
    for (uint64_t p = 0; p < 64; ++p) {
        yyjson_mut_obj_remove_key(root, "Page");
        CHECK(yyjson_mut_obj_add_uint(doc, root, "Page", p));
        CHECK(nm_ping_storage_write(123, p, root));
    }
    for (uint64_t p = 0; p < 64; ++p) {
        yyjson_mut_doc *read = nm_ping_storage_read(123, p);
        CHECK(read &&
              yyjson_mut_get_uint(yyjson_mut_obj_get(yyjson_mut_doc_get_root(read), "Page")) == p);
        yyjson_mut_doc_free(read);
    }
    char name[256];
    struct stat st;
    for (unsigned segment = 0; segment < 2; ++segment) {
        int n = snprintf(name, sizeof(name), "%s/000000000000007b/0000000000000000/%016x.seg",
                         directory, segment);
        CHECK(n > 0 && (size_t)n < sizeof(name) && stat(name, &st) == 0);
        CHECK(st.st_size > 24 && st.st_size < 4096);
    }
    nm_ping_storage_begin(123, 0, 64);
    CHECK(!nm_ping_storage_write(123, 63, root));
    yyjson_mut_obj_remove_key(root, "Page");
    CHECK(yyjson_mut_obj_add_uint(doc, root, "Page", 64));
    CHECK(nm_ping_storage_write(123, 64, root));
    /* Simulate a torn uncommitted suffix, then retry the same block. */
    int n = snprintf(name, sizeof(name),
                     "%s/000000000000007b/0000000000000000/0000000000000002.seg", directory);
    CHECK(n > 0 && (size_t)n < sizeof(name));
    FILE *file = fopen(name, "ab");
    CHECK(file && fwrite("torn suffix", 1, 11, file) == 11 && fclose(file) == 0);
    CHECK(nm_ping_storage_write(123, 64, root));
    yyjson_mut_doc *read = nm_ping_storage_read(123, 63);
    CHECK(read);
    yyjson_mut_doc_free(read);
    CHECK(nm_ping_storage_delete(123, 0));
    read = nm_ping_storage_read(123, 1);
    CHECK(read); /* A partial acknowledgement must retain the shared segment. */
    yyjson_mut_doc_free(read);
    CHECK(nm_ping_storage_delete(123, 31));
    CHECK(!nm_ping_storage_read(123, 0));
    read = nm_ping_storage_read(123, 32);
    CHECK(read);
    yyjson_mut_doc_free(read);
    nm_ping_storage_collect(123, 65, 65);
    CHECK(!nm_ping_storage_read(123, 64));
    yyjson_mut_doc_free(doc);
}
static void test_nvs_rotation_layout(void)
{
    const uint64_t heads[] = {0, 1, 63, 64, 1005};
    const unsigned counts[] = {1, 7, 63, 64};
    for (size_t h = 0; h < sizeof(heads) / sizeof(*heads); ++h)
        for (size_t n = 0; n < sizeof(counts) / sizeof(*counts); ++n) {
            use_sd = false;
            CHECK(nm_ping_storage_init(NULL, "test"));
            for (size_t i = 0; i <= NM_PING_NVS_PAGES; ++i) {
                free(blobs[i]);
                blobs[i] = NULL;
            }
            uint64_t head = heads[h], tail = head + counts[n], split = tail;
            yyjson_mut_doc *doc = parse("{\"Epoch\":1,\"Page\":0}");
            yyjson_mut_val *root = yyjson_mut_doc_get_root(doc);
            for (uint64_t page = head; page < tail; ++page) {
                CHECK(nm_json_put(doc, root, "Page", yyjson_mut_uint(doc, page)));
                CHECK(nm_ping_storage_write(1, page, root));
            }
            nm_ping_storage_layout(true, split, (unsigned)(head % 64));
            for (unsigned i = 0; i < counts[n] + 130; ++i) {
                CHECK(nm_json_put(doc, root, "Page", yyjson_mut_uint(doc, tail)));
                CHECK(nm_ping_storage_write(1, tail, root));
                /* The old root's entire queue remains readable before retirement. */
                for (uint64_t p = head; p < tail; ++p) {
                    yyjson_mut_doc *read = nm_ping_storage_read(1, p);
                    CHECK(read);
                    CHECK(yyjson_mut_get_uint(
                              yyjson_mut_obj_get(yyjson_mut_doc_get_root(read), "Page")) == p);
                    yyjson_mut_doc_free(read);
                }
                CHECK(nm_ping_storage_delete(1, head));
                ++head;
                ++tail;
                nm_ping_storage_collect(1, head, tail);
            }
            yyjson_mut_doc_free(doc);
        }
}
int main(void)
{
    test_nvs_rotation_layout();
    CHECK(mkdtemp(directory));
    test_store(false);
    test_store(true);
    test_sd_segments();
    char path[256];
    CHECK(snprintf(path, sizeof(path), "%s/0000000000000001/0000000000000000/0000000000000000.seg",
                   directory) > 0);
    CHECK(unlink(path) == 0 || errno == ENOENT);
    CHECK(snprintf(path, sizeof(path), "%s/0000000000000001/0000000000000000", directory) > 0);
    CHECK(rmdir(path) == 0 || errno == ENOENT);
    CHECK(snprintf(path, sizeof(path), "%s/0000000000000001", directory) > 0);
    CHECK(rmdir(path) == 0 || errno == ENOENT);
    CHECK(rmdir(directory) == 0);
    puts("PASS NVS/SD block adapters: exact JSON, committed-prefix protection, "
         "sync/truncate/write/commit "
         "failures, recycled-key cleanup");
    return 0;
}
