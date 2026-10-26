#include "ping_backlog.h"
#include "monitor_time.h"
#include "sd_card.h"
#include "nm_esp.h"
#include "nvs.h"
#include "nvs_flash.h"
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

#define CHECK(x)                                                                                   \
    do {                                                                                           \
        if (!(x)) {                                                                                \
            fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #x);                                \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)
#define ROOT yyjson_mut_doc_get_root
#define GET yyjson_mut_obj_get
static char directory[] = "/tmp/nm-sd-backlog-XXXXXX";
static yyjson_mut_doc *checkpoint;
static bool fail_root;
static unsigned sync_calls, fail_sync_at;
int __real_fsync(int fd);
int __wrap_fsync(int fd)
{
    return ++sync_calls == fail_sync_at ? -1 : __real_fsync(fd);
}
const char *nm_sd_card_mount(yyjson_mut_val *settings, const char *identity)
{
    (void)settings;
    CHECK(!strcmp(identity, "test"));
    return directory;
}
bool nm_sd_card_space(uint64_t *bytes)
{
    struct statvfs stats;
    if (statvfs(directory, &stats))
        return false;
    *bytes = (uint64_t)stats.f_bavail * stats.f_frsize;
    return true;
}
esp_err_t nvs_open_from_partition(const char *partition, const char *space, nvs_open_mode_t mode,
                                  nvs_handle_t *handle)
{
    (void)mode;
    (void)handle;
    CHECK(!strcmp(partition, "nmdata") && !strcmp(space, "nmpings"));
    return ESP_ERR_NVS_NOT_FOUND;
}
esp_err_t nvs_get_stats(const char *partition, nvs_stats_t *stats)
{
    (void)partition;
    (void)stats;
    return ESP_FAIL;
}
esp_err_t nvs_get_blob(nvs_handle_t h, const char *k, void *v, size_t *n)
{
    (void)h;
    (void)k;
    (void)v;
    (void)n;
    return ESP_FAIL;
}
esp_err_t nvs_set_blob(nvs_handle_t h, const char *k, const void *v, size_t n)
{
    (void)h;
    (void)k;
    (void)v;
    (void)n;
    return ESP_FAIL;
}
esp_err_t nvs_erase_key(nvs_handle_t h, const char *k)
{
    (void)h;
    (void)k;
    return ESP_FAIL;
}
esp_err_t nvs_commit(nvs_handle_t h)
{
    (void)h;
    return ESP_FAIL;
}
void nvs_close(nvs_handle_t h)
{
    (void)h;
    CHECK(false);
}
bool nm_esp_storage_save(const char *key, yyjson_mut_val *value)
{
    CHECK(!strcmp(key, "monitoring"));
    if (fail_root)
        return false;
    size_t length;
    char *text = nm_json_write(value, 0, &length);
    if (!text)
        return false;
    yyjson_mut_doc *copy = nm_json_read(text, length);
    free(text);
    if (!copy)
        return false;
    yyjson_mut_doc_free(checkpoint);
    checkpoint = copy;
    return true;
}
static nm_ping_backlog *open_model(nm_model *model)
{
    CHECK(nm_model_open(model, ROOT(checkpoint), NULL, NULL, 150, 5000));
    if (!checkpoint) {
        const char *init = "{\"MonitorIPs\":[{\"ID\":7,\"Address\":\"example.test\","
                           "\"EndPointType\":\"http\",\"Enabled\":true}]}";
        yyjson_mut_doc *doc = nm_json_read(init, strlen(init));
        CHECK(doc && nm_model_init(model, ROOT(doc), "test", "2026-10-26T12:00:00Z"));
        yyjson_mut_doc_free(doc);
    }
    nm_ping_backlog *queue = nm_ping_backlog_open(ROOT(checkpoint), model, 123, 500);
    CHECK(queue);
    return queue;
}
static void probe(nm_model *model, unsigned count)
{
    for (unsigned i = 0; i < count; ++i)
        CHECK(nm_model_probe(model, 7, true, 15, "OK", "reachable", "2026-10-26T12:00:00Z",
                             151000000));
}
static void drain(nm_ping_backlog *queue, nm_model *model)
{
    for (unsigned retry = 0; nm_ping_backlog_pending(queue, model); ++retry) {
        CHECK(retry < 100 && nm_ping_backlog_load(queue, model));
        yyjson_mut_doc *ack = nm_json_new();
        yyjson_mut_val *root = yyjson_mut_obj(ack), *array = yyjson_mut_arr(ack);
        CHECK(root && array && yyjson_mut_obj_add_val(ack, root, "RemovePingInfos", array));
        yyjson_mut_doc_set_root(ack, root);
        for (size_t i = 0; i < model->pings.count; ++i) {
            yyjson_mut_val *id = yyjson_mut_obj(ack);
            CHECK(id &&
                  yyjson_mut_obj_add_uint(ack, id, "ID",
                                          ((nm_ping_record *)model->pings.items[i])->ID) &&
                  yyjson_mut_arr_append(array, id));
        }
        CHECK(nm_model_ack(model, root));
        yyjson_mut_doc_free(ack);
        CHECK(nm_ping_backlog_save(queue, model));
    }
}
static size_t segment_count(const char *path)
{
    DIR *dir = opendir(path);
    CHECK(dir);
    size_t count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        char child[256];
        int n = snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
        CHECK(n > 0 && (size_t)n < sizeof(child));
        struct stat st;
        CHECK(stat(child, &st) == 0);
        if (S_ISDIR(st.st_mode))
            count += segment_count(child);
        else {
            CHECK(strstr(entry->d_name, ".seg"));
            ++count;
        }
    }
    CHECK(closedir(dir) == 0);
    return count;
}
int main(void)
{
    CHECK(mkdtemp(directory) && nm_ping_storage_init(NULL, "test"));
    nm_model model;
    nm_ping_backlog *queue = open_model(&model);
    for (unsigned cycle = 0; cycle < 70; ++cycle) {
        CHECK(nm_ping_backlog_load(queue, &model));
        probe(&model, 50);
        CHECK(nm_ping_backlog_save(queue, &model));
        CHECK(model.pings.count <= NM_PING_WINDOW_RECORDS);
    }
    CHECK(nm_ping_backlog_pending(queue, &model) == 3500 && segment_count(directory) == 3);
    nm_ping_backlog_free(queue);
    nm_model_close(&model);
    queue = open_model(&model);
    CHECK(nm_ping_backlog_pending(queue, &model) == 3500);
    nm_model candidate = {0};
    CHECK(nm_model_clone(&candidate, &model));
    CHECK(nm_monitor_time_begin(&candidate, 3600, nm_ping_backlog_pages(queue)));
    nm_ping_backlog_time_begin(queue);
    CHECK(nm_ping_backlog_save(queue, &candidate));
    nm_model_close(&model);
    model = candidate;
    bool injected = false;
    while (model.clock.correcting) {
        if (!injected) {
            fail_sync_at = sync_calls + 1;
            CHECK(!nm_ping_backlog_time_step(queue, &model));
            fail_sync_at = 0;
            fail_root = true;
            CHECK(!nm_ping_backlog_time_step(queue, &model));
            fail_root = false;
            injected = true;
        }
        CHECK(nm_ping_backlog_time_step(queue, &model));
        nm_model_close(&model);
        nm_ping_backlog_free(queue);
        queue = open_model(&model);
    }
    CHECK(nm_ping_backlog_load(queue, &model));
    for (size_t i = 0; i < model.pings.count; ++i)
        CHECK(((nm_ping_record *)model.pings.items[i])->DateSentInt == 151003600);
    drain(queue, &model);
    CHECK(segment_count(directory) == 0);
    probe(&model, 150);
    fail_root = true;
    CHECK(!nm_ping_backlog_save(queue, &model) && model.pings.count == 150);
    fail_root = false;
    CHECK(nm_ping_backlog_save(queue, &model));
    CHECK(nm_ping_backlog_load(queue, &model));
    probe(&model, 70);
    fail_sync_at = sync_calls + 2;
    CHECK(!nm_ping_backlog_save(queue, &model) && nm_ping_backlog_pending(queue, &model) == 220);
    nm_model reboot;
    nm_ping_backlog *other = open_model(&reboot);
    CHECK(nm_ping_backlog_pending(other, &reboot) == 150);
    nm_ping_backlog_free(other);
    nm_model_close(&reboot);
    fail_sync_at = 0;
    CHECK(nm_ping_backlog_save(queue, &model));
    CHECK(nm_ping_backlog_pending(queue, &model) == 220);
    drain(queue, &model);
    CHECK(segment_count(directory) == 0);
    nm_ping_backlog_free(queue);
    nm_model_close(&model);
    yyjson_mut_doc_free(checkpoint);
    CHECK(rmdir(directory) == 0);
    puts("PASS production SD backlog: 3500 readings in 3 segments, bounded RAM, reboot/drain, "
         "failed root/sync retry and committed-prefix preservation");
}
