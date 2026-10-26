#include "ping_backlog.h"
#include "monitor_time.h"
#include "ping_storage_memory.h"
#include "nm_esp.h"
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
#define GET yyjson_mut_obj_get
static yyjson_mut_doc *checkpoint;
static bool fail_checkpoint;
static unsigned saves;
static size_t allocations, fail_allocation;
void *__real_malloc(size_t size);
void *__real_calloc(size_t count, size_t size);
void *__real_realloc(void *pointer, size_t size);
void *__wrap_malloc(size_t size)
{
    return ++allocations == fail_allocation ? NULL : __real_malloc(size);
}
void *__wrap_calloc(size_t count, size_t size)
{
    return ++allocations == fail_allocation ? NULL : __real_calloc(count, size);
}
void *__wrap_realloc(void *pointer, size_t size)
{
    return ++allocations == fail_allocation ? NULL : __real_realloc(pointer, size);
}
static yyjson_mut_doc *parse(const char *json)
{
    yyjson_mut_doc *doc = nm_json_read(json, strlen(json));
    CHECK(doc);
    return doc;
}
bool nm_esp_storage_save(const char *key, yyjson_mut_val *value)
{
    CHECK(!strcmp(key, "monitoring"));
    ++saves;
    if (fail_checkpoint)
        return false;
    size_t length;
    char *json = nm_json_write(value, 0, &length);
    if (!json)
        return false;
    yyjson_mut_doc *copy = nm_json_read(json, length);
    free(json);
    if (!copy)
        return false;
    yyjson_mut_doc_free(checkpoint);
    checkpoint = copy;
    return true;
}
static void reset(nm_ping_storage_mode mode)
{
    nm_test_ping_reset();
    nm_test_ping_mode = mode;
    yyjson_mut_doc_free(checkpoint);
    checkpoint = NULL;
    saves = 0;
    fail_checkpoint = false;
}
static nm_ping_backlog *open_model(nm_model *model)
{
    CHECK(nm_model_open(model, ROOT(checkpoint), NULL, NULL, 150, 5000));
    if (!checkpoint) {
        yyjson_mut_doc *request = parse("{\"MonitorIPs\":[{\"ID\":7,\"Enabled\":true,\"Address\":"
                                        "\"example.test\",\"EndPointType\":\"http\"}]}");
        CHECK(nm_model_init(model, ROOT(request), "test", "2026-10-26T12:00:00Z"));
        yyjson_mut_doc_free(request);
    }
    nm_ping_backlog *queue = nm_ping_backlog_open(ROOT(checkpoint), model, 123, 500);
    CHECK(queue);
    return queue;
}
static void probe(nm_model *model, size_t count)
{
    for (size_t i = 0; i < count; ++i)
        CHECK(nm_model_probe(model, 7, true, 12, "OK", "reachable", "2026-10-26T12:00:00Z", 123));
}
static void acknowledge(nm_model *model, size_t maximum)
{
    yyjson_mut_doc *doc = parse("{\"RemovePingInfos\":[]}");
    yyjson_mut_val *array = GET(ROOT(doc), "RemovePingInfos");
    for (size_t i = 0; i < model->pings.count && i < maximum; ++i) {
        yyjson_mut_val *ack = yyjson_mut_obj(doc);
        CHECK(ack && yyjson_mut_obj_add_uint(doc, ack, "ID",
                                             ((nm_ping_record *)model->pings.items[i])->ID));
        CHECK(yyjson_mut_arr_append(array, ack));
    }
    CHECK(nm_model_ack(model, ROOT(doc)));
    yyjson_mut_doc_free(doc);
}
static void test_large_backlog(void)
{
    reset(NM_PING_STORAGE_SD);
    nm_model model;
    nm_ping_backlog *queue = open_model(&model);
    for (size_t cycle = 0; cycle < 40; ++cycle) {
        CHECK(nm_ping_backlog_load(queue, &model));
        CHECK(nm_ping_backlog_room(queue, 150));
        probe(&model, 150);
        CHECK(model.pings.count <= NM_PING_WINDOW_RECORDS + 150);
        CHECK(nm_ping_backlog_save(queue, &model));
        CHECK(nm_ping_backlog_pending(queue, &model) == (cycle + 1) * 150);
        CHECK(yyjson_mut_arr_size(GET(GET(ROOT(checkpoint), "ProcessorData"), "PingInfos")) == 0);
    }
    CHECK(model.infos.count == 1 &&
          ((nm_monitor_record *)model.infos.items[0])->PacketsSent == 6000);
    nm_ping_backlog_free(queue);
    nm_model_close(&model);
    queue = open_model(&model);
    CHECK(nm_ping_backlog_pending(queue, &model) == 6000);
    CHECK(model.pings.count <= NM_PING_WINDOW_RECORDS);
    CHECK(model.sequence == 6001);
    unsigned cycles = 0;
    while (nm_ping_backlog_pending(queue, &model)) {
        CHECK(++cycles < 100);
        CHECK(nm_ping_backlog_load(queue, &model));
        acknowledge(&model, SIZE_MAX);
        CHECK(nm_ping_backlog_save(queue, &model));
    }
    CHECK(nm_test_ping_deletes == 120);
    nm_ping_backlog_free(queue);
    nm_model_close(&model);
}
static void test_failures(void)
{
    reset(NM_PING_STORAGE_SD);
    nm_model model;
    nm_ping_backlog *queue = open_model(&model);
    CHECK(nm_ping_backlog_save(queue, &model));
    probe(&model, 100);
    nm_test_ping_fail_write = true;
    CHECK(!nm_ping_backlog_save(queue, &model));
    CHECK(model.pings.count == 100 && !nm_ping_backlog_room(queue, 150));
    nm_test_ping_fail_write = false;
    fail_checkpoint = true;
    CHECK(!nm_ping_backlog_save(queue, &model));
    CHECK(model.pings.count == 100);
    nm_model reboot;
    nm_ping_backlog *other = open_model(&reboot);
    CHECK(nm_ping_backlog_pending(other, &reboot) == 0);
    nm_ping_backlog_free(other);
    nm_model_close(&reboot);
    fail_checkpoint = false;
    CHECK(nm_ping_backlog_save(queue, &model));
    CHECK(nm_ping_backlog_pending(queue, &model) == 100 && model.pings.count == 0);
    nm_test_ping_fail_read = true;
    CHECK(!nm_ping_backlog_load(queue, &model));
    CHECK(model.pings.count == 0 && !nm_ping_backlog_room(queue, 150));
    nm_test_ping_fail_read = false;
    CHECK(nm_ping_backlog_load(queue, &model));
    CHECK(model.pings.count == 100);
    acknowledge(&model, 10);
    CHECK(nm_ping_backlog_save(queue, &model));
    nm_ping_backlog_free(queue);
    nm_model_close(&model);
    queue = open_model(&model);
    CHECK(model.pings.count == 90 && nm_ping_backlog_pending(queue, &model) == 90);
    nm_test_ping_fail_delete = true;
    acknowledge(&model, SIZE_MAX);
    CHECK(nm_ping_backlog_save(queue, &model));
    unsigned deletes = nm_test_ping_deletes;
    nm_test_ping_fail_delete = false;
    CHECK(nm_ping_backlog_save(queue, &model));
    CHECK(nm_test_ping_deletes > deletes);
    nm_ping_backlog_free(queue);
    nm_model_close(&model);
}
static void test_capacity_and_switch(void)
{
    reset(NM_PING_STORAGE_NVS);
    nm_model model;
    nm_ping_backlog *queue = open_model(&model);
    for (size_t i = 0; i < NM_PING_NVS_PAGES; ++i) {
        CHECK(nm_ping_backlog_load(queue, &model));
        CHECK(nm_ping_backlog_room(queue, 1));
        probe(&model, 1);
        CHECK(nm_ping_backlog_save(queue, &model));
    }
    CHECK(!nm_ping_backlog_room(queue, 1));
    nm_ping_backlog_reset(queue);
    while (model.pings.count)
        nm_records_remove(&model.pings, model.pings.count - 1);
    /* Reset may not overwrite a page referenced by the old durable root. */
    CHECK(!nm_ping_backlog_room(queue, 1));
    CHECK(nm_ping_backlog_save(queue, &model));
    CHECK(nm_ping_backlog_room(queue, 1));
    CHECK(nm_ping_backlog_save(queue, &model));
    probe(&model, 1);
    CHECK(nm_ping_backlog_save(queue, &model));
    nm_ping_backlog_free(queue);
    nm_model_close(&model);
    nm_test_ping_mode = NM_PING_STORAGE_SD;
    queue = open_model(&model);
    CHECK(model.hosts.count == 1 && model.infos.count == 1 && model.sequence == 66);
    CHECK(nm_ping_backlog_pending(queue, &model) == 0);
    nm_test_ping_capacity.free_bytes = nm_test_ping_capacity.reserve_bytes + 65535;
    CHECK(!nm_ping_backlog_room(queue, 1));
    nm_test_ping_capacity.free_bytes++;
    CHECK(!nm_ping_backlog_room(queue, 1));
    nm_test_ping_capacity.free_bytes += 65536;
    CHECK(nm_ping_backlog_room(queue, 1));
    probe(&model, 1);
    CHECK(nm_ping_backlog_save(queue, &model));
    nm_ping_backlog_stats stats = nm_ping_backlog_status(queue, &model, 60);
    CHECK(!stats.estimate_known);
    probe(&model, 1);
    CHECK(nm_ping_backlog_save(queue, &model));
    stats = nm_ping_backlog_status(queue, &model, 120);
    CHECK(stats.estimate_known && stats.estimated_seconds > 120);
    nm_ping_backlog_free(queue);
    nm_model_close(&model);
}
static void test_wire_types_and_corruption(void)
{
    reset(NM_PING_STORAGE_SD);
    nm_model model;
    nm_ping_backlog *queue = open_model(&model);
    yyjson_mut_doc *doc =
        parse("{\"ID\":9007199254740993,\"MonitorPingInfoID\":7,\"RoundTripTime\":null,\"Status\":"
              "\"OK\",\"FutureField\":{\"n\":18446744073709551615}}");
    nm_record *record = nm_record_decode(NM_PING, ROOT(doc));
    CHECK(record && nm_records_append(&model.pings, record));
    CHECK(nm_ping_backlog_save(queue, &model));
    CHECK(nm_ping_backlog_load(queue, &model));
    CHECK(model.pings.count == 1);
    yyjson_mut_doc *encoded = nm_json_new();
    yyjson_mut_val *value = nm_record_encode(encoded, model.pings.items[0]);
    CHECK(value && yyjson_mut_equals(value, ROOT(doc)));
    yyjson_mut_doc_free(encoded);
    yyjson_mut_doc_free(doc);
    yyjson_mut_doc *page = nm_ping_storage_read(123, 0);
    CHECK(page);
    CHECK(yyjson_mut_obj_add_str(page, yyjson_mut_arr_get(GET(ROOT(page), "PingInfos"), 0),
                                 "Corrupt", "yes"));
    CHECK(nm_ping_storage_write(123, 0, ROOT(page)));
    yyjson_mut_doc_free(page);
    nm_ping_backlog_free(queue);
    nm_model_close(&model);
    CHECK(nm_model_open(&model, ROOT(checkpoint), NULL, NULL, 150, 5000));
    CHECK(!nm_ping_backlog_open(ROOT(checkpoint), &model, 999, 500));
    nm_model_close(&model);
}

static void test_allocation_failures(void)
{
    size_t save_allocations = 0, load_allocations = 0;
    /* Include a complete page plus a partial page to exercise partial cleanup. */
    for (size_t nth = 0; nth <= save_allocations; ++nth) {
        reset(NM_PING_STORAGE_SD);
        nm_model model;
        nm_ping_backlog *queue = open_model(&model);
        CHECK(nm_ping_backlog_save(queue, &model));
        probe(&model, 70);
        allocations = 0;
        fail_allocation = nth;
        bool saved = nm_ping_backlog_save(queue, &model);
        fail_allocation = 0;
        if (!nth)
            save_allocations = allocations;
        if (!saved) {
            CHECK(model.pings.count == 70);
            CHECK(nm_ping_backlog_pending(queue, &model) == 70);
            CHECK(!nm_ping_backlog_room(queue, 150));
            CHECK(yyjson_mut_get_uint(GET(GET(ROOT(checkpoint), "PingBacklog"), "Count")) == 0);
            CHECK(nm_ping_backlog_save(queue, &model));
        }
        CHECK(nm_ping_backlog_pending(queue, &model) == 70);
        nm_ping_backlog_free(queue);
        nm_model_close(&model);
    }
    for (size_t nth = 0; nth <= load_allocations; ++nth) {
        reset(NM_PING_STORAGE_SD);
        nm_model model;
        nm_ping_backlog *queue = open_model(&model);
        probe(&model, 70);
        CHECK(nm_ping_backlog_save(queue, &model));
        CHECK(model.pings.count == 0);
        allocations = 0;
        fail_allocation = nth;
        bool loaded = nm_ping_backlog_load(queue, &model);
        fail_allocation = 0;
        if (!nth)
            load_allocations = allocations;
        if (!loaded) {
            CHECK(model.pings.count == 0);
            CHECK(nm_ping_backlog_pending(queue, &model) == 70);
            CHECK(nm_ping_backlog_load(queue, &model));
        }
        CHECK(model.pings.count == 70);
        nm_ping_backlog_free(queue);
        nm_model_close(&model);
    }
    printf("PASS failed each of %zu save and %zu load allocations\n", save_allocations,
           load_allocations);
}

static void test_rollover_and_removed_parent(void)
{
    reset(NM_PING_STORAGE_SD);
    nm_model model;
    nm_ping_backlog *queue = open_model(&model);
    model.sequence = UINT32_MAX - 1;
    CHECK(nm_ping_backlog_save(queue, &model));
    probe(&model, 1);
    CHECK(nm_ping_backlog_save(queue, &model));
    CHECK(nm_ping_backlog_sequence_safe(queue, UINT32_MAX, 2));
    probe(&model, 2); /* UINT32_MAX, then zero. */
    CHECK(nm_ping_backlog_save(queue, &model));
    CHECK(!nm_ping_backlog_sequence_safe(queue, 0, 1));
    CHECK(nm_ping_backlog_load(queue, &model));
    yyjson_mut_doc *ack = parse("{\"RemovePingInfos\":[{\"ID\":0}]}");
    CHECK(nm_model_ack(&model, ROOT(ack)));
    yyjson_mut_doc_free(ack);
    CHECK(nm_ping_backlog_save(queue, &model));
    CHECK(nm_ping_backlog_sequence_safe(queue, 0, 1));
    model.sequence = 0;
    probe(&model, 1); /* Reusing an acknowledged slot must create a new disk record. */
    CHECK(nm_ping_backlog_pending(queue, &model) == 3);
    CHECK(nm_ping_backlog_save(queue, &model));
    nm_ping_backlog_free(queue);
    nm_model_close(&model);
    queue = open_model(&model);
    CHECK(model.pings.count == 3 && nm_ping_backlog_pending(queue, &model) == 3);
    nm_ping_backlog_free(queue);
    nm_model_close(&model);

    reset(NM_PING_STORAGE_SD);
    queue = open_model(&model);
    for (unsigned i = 0; i < 10; ++i) {
        CHECK(nm_ping_backlog_load(queue, &model));
        probe(&model, 70);
        CHECK(nm_ping_backlog_save(queue, &model));
    }
    CHECK(nm_ping_backlog_pending(queue, &model) == 700);
    yyjson_mut_doc *update = parse("[{\"ID\":7,\"Delete\":true}]");
    CHECK(nm_model_updates(&model, ROOT(update), "test", "2026-10-26T12:00:00Z"));
    yyjson_mut_doc_free(update);
    CHECK(model.hosts.count == 0 && model.infos.count == 1);
    ack = parse("{\"RemoveMonitorPingInfoIDs\":[7]}");
    nm_model before = {0};
    CHECK(nm_model_clone(&before, &model));
    CHECK(nm_model_ack(&model, ROOT(ack)));
    CHECK(nm_ping_backlog_ack(queue, &before, ROOT(ack)));
    nm_model_close(&before);
    yyjson_mut_doc_free(ack);
    CHECK(model.infos.count == 0);
    update =
        parse("[{\"ID\":7,\"Enabled\":true,\"Address\":\"new.test\",\"EndPointType\":\"http\"}]");
    CHECK(nm_model_updates(&model, ROOT(update), "test", "2026-10-26T12:00:00Z"));
    yyjson_mut_doc_free(update);
    probe(&model, 1); /* Re-add before the old on-disk backlog has drained. */
    CHECK(nm_ping_backlog_save(queue, &model));
    nm_ping_backlog_free(queue);
    nm_model_close(&model);
    queue = open_model(&model); /* Cutoff must survive reboot as well. */
    for (unsigned i = 0; i < 10 && nm_ping_backlog_pending(queue, &model) > 1; ++i) {
        CHECK(nm_ping_backlog_save(queue, &model));
        CHECK(nm_ping_backlog_load(queue, &model));
        for (size_t j = 0; j < model.pings.count; ++j)
            CHECK(((nm_ping_record *)model.pings.items[j])->ID == 701);
    }
    CHECK(nm_ping_backlog_pending(queue, &model) == 1);
    CHECK(nm_ping_backlog_load(queue, &model));
    acknowledge(&model, SIZE_MAX);
    CHECK(nm_ping_backlog_save(queue, &model));
    CHECK(nm_ping_backlog_pending(queue, &model) == 0);
    nm_ping_backlog_free(queue);
    nm_model_close(&model);
}
static void start_correction(nm_ping_backlog *q, nm_model *m, int64_t offset)
{
    nm_model candidate = {0};
    CHECK(nm_model_clone(&candidate, m));
    CHECK(nm_monitor_time_begin(&candidate, offset, nm_ping_backlog_pages(q)));
    nm_ping_backlog_time_begin(q);
    CHECK(nm_ping_backlog_save(q, &candidate));
    nm_model_close(m);
    *m = candidate;
}
static void test_time_rewrite(void)
{
    for (unsigned mode = NM_PING_STORAGE_NVS; mode <= NM_PING_STORAGE_SD; ++mode) {
        reset((nm_ping_storage_mode)mode);
        nm_model m = {0};
        nm_ping_backlog *q = open_model(&m);
        /* Full logical NVS ring exercises the spare slot, not just free space. */
        unsigned pages = mode == NM_PING_STORAGE_NVS ? 64 : 100;
        for (unsigned i = 0; i < pages; ++i) {
            probe(&m, 64);
            for (size_t j = 0; j < m.pings.count; ++j) {
                nm_ping_record *p = (nm_ping_record *)nm_records_edit(&m.pings, j);
                p->DateSentInt = p->ID % 2 ? 150 : 250;
            }
            CHECK(nm_ping_backlog_save(q, &m));
        }
        m.clock = (nm_time_state){.present = true, .valid = true, .low = 100, .high = 200};
        start_correction(q, &m, 1000);
        CHECK(m.clock.correcting && m.clock.remaining == pages);
        for (unsigned i = 0; i < pages; ++i) {
            fail_checkpoint = true;
            uint64_t remaining = m.clock.remaining;
            CHECK(!nm_ping_backlog_time_step(q, &m));
            CHECK(m.clock.remaining == remaining);
            fail_checkpoint = false;
            CHECK(nm_ping_backlog_time_step(q, &m));
            /* Restart after EVERY committed step, including the final one. */
            nm_model_close(&m);
            nm_ping_backlog_free(q);
            q = open_model(&m);
            CHECK(m.clock.remaining == pages - i - 1);
        }
        CHECK(!m.clock.correcting && m.clock.valid);
        CHECK(nm_ping_backlog_pending(q, &m) == (uint64_t)pages * 64);
        size_t seen = 0;
        while (nm_ping_backlog_pending(q, &m)) {
            CHECK(nm_ping_backlog_load(q, &m));
            for (size_t i = 0; i < m.pings.count; ++i) {
                nm_ping_record *p = (nm_ping_record *)m.pings.items[i];
                CHECK(p->DateSentInt == (p->ID % 2 ? 150U : 1250U));
                ++seen;
            }
            acknowledge(&m, SIZE_MAX);
            CHECK(nm_ping_backlog_save(q, &m));
        }
        CHECK(seen == (size_t)pages * 64);
        nm_model_close(&m);
        nm_ping_backlog_free(q);
    }
}
static void test_time_rewrite_failures(void)
{
    reset(NM_PING_STORAGE_SD);
    nm_model m = {0};
    nm_ping_backlog *q = open_model(&m);
    probe(&m, 100);
    CHECK(nm_ping_backlog_save(q, &m));
    start_correction(q, &m, 10);
    nm_test_ping_fail_read = true;
    CHECK(!nm_ping_backlog_time_step(q, &m));
    nm_test_ping_fail_read = false;
    nm_test_ping_fail_write = true;
    CHECK(!nm_ping_backlog_time_step(q, &m));
    nm_test_ping_fail_write = false;
    CHECK(m.clock.remaining == 2);
    allocations = 0;
    CHECK(nm_ping_backlog_time_step(q, &m));
    size_t calls = allocations;
    nm_model_close(&m);
    nm_ping_backlog_free(q);
    for (size_t fail = 1; fail <= calls; ++fail) {
        reset(NM_PING_STORAGE_SD);
        q = open_model(&m);
        probe(&m, 100);
        CHECK(nm_ping_backlog_save(q, &m));
        start_correction(q, &m, 10);
        allocations = 0;
        fail_allocation = fail;
        bool ok = nm_ping_backlog_time_step(q, &m);
        fail_allocation = 0;
        CHECK(m.clock.remaining == (ok ? 1U : 2U));
        nm_model_close(&m);
        nm_ping_backlog_free(q);
        q = open_model(&m);
        CHECK(m.clock.remaining == (ok ? 1U : 2U));
        while (m.clock.correcting)
            CHECK(nm_ping_backlog_time_step(q, &m));
        nm_model_close(&m);
        nm_ping_backlog_free(q);
    }
}
int main(void)
{
    test_time_rewrite();
    test_time_rewrite_failures();
    test_large_backlog();
    test_failures();
    test_capacity_and_switch();
    test_wire_types_and_corruption();
    test_allocation_failures();
    test_rollover_and_removed_parent();
    reset(NM_PING_STORAGE_NONE);
    puts("PASS storage-backed PingInfos: bounded RAM, reboot, acknowledgements, failures, "
         "capacity, switching, uint64 and corruption");
    return 0;
}
