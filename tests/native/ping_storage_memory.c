#include "ping_storage_memory.h"
#include <stdlib.h>
#include <string.h>

nm_ping_storage_mode nm_test_ping_mode;
nm_ping_storage_capacity nm_test_ping_capacity;
bool nm_test_ping_fail_read, nm_test_ping_fail_write, nm_test_ping_fail_delete;
unsigned nm_test_ping_writes, nm_test_ping_deletes;
static struct {
    uint64_t epoch, page;
    char *json;
} pages[4096];

static bool rotating;
static uint64_t split;
static unsigned first;
void nm_ping_storage_layout(bool enabled, uint64_t boundary, unsigned slot)
{
    rotating = enabled;
    split = boundary;
    first = slot;
}
void nm_test_ping_reset(void)
{
    for (size_t i = 0; i < 4096; ++i) {
        free(pages[i].json);
        pages[i].json = NULL;
    }
    nm_ping_storage_layout(false, 0, 0);
    nm_test_ping_mode = NM_PING_STORAGE_NONE;
    nm_test_ping_capacity = (nm_ping_storage_capacity){.healthy = true,
                                                       .free_bytes = UINT64_C(1024) * 1024 * 1024,
                                                       .reserve_bytes = 8 * 1024 * 1024};
    nm_test_ping_fail_read = nm_test_ping_fail_write = nm_test_ping_fail_delete = false;
    nm_test_ping_writes = nm_test_ping_deletes = 0;
}
nm_ping_storage_mode nm_ping_storage_selected(void)
{
    return nm_test_ping_mode;
}
nm_ping_storage_capacity nm_ping_storage_space(void)
{
    return nm_test_ping_capacity;
}
static size_t find(uint64_t epoch, uint64_t page)
{
    if (nm_test_ping_mode == NM_PING_STORAGE_NVS) {
        if (rotating && page >= split) {
            unsigned index = (unsigned)((page - split) % (NM_PING_NVS_PAGES + 1));
            return index ? (first + index - 1) % NM_PING_NVS_PAGES : NM_PING_NVS_PAGES;
        }
        return page % NM_PING_NVS_PAGES;
    }
    for (size_t i = 0; i < 4096; ++i)
        if (pages[i].json && pages[i].epoch == epoch && pages[i].page == page)
            return i;
    return 4096;
}
yyjson_mut_doc *nm_ping_storage_read(uint64_t epoch, uint64_t page)
{
    size_t i = find(epoch, page);
    return !nm_test_ping_fail_read && i < 4096 && pages[i].json
               ? nm_json_read(pages[i].json, strlen(pages[i].json))
               : NULL;
}
bool nm_ping_storage_write(uint64_t epoch, uint64_t page, yyjson_mut_val *value)
{
    ++nm_test_ping_writes;
    if (nm_test_ping_fail_write)
        return false;
    size_t i = find(epoch, page);
    if (i == 4096)
        for (i = 0; i < 4096 && pages[i].json; ++i) {
        }
    if (i == 4096)
        return false;
    size_t length = 0;
    char *json = nm_json_write(value, 0, &length);
    if (!json || length > NM_PING_PAGE_BYTES) {
        free(json);
        return false;
    }
    free(pages[i].json);
    pages[i].json = json;
    pages[i].epoch = epoch;
    pages[i].page = page;
    return true;
}
bool nm_ping_storage_delete(uint64_t epoch, uint64_t page)
{
    ++nm_test_ping_deletes;
    if (nm_test_ping_fail_delete)
        return false;
    size_t i = find(epoch, page);
    if (i < 4096 && pages[i].epoch == epoch && pages[i].page == page) {
        free(pages[i].json);
        pages[i].json = NULL;
    }
    return true;
}
void nm_ping_storage_collect(uint64_t epoch, uint64_t head, uint64_t tail)
{
    (void)epoch;
    (void)head;
    (void)tail;
}
void nm_ping_storage_begin(uint64_t epoch, uint64_t head, uint64_t tail)
{
    (void)epoch;
    (void)head;
    (void)tail;
}
