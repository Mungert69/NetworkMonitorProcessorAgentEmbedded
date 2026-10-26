#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "ping_storage.h"
#include "sd_card.h"
#include "monitor_numbers.h"
#include "nvs.h"
#include "nvs_flash.h"
#include <errno.h>
#include <dirent.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static nm_ping_storage_mode selected;
static const char *sd_directory;
static bool rotating_layout;
static uint64_t layout_split;
static unsigned layout_first;
void nm_ping_storage_layout(bool rotating, uint64_t split, unsigned first_slot)
{
    rotating_layout = rotating;
    layout_split = split;
    layout_first = first_slot;
}

bool nm_ping_storage_init(yyjson_mut_val *settings, const char *identity)
{
    nm_ping_storage_layout(false, 0, 0);
    sd_directory = nm_sd_card_mount(settings, identity);
    selected = sd_directory ? NM_PING_STORAGE_SD : NM_PING_STORAGE_NVS;
    return true;
}

nm_ping_storage_mode nm_ping_storage_selected(void)
{
    return selected;
}

nm_ping_storage_capacity nm_ping_storage_space(void)
{
    nm_ping_storage_capacity result = {0};
    if (selected == NM_PING_STORAGE_SD) {
        result.reserve_bytes = 8 * 1024 * 1024;
        result.healthy = nm_sd_card_space(&result.free_bytes);
    } else if (selected == NM_PING_STORAGE_NVS) {
        nvs_stats_t stats;
        result.reserve_bytes = 256 * 1024;
        result.healthy = nvs_get_stats("nmdata", &stats) == ESP_OK;
        /* NVS entries are 32 bytes, including metadata. Use 16 as a conservative
         * payload estimate, leaving additional space for GC and root replacement. */
        if (result.healthy)
            result.free_bytes = (uint64_t)stats.available_entries * 16;
    }
    return result;
}

enum {
    SEGMENT_HEADER = 24,
    BLOCK_HEADER = 16,
    SEGMENT_MAX_BYTES =
        SEGMENT_HEADER + NM_PING_SD_SEGMENT_PAGES * (BLOCK_HEADER + NM_PING_PAGE_BYTES)
};
static const uint8_t segment_magic[8] = {'N', 'M', 'P', 'S', 'E', 'G', 1, '\n'};
static uint64_t durable_epoch, durable_head, durable_tail;

void nm_ping_storage_begin(uint64_t epoch, uint64_t head, uint64_t tail)
{
    durable_epoch = epoch;
    durable_head = head;
    durable_tail = tail;
}
static uint64_t read_u64(const uint8_t *bytes)
{
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i)
        value |= (uint64_t)bytes[i] << (8 * i);
    return value;
}
static uint32_t read_u32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) | ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}
static void write_integer(uint8_t *bytes, uint64_t value, unsigned width)
{
    for (unsigned i = 0; i < width; ++i)
        bytes[i] = (uint8_t)(value >> (8 * i));
}
/* Up to 32 immutable logical blocks share one append-only FAT segment. Bounds
 * apply to every header/seek; no whole-segment buffer or index is resident. */
static bool page_directory(char *out, size_t capacity, uint64_t epoch, uint64_t segment,
                           bool create)
{
    if (!sd_directory)
        return false;
    int n = snprintf(out, capacity, "%s/%016" PRIx64, sd_directory, epoch);
    if (n <= 0 || (size_t)n >= capacity || (create && mkdir(out, 0700) && errno != EEXIST))
        return false;
    size_t used = (size_t)n;
    n = snprintf(out + used, capacity - used, "/%016" PRIx64, segment / 1024);
    return n > 0 && (size_t)n < capacity - used &&
           (!create || mkdir(out, 0700) == 0 || errno == EEXIST);
}
static bool path(char *out, size_t capacity, uint64_t epoch, uint64_t page)
{
    uint64_t segment = page / NM_PING_SD_SEGMENT_PAGES;
    if (!page_directory(out, capacity, epoch, segment, false))
        return false;
    size_t used = strlen(out);
    int n = snprintf(out + used, capacity - used, "/%016" PRIx64 ".seg", segment);
    return n > 0 && (size_t)n < capacity - used;
}
/* Locate a block's header by scanning at most 31 small headers. A write to this
 * position only changes the uncommitted suffix; read callers validate the target
 * block as well. first_page can be inside a segment after an empty-queue reset. */
static bool segment_position(FILE *file, uint64_t epoch, uint64_t page, long *position)
{
    uint8_t header[SEGMENT_HEADER];
    struct stat st;
    if (fstat(fileno(file), &st) || st.st_size < SEGMENT_HEADER || st.st_size > SEGMENT_MAX_BYTES ||
        fseek(file, 0, SEEK_SET) || fread(header, 1, sizeof(header), file) != sizeof(header) ||
        memcmp(header, segment_magic, sizeof(segment_magic)) || read_u64(header + 8) != epoch)
        return false;
    uint64_t first = read_u64(header + 16);
    if (first > page || first / NM_PING_SD_SEGMENT_PAGES != page / NM_PING_SD_SEGMENT_PAGES)
        return false;
    long offset = SEGMENT_HEADER;
    for (uint64_t current = first; current < page; ++current) {
        uint8_t block[BLOCK_HEADER];
        if (fread(block, 1, sizeof(block), file) != sizeof(block))
            return false;
        uint32_t length = read_u32(block);
        if (!length || length > NM_PING_PAGE_BYTES || read_u32(block + 4) != ~length ||
            read_u64(block + 8) != current ||
            (uint64_t)offset + BLOCK_HEADER + length > (uint64_t)st.st_size)
            return false;
        offset += BLOCK_HEADER + (long)length;
        if (fseek(file, offset, SEEK_SET))
            return false;
    }
    *position = offset;
    return true;
}
static char *read_sd(uint64_t epoch, uint64_t page, size_t *length)
{
    char name[176];
    if (!path(name, sizeof(name), epoch, page))
        return NULL;
    FILE *file = fopen(name, "rb");
    if (!file)
        return NULL;
    long offset;
    uint8_t block[BLOCK_HEADER];
    bool ok = segment_position(file, epoch, page, &offset) &&
              fread(block, 1, sizeof(block), file) == sizeof(block);
    uint32_t size = ok ? read_u32(block) : 0;
    ok = ok && size > 0 && size <= NM_PING_PAGE_BYTES && read_u32(block + 4) == ~size &&
         read_u64(block + 8) == page;
    char *bytes = ok ? nm_bulk_malloc(size) : NULL;
    ok = bytes && fread(bytes, 1, size, file) == size && !ferror(file);
    if (fclose(file))
        ok = false;
    if (!ok) {
        free(bytes);
        return NULL;
    }
    *length = size;
    return bytes;
}
static bool write_sd(uint64_t epoch, uint64_t page, const char *bytes, size_t length)
{
    if (durable_epoch != epoch || page < durable_tail)
        return false;
    char name[176], folder[160];
    uint64_t segment = page / NM_PING_SD_SEGMENT_PAGES;
    if (!page_directory(folder, sizeof(folder), epoch, segment, true) ||
        !path(name, sizeof(name), epoch, page))
        return false;
    FILE *file = fopen(name, "r+b");
    bool created = false;
    if (!file && errno == ENOENT) {
        file = fopen(name, "w+b");
        created = file != NULL;
    }
    if (!file)
        return false;
    long offset = 0;
    bool positioned = !created && segment_position(file, epoch, page, &offset);
    if (!positioned) {
        uint64_t first = segment * NM_PING_SD_SEGMENT_PAGES;
        uint64_t last = first + NM_PING_SD_SEGMENT_PAGES - 1;
        bool referenced = durable_epoch == epoch && durable_head < durable_tail &&
                          first < durable_tail && last >= durable_head;
        bool first_write = page == durable_tail || page % NM_PING_SD_SEGMENT_PAGES == 0;
        /* Recover an orphaned/torn new segment only at the first staged block.
         * A damaged prefix containing live or already-staged blocks fails closed. */
        if (referenced || !first_write || fseek(file, 0, SEEK_SET)) {
            fclose(file);
            return false;
        }
        uint8_t header[SEGMENT_HEADER];
        memcpy(header, segment_magic, sizeof(segment_magic));
        write_integer(header + 8, epoch, 8);
        write_integer(header + 16, page, 8);
        positioned = fwrite(header, 1, sizeof(header), file) == sizeof(header);
        offset = SEGMENT_HEADER;
    }
    uint8_t block[BLOCK_HEADER];
    write_integer(block, length, 4);
    write_integer(block + 4, ~(uint32_t)length, 4);
    write_integer(block + 8, page, 8);
    bool ok = positioned && fflush(file) == 0 && ftruncate(fileno(file), offset) == 0 &&
              fseek(file, offset, SEEK_SET) == 0 &&
              fwrite(block, 1, sizeof(block), file) == sizeof(block) &&
              fwrite(bytes, 1, length, file) == length && fflush(file) == 0 &&
              fsync(fileno(file)) == 0;
    if (fclose(file))
        ok = false;
    return ok;
}

static void key(char out[16], uint64_t page)
{
    unsigned slot = (unsigned)(page % NM_PING_NVS_PAGES);
    if (rotating_layout && page >= layout_split) {
        unsigned index = (unsigned)((page - layout_split) % (NM_PING_NVS_PAGES + 1));
        slot = index ? (layout_first + index - 1) % NM_PING_NVS_PAGES : NM_PING_NVS_PAGES;
    }
    snprintf(out, 16, "p%02u", slot);
}

yyjson_mut_doc *nm_ping_storage_read(uint64_t epoch, uint64_t page)
{
    char *bytes = NULL;
    size_t length = 0;
    if (selected == NM_PING_STORAGE_SD) {
        bytes = read_sd(epoch, page, &length);
    } else if (selected == NM_PING_STORAGE_NVS) {
        char name[16];
        key(name, page);
        nvs_handle_t handle;
        if (nvs_open_from_partition("nmdata", "nmpings", NVS_READONLY, &handle) != ESP_OK)
            return NULL;
        bool ok = nvs_get_blob(handle, name, NULL, &length) == ESP_OK && length > 0 &&
                  length <= NM_PING_PAGE_BYTES;
        if (ok) {
            bytes = nm_bulk_malloc(length);
            ok = bytes && nvs_get_blob(handle, name, bytes, &length) == ESP_OK;
        }
        nvs_close(handle);
        if (!ok) {
            free(bytes);
            return NULL;
        }
    }
    yyjson_mut_doc *doc = bytes ? nm_json_read(bytes, length) : NULL;
    free(bytes);
    return doc;
}

bool nm_ping_storage_write(uint64_t epoch, uint64_t page, yyjson_mut_val *value)
{
    size_t length = 0;
    char *bytes = nm_json_write(value, 0, &length);
    if (!bytes || !length || length > NM_PING_PAGE_BYTES) {
        free(bytes);
        return false;
    }
    bool ok = false;
    if (selected == NM_PING_STORAGE_SD) {
        ok = write_sd(epoch, page, bytes, length);
    } else if (selected == NM_PING_STORAGE_NVS) {
        char name[16];
        key(name, page);
        nvs_handle_t handle;
        if (nvs_open_from_partition("nmdata", "nmpings", NVS_READWRITE, &handle) == ESP_OK) {
            ok =
                nvs_set_blob(handle, name, bytes, length) == ESP_OK && nvs_commit(handle) == ESP_OK;
            nvs_close(handle);
        }
    }
    free(bytes);
    return ok;
}

bool nm_ping_storage_delete(uint64_t epoch, uint64_t page)
{
    if (selected == NM_PING_STORAGE_SD) {
        if (page % NM_PING_SD_SEGMENT_PAGES != NM_PING_SD_SEGMENT_PAGES - 1)
            return true; /* Reclaim only complete segments; never rewrite live blocks. */
        char name[176];
        return path(name, sizeof(name), epoch, page) && (unlink(name) == 0 || errno == ENOENT);
    }
    if (selected == NM_PING_STORAGE_NVS) {
        char name[16];
        key(name, page);
        /* A cleanup cursor can lag a whole ring after a reset or failed erase.
         * Never erase a newer page that has since reused the same NVS key. */
        yyjson_mut_doc *doc = nm_ping_storage_read(epoch, page);
        uint64_t stored_epoch = 0, stored_page = 0;
        yyjson_mut_val *root = yyjson_mut_doc_get_root(doc);
        bool same = doc && nm_monitor_u64(yyjson_mut_obj_get(root, "Epoch"), &stored_epoch) &&
                    nm_monitor_u64(yyjson_mut_obj_get(root, "Page"), &stored_page) &&
                    stored_epoch == epoch && stored_page == page;
        yyjson_mut_doc_free(doc);
        if (!same)
            return true;
        nvs_handle_t handle;
        if (nvs_open_from_partition("nmdata", "nmpings", NVS_READWRITE, &handle) != ESP_OK)
            return false;
        esp_err_t error = nvs_erase_key(handle, name);
        bool ok =
            (error == ESP_OK || error == ESP_ERR_NVS_NOT_FOUND) && nvs_commit(handle) == ESP_OK;
        nvs_close(handle);
        return ok;
    }
    return false;
}

static bool hex_id(const char *name, uint64_t *id)
{
    if (strlen(name) != 16)
        return false;
    uint64_t value = 0;
    for (size_t i = 0; i < 16; ++i) {
        unsigned char c = (unsigned char)name[i];
        unsigned digit;
        if (c >= '0' && c <= '9')
            digit = c - '0';
        else if (c >= 'a' && c <= 'f')
            digit = c - 'a' + 10;
        else
            return false;
        value = (value << 4) | digit;
    }
    *id = value;
    return true;
}

static void collect_nvs(uint64_t epoch, uint64_t head, uint64_t tail)
{
    static unsigned cursor;
    nvs_handle_t handle;
    if (nvs_open_from_partition("nmdata", "nmpings", NVS_READWRITE, &handle) != ESP_OK)
        return;
    bool changed = false;
    for (unsigned i = 0; i < 8; ++i) {
        char name[16];
        snprintf(name, sizeof(name), "p%02u", cursor++ % (NM_PING_NVS_PAGES + 1));
        bool obsolete = selected == NM_PING_STORAGE_SD;
        if (!obsolete) {
            size_t size = 0;
            if (nvs_get_blob(handle, name, NULL, &size) != ESP_OK || !size ||
                size > NM_PING_PAGE_BYTES)
                continue;
            char *text = nm_bulk_malloc(size);
            yyjson_mut_doc *doc = text && nvs_get_blob(handle, name, text, &size) == ESP_OK
                                      ? nm_json_read(text, size)
                                      : NULL;
            free(text);
            uint64_t stored_epoch, page;
            yyjson_mut_val *root = yyjson_mut_doc_get_root(doc);
            bool valid = doc && nm_monitor_u64(yyjson_mut_obj_get(root, "Epoch"), &stored_epoch) &&
                         nm_monitor_u64(yyjson_mut_obj_get(root, "Page"), &page);
            obsolete = valid && (stored_epoch != epoch || page < head || page >= tail);
            yyjson_mut_doc_free(doc);
        }
        if (obsolete && nvs_erase_key(handle, name) == ESP_OK)
            changed = true;
    }
    if (changed)
        (void)nvs_commit(handle); /* Failed cleanup is retried on a later pass. */
    nvs_close(handle);
}

void nm_ping_storage_collect(uint64_t epoch, uint64_t head, uint64_t tail)
{
    collect_nvs(epoch, head, tail);
    if (selected != NM_PING_STORAGE_SD)
        return;
    /* Retain directory cursors across cycles, with fixed work per call. Only
     * canonical page paths under this identity's directory are ever removed. */
    static DIR *root, *epochs, *groups;
    static char epoch_path[144], group_path[168];
    static uint64_t scan_epoch, scan_group;
    if (!root)
        root = opendir(sd_directory);
    for (unsigned step = 0; root && step < 96; ++step) {
        DIR *current = groups ? groups : epochs ? epochs : root;
        struct dirent *entry = readdir(current);
        if (!entry) {
            closedir(current);
            if (groups) {
                groups = NULL;
                (void)rmdir(group_path);
            } else if (epochs) {
                epochs = NULL;
                (void)rmdir(epoch_path);
            } else {
                root = NULL;
            }
            continue;
        }
        if (groups) {
            size_t length = strlen(entry->d_name);
            if (length != 20 || strcmp(entry->d_name + 16, ".seg"))
                continue;
            char id[17];
            memcpy(id, entry->d_name, 16);
            id[16] = 0;
            uint64_t segment;
            if (!hex_id(id, &segment) || segment / 1024 != scan_group ||
                segment > UINT64_MAX / NM_PING_SD_SEGMENT_PAGES)
                continue;
            uint64_t first = segment * NM_PING_SD_SEGMENT_PAGES;
            uint64_t last = first + NM_PING_SD_SEGMENT_PAGES - 1;
            if (scan_epoch != epoch || head == tail || last < head || first >= tail) {
                char name[192];
                int n = snprintf(name, sizeof(name), "%s/%s", group_path, entry->d_name);
                if (n > 0 && (size_t)n < sizeof(name))
                    (void)unlink(name);
            }
        } else {
            uint64_t id;
            if (!hex_id(entry->d_name, &id))
                continue;
            char *destination = epochs ? group_path : epoch_path;
            size_t capacity = epochs ? sizeof(group_path) : sizeof(epoch_path);
            int n = snprintf(destination, capacity, "%s/%s", epochs ? epoch_path : sd_directory,
                             entry->d_name);
            if (n <= 0 || (size_t)n >= capacity)
                continue;
            if (epochs) {
                scan_group = id;
                groups = opendir(destination);
            } else {
                scan_epoch = id;
                epochs = opendir(destination);
            }
        }
    }
}
