#include "ping_backlog.h"
#include "storage_checkpoint.h"
#include "monitor_time.h"
#include "monitor_numbers.h"
#include "nm_esp.h"
#include "esp_log.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define GET yyjson_mut_obj_get
typedef struct {
    uint64_t page, mask, ids[NM_PING_PAGE_RECORDS];
    size_t count;
} ping_window;
typedef struct {
    int32_t monitor_id;
    uint64_t before_page;
} ping_discard;
struct nm_ping_backlog {
    uint64_t epoch, head, tail, count, durable_head, cleanup_head;
    bool rotating, stamp_utc;
    uint64_t split;
    unsigned first_slot;
    ping_window window[NM_PING_WINDOW_PAGES];
    ping_discard discard[NM_ESP_MAX_MONITORS];
    size_t discards;
    size_t windows, window_limit;
    nm_ping_storage_mode mode;
    bool failed, read_failed, wrapped, capacity_paused;
    uint32_t sequence;
    uint32_t scan_sequence;
    size_t scan_results;
    uint64_t scan_page;
    uint64_t sample_time, bytes_written, sample_bytes, bytes_per_hour, pages_written;
};

static bool discarded(const nm_ping_backlog *q, int32_t monitor_id, uint64_t page)
{
    for (size_t i = 0; i < q->discards; ++i)
        if (q->discard[i].monitor_id == monitor_id && page < q->discard[i].before_page)
            return true;
    return false;
}
static void prune_discards(nm_ping_backlog *q)
{
    for (size_t i = q->discards; i > 0; --i)
        if (q->discard[i - 1].before_page <= q->head) {
            memmove(q->discard + i - 1, q->discard + i, (q->discards - i) * sizeof(*q->discard));
            --q->discards;
        }
}

static const char *mode_name(nm_ping_storage_mode mode)
{
    return mode == NM_PING_STORAGE_SD ? "sd" : "nvs";
}
static unsigned bits(uint64_t mask)
{
    unsigned n = 0;
    for (; mask; mask &= mask - 1)
        ++n;
    return n;
}
static bool contains(const nm_records *records, uint64_t id)
{
    for (size_t i = 0; i < records->count; ++i)
        if (((nm_ping_record *)records->items[i])->ID == id)
            return true;
    return false;
}
static bool window_id(const nm_ping_backlog *q, uint64_t id)
{
    for (size_t w = 0; w < q->windows; ++w)
        for (size_t i = 0; i < q->window[w].count; ++i)
            if ((q->window[w].mask & (UINT64_C(1) << i)) && q->window[w].ids[i] == id)
                return true;
    return false;
}
static uint64_t remaining_mask(const ping_window *window, const nm_model *model)
{
    uint64_t mask = window->mask;
    for (size_t i = 0; i < window->count; ++i)
        if (!contains(&model->pings, window->ids[i]))
            mask &= ~(UINT64_C(1) << i);
    return mask;
}
void nm_ping_backlog_delivery_view(const nm_ping_backlog *q, nm_model *view)
{
    for (size_t i = view->pings.count; i > 0; --i)
        if (!window_id(q, ((nm_ping_record *)view->pings.items[i - 1])->ID))
            nm_records_remove(&view->pings, i - 1);
}
uint64_t nm_ping_backlog_pending(const nm_ping_backlog *q, const nm_model *model)
{
    uint64_t count = q->count;
    for (size_t w = 0; w < q->windows; ++w)
        count -= bits(q->window[w].mask) - bits(remaining_mask(&q->window[w], model));
    for (size_t i = 0; i < model->pings.count; ++i)
        if (!window_id(q, ((nm_ping_record *)model->pings.items[i])->ID))
            ++count;
    return count;
}
/* Detect valid-JSON corruption as well as truncated/misrouted pages. This is an
 * integrity checksum, not a security signature; commands retain their own gates. */
static bool checksum(yyjson_mut_val *array, uint64_t *result)
{
    size_t length = 0;
    char *text = nm_json_write(array, 0, &length);
    if (!text)
        return false;
    uint64_t hash = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < length; ++i)
        hash = (hash ^ (unsigned char)text[i]) * UINT64_C(1099511628211);
    free(text);
    *result = hash;
    return true;
}
static yyjson_mut_doc *read_page(const nm_ping_backlog *q, uint64_t page)
{
    yyjson_mut_doc *doc = nm_ping_storage_read(q->epoch, page);
    yyjson_mut_val *root = yyjson_mut_doc_get_root(doc), *pings = GET(root, "PingInfos");
    uint64_t epoch, number, stored, actual;
    if (!doc || !nm_monitor_u64(GET(root, "Epoch"), &epoch) || epoch != q->epoch ||
        !nm_monitor_u64(GET(root, "Page"), &number) || number != page ||
        !yyjson_mut_is_arr(pings) || !yyjson_mut_arr_size(pings) ||
        yyjson_mut_arr_size(pings) > NM_PING_PAGE_RECORDS ||
        !nm_monitor_u64(GET(root, "Checksum"), &stored) || !checksum(pings, &actual) ||
        stored != actual) {
        yyjson_mut_doc_free(doc);
        return NULL;
    }
    return doc;
}

nm_ping_backlog *nm_ping_backlog_open(yyjson_mut_val *snapshot, nm_model *model, uint64_t nonce,
                                      size_t window_records)
{
    nm_ping_backlog *q = nm_bulk_calloc(1, sizeof(*q));
    if (!q)
        return NULL;
    q->mode = nm_ping_storage_selected();
    q->epoch = nonce ? nonce : 1;
    q->sequence = model->sequence;
    q->window_limit = window_records / NM_PING_PAGE_RECORDS;
    if (!q->window_limit)
        q->window_limit = 1;
    if (q->window_limit > NM_PING_WINDOW_PAGES)
        q->window_limit = NM_PING_WINDOW_PAGES;
    yyjson_mut_val *meta = GET(snapshot, "PingBacklog"), *mode = GET(meta, "Store");
    if (meta && (!yyjson_mut_is_str(mode) || (strcmp(yyjson_mut_get_str(mode), "sd") &&
                                              strcmp(yyjson_mut_get_str(mode), "nvs"))))
        goto fail;
    if (meta && yyjson_mut_is_str(mode) && !strcmp(yyjson_mut_get_str(mode), mode_name(q->mode))) {
        uint32_t version;
        if (!nm_monitor_u32(GET(meta, "Version"), &version) || version != 1 ||
            !nm_monitor_u64(GET(meta, "Epoch"), &q->epoch) || !q->epoch ||
            !nm_monitor_u64(GET(meta, "Head"), &q->head) ||
            !nm_monitor_u64(GET(meta, "Tail"), &q->tail) || q->head > q->tail ||
            !nm_monitor_u64(GET(meta, "CleanupHead"), &q->cleanup_head) ||
            q->cleanup_head > q->head || !nm_monitor_u64(GET(meta, "Count"), &q->count) ||
            q->count > UINT32_MAX - 1024 || q->tail - q->head > UINT32_MAX / NM_PING_PAGE_RECORDS ||
            q->count > (q->tail - q->head) * NM_PING_PAGE_RECORDS ||
            (q->mode == NM_PING_STORAGE_NVS && q->tail - q->head > NM_PING_NVS_PAGES))
            goto fail;
        if (GET(meta, "NvsRotate")) {
            uint32_t slot;
            if (!yyjson_mut_is_bool(GET(meta, "NvsRotate")) ||
                !nm_monitor_u64(GET(meta, "NvsSplit"), &q->split) ||
                !nm_monitor_u32(GET(meta, "NvsFirst"), &slot) || slot >= NM_PING_NVS_PAGES)
                goto fail;
            q->rotating = yyjson_mut_is_true(GET(meta, "NvsRotate"));
            q->first_slot = slot;
            if (q->rotating && q->split > q->tail)
                goto fail;
        }
        yyjson_mut_val *masks = GET(meta, "Masks");
        if (!yyjson_mut_is_arr(masks) || yyjson_mut_arr_size(masks) > NM_PING_WINDOW_PAGES ||
            yyjson_mut_arr_size(masks) > q->tail - q->head)
            goto fail;
        q->windows = yyjson_mut_arr_size(masks);
        for (size_t i = 0; i < q->windows; ++i) {
            q->window[i].page = q->head + i;
            if (!nm_monitor_u64(yyjson_mut_arr_get(masks, i), &q->window[i].mask))
                goto fail;
        }
        uint64_t minimum = 0;
        for (size_t i = 0; i < q->windows; ++i)
            minimum += bits(q->window[i].mask);
        if (minimum > q->count)
            goto fail;
        /* A smaller setting must still restore all masks already committed. */
        if (q->window_limit < q->windows)
            q->window_limit = q->windows;
        q->wrapped = yyjson_mut_is_true(GET(meta, "Wrapped"));
        yyjson_mut_val *discards = GET(meta, "DiscardBefore");
        if (!yyjson_mut_is_arr(discards) || yyjson_mut_arr_size(discards) > NM_ESP_MAX_MONITORS)
            goto fail;
        q->discards = yyjson_mut_arr_size(discards);
        for (size_t i = 0; i < q->discards; ++i) {
            yyjson_mut_val *entry = yyjson_mut_arr_get(discards, i);
            if (!nm_monitor_i32(GET(entry, "MonitorIPID"), &q->discard[i].monitor_id) ||
                !nm_monitor_u64(GET(entry, "Page"), &q->discard[i].before_page) ||
                q->discard[i].before_page > q->tail)
                goto fail;
            for (size_t j = 0; j < i; ++j)
                if (q->discard[i].monitor_id == q->discard[j].monitor_id)
                    goto fail;
        }
    } else if (meta && !yyjson_mut_is_str(mode)) {
        goto fail;
    }
    q->durable_head = q->head;
    /* Explicit initial/switch policy: configuration and parents remain intact. */
    while (model->pings.count)
        nm_records_remove(&model->pings, model->pings.count - 1);
    model->pings.limit = NM_PING_WINDOW_RECORDS + model->hosts.limit;
    model->retain_infos = q->count != 0;
    nm_ping_storage_layout(q->rotating, q->split, q->first_slot);
    if (model->clock.correcting && model->clock.remaining > q->tail - q->head)
        goto fail;
    if (!nm_ping_backlog_load(q, model))
        goto fail;
    return q;
fail:
    free(q);
    return NULL;
}

void nm_ping_backlog_free(nm_ping_backlog *q)
{
    free(q);
}

bool nm_ping_backlog_load(nm_ping_backlog *q, nm_model *model)
{
    /* Build all new records in an independent collection so read/allocation
     * failures cannot partially replace the live working set. */
    nm_records added = {.limit = NM_PING_WINDOW_RECORDS};
    nm_ping_backlog *next = nm_bulk_malloc(sizeof(*next));
    if (!next) {
        q->failed = true;
        return false;
    }
    *next = *q;
    size_t windows = (size_t)(q->tail - q->head);
    if (windows > q->window_limit)
        windows = q->window_limit;
    bool ok = true;
    for (size_t w = 0; w < windows && ok; ++w) {
        if (w < q->windows && q->window[w].count)
            continue;
        yyjson_mut_doc *doc = read_page(q, q->head + w);
        yyjson_mut_val *array = GET(yyjson_mut_doc_get_root(doc), "PingInfos");
        size_t count = yyjson_mut_arr_size(array);
        uint64_t full = count == 64 ? UINT64_MAX : (UINT64_C(1) << count) - 1;
        ping_window *window = &next->window[w];
        window->page = q->head + w;
        window->count = count;
        if (w >= q->windows)
            window->mask = full;
        ok = doc && !(window->mask & ~full);
        for (size_t i = 0; i < count && ok; ++i) {
            nm_ping_record *record =
                (nm_ping_record *)nm_record_decode(NM_PING, yyjson_mut_arr_get(array, i));
            if (!record || !nm_record_has(&record->base, NM_P_ID) ||
                !nm_record_has(&record->base, NM_P_MonitorPingInfoID)) {
                nm_record_release((nm_record *)record);
                ok = false;
                break;
            }
            window->ids[i] = record->ID;
            bool pending = (window->mask & (UINT64_C(1) << i)) != 0;
            /* An acknowledged removed monitor has no parent. Its stored samples
             * follow .NET's remove-monitor acknowledgement semantics. */
            bool parent = nm_model_info(model, record->MonitorPingInfoID) ||
                          nm_model_host(model, record->MonitorPingInfoID);
            if (pending && parent && !discarded(q, record->MonitorPingInfoID, window->page)) {
                if (contains(&model->pings, record->ID) || contains(&added, record->ID) ||
                    !nm_records_append(&added, &record->base)) {
                    nm_record_release(&record->base);
                    ok = false;
                }
            } else {
                nm_record_release(&record->base);
            }
        }
        yyjson_mut_doc_free(doc);
    }
    uint64_t minimum = 0;
    for (size_t w = 0; w < windows; ++w)
        minimum += bits(next->window[w].mask);
    if (minimum > q->count)
        ok = false;
    if (ok) {
        nm_model candidate = {0};
        ok = nm_model_clone(&candidate, model);
        for (size_t i = 0; i < added.count && ok; ++i) {
            nm_record *record = nm_record_retain(added.items[i]);
            if (!nm_records_append(&candidate.pings, record)) {
                nm_record_release(record);
                ok = false;
            }
        }
        if (ok) {
            nm_model_close(model);
            *model = candidate;
            memset(&candidate, 0, sizeof(candidate));
            next->windows = windows;
            next->read_failed = false;
            *q = *next;
        }
        nm_model_close(&candidate);
    }
    nm_records_free(&added);
    free(next);
    if (!ok)
        q->read_failed = true;
    return ok;
}

static yyjson_mut_doc *metadata(const nm_ping_backlog *q)
{
    yyjson_mut_doc *doc = nm_json_new();
    if (!doc)
        return NULL;
    yyjson_mut_val *root = yyjson_mut_obj(doc), *masks = yyjson_mut_arr(doc),
                   *discards = yyjson_mut_arr(doc);
    yyjson_mut_doc_set_root(doc, root);
    bool ok = root && masks && discards && yyjson_mut_obj_add_uint(doc, root, "Version", 1) &&
              yyjson_mut_obj_add_str(doc, root, "Store", mode_name(q->mode)) &&
              yyjson_mut_obj_add_uint(doc, root, "Epoch", q->epoch) &&
              yyjson_mut_obj_add_uint(doc, root, "Head", q->head) &&
              yyjson_mut_obj_add_uint(doc, root, "Tail", q->tail) &&
              yyjson_mut_obj_add_uint(doc, root, "CleanupHead", q->cleanup_head) &&
              yyjson_mut_obj_add_uint(doc, root, "Count", q->count) &&
              yyjson_mut_obj_add_bool(doc, root, "NvsRotate", q->rotating) &&
              yyjson_mut_obj_add_uint(doc, root, "NvsSplit", q->split) &&
              yyjson_mut_obj_add_uint(doc, root, "NvsFirst", q->first_slot) &&
              yyjson_mut_obj_add_bool(doc, root, "Wrapped", q->wrapped) &&
              yyjson_mut_obj_add_val(doc, root, "Masks", masks) &&
              yyjson_mut_obj_add_val(doc, root, "DiscardBefore", discards);
    for (size_t w = 0; w < q->windows && ok; ++w)
        ok = yyjson_mut_arr_add_uint(doc, masks, q->window[w].mask);
    for (size_t i = 0; i < q->discards && ok; ++i) {
        yyjson_mut_val *entry = yyjson_mut_obj(doc);
        ok = entry &&
             yyjson_mut_obj_add_sint(doc, entry, "MonitorIPID", q->discard[i].monitor_id) &&
             yyjson_mut_obj_add_uint(doc, entry, "Page", q->discard[i].before_page) &&
             yyjson_mut_arr_append(discards, entry);
    }
    if (!ok) {
        yyjson_mut_doc_free(doc);
        return NULL;
    }
    return doc;
}

static bool write_page(nm_ping_backlog *q, yyjson_mut_doc *doc, yyjson_mut_val *array)
{
    yyjson_mut_val *root = yyjson_mut_doc_get_root(doc);
    uint64_t hash = 0;
    size_t length = 0;
    bool ok = q->tail < UINT64_MAX && checksum(array, &hash) &&
              yyjson_mut_obj_add_uint(doc, root, "Epoch", q->epoch) &&
              yyjson_mut_obj_add_uint(doc, root, "Page", q->tail) &&
              yyjson_mut_obj_add_uint(doc, root, "Checksum", hash);
    char *text = ok ? nm_json_write(root, 0, &length) : NULL;
    ok = text && length <= NM_PING_PAGE_BYTES && nm_ping_storage_write(q->epoch, q->tail, root);
    free(text);
    if (ok) {
        ++q->tail;
        q->bytes_written += length + (q->mode == NM_PING_STORAGE_SD ? 16 : 64);
        ++q->pages_written;
    }
    return ok;
}

bool nm_ping_backlog_save(nm_ping_backlog *q, nm_model *model)
{
    nm_ping_backlog *next = nm_bulk_malloc(sizeof(*next));
    if (!next) {
        q->failed = true;
        q->stamp_utc = false;
        return false;
    }
    *next = *q;
    size_t new_count = 0;
    for (size_t i = 0; i < model->pings.count; ++i)
        if (!window_id(q, ((nm_ping_record *)model->pings.items[i])->ID))
            ++new_count;
    size_t pages = (new_count + NM_PING_PAGE_RECORDS - 1) / NM_PING_PAGE_RECORDS;
    nm_ping_storage_layout(q->rotating, q->split, q->first_slot);
    nm_ping_storage_begin(q->epoch, q->durable_head, q->tail);
    bool ok =
        q->count <= UINT32_MAX - 1024 - new_count &&
        (q->mode != NM_PING_STORAGE_NVS || q->tail - q->durable_head + pages <= NM_PING_NVS_PAGES);
    for (size_t w = 0; w < next->windows; ++w) {
        uint64_t mask = remaining_mask(&next->window[w], model);
        next->count -= bits(next->window[w].mask) - bits(mask);
        next->window[w].mask = mask;
    }
    size_t retired = 0;
    while (retired < next->windows && !next->window[retired].mask)
        ++retired;
    next->head += retired;
    next->windows -= retired;
    memmove(next->window, next->window + retired, next->windows * sizeof(*next->window));
    prune_discards(next);
    if (next->head == next->tail && next->count != 0)
        ok = false;
    yyjson_mut_doc *page = NULL;
    yyjson_mut_val *array = NULL;
    size_t in_page = 0;
    for (size_t i = 0; i < model->pings.count && ok; ++i) {
        if (window_id(q, ((nm_ping_record *)model->pings.items[i])->ID))
            continue;
        if (!page) {
            page = nm_json_new();
            yyjson_mut_val *root = page ? yyjson_mut_obj(page) : NULL;
            array = page ? yyjson_mut_arr(page) : NULL;
            if (page)
                yyjson_mut_doc_set_root(page, root);
            ok = root && array && yyjson_mut_obj_add_val(page, root, "PingInfos", array);
        }
        yyjson_mut_val *value = ok ? nm_record_encode(page, model->pings.items[i]) : NULL;
        ok = ok && value && yyjson_mut_arr_append(array, value);
        if (ok && (++in_page == NM_PING_PAGE_RECORDS || i + 1 == model->pings.count)) {
            ok = write_page(next, page, array);
            yyjson_mut_doc_free(page);
            page = NULL;
            in_page = 0;
        }
    }
    if (ok && page)
        ok = write_page(next, page, array);
    yyjson_mut_doc_free(page);
    next->count += new_count;
    next->wrapped = next->wrapped || model->sequence < q->sequence;
    next->sequence = model->sequence;
    /* Encode the existing state format, retaining opaque extension fields, but
     * with an empty PingInfos array and a private queue cursor at the root. */
    nm_model view = *model;
    view.pings.count = 0;
    yyjson_mut_doc *snapshot = ok ? nm_model_encode(&view) : NULL;
    yyjson_mut_doc *meta = ok ? metadata(next) : NULL;
    yyjson_mut_val *root = yyjson_mut_doc_get_root(snapshot);
    if (root)
        yyjson_mut_obj_remove_key(root, "PingBacklog");
    ok = snapshot && meta &&
         yyjson_mut_obj_add_val(snapshot, root, "PingBacklog",
                                yyjson_mut_val_mut_copy(snapshot, yyjson_mut_doc_get_root(meta))) &&
         (q->stamp_utc ? nm_storage_checkpoint_save_at(snapshot, time(NULL))
                       : nm_storage_checkpoint_save(snapshot));
    yyjson_mut_doc_free(snapshot);
    yyjson_mut_doc_free(meta);
    if (ok) {
        for (size_t i = model->pings.count; i > 0; --i)
            if (!window_id(q, ((nm_ping_record *)model->pings.items[i - 1])->ID))
                nm_records_remove(&model->pings, i - 1);
        /* Reclaim only pages no longer referenced by the durable root. Failure
         * wastes space but never loses an unacknowledged reading. */
        for (size_t i = 0; i < 32 && next->cleanup_head < next->head; ++i) {
            if (!nm_ping_storage_delete(q->epoch, next->cleanup_head)) {
                ESP_LOGW("nm_backlog", "acknowledged page cleanup deferred");
                break;
            }
            ++next->cleanup_head;
        }
        next->durable_head = next->head;
        nm_ping_storage_collect(next->epoch, next->head, next->tail);
        next->failed = false;
        next->stamp_utc = false;
        *q = *next;
        model->retain_infos = q->count != 0;
    } else {
        q->failed = true;
        q->stamp_utc = false; /* A failed marker must not stamp a later raw flush as UTC. */
    }
    free(next);
    return ok;
}

uint64_t nm_ping_backlog_pages(const nm_ping_backlog *q)
{
    return q->tail - q->head;
}
void nm_ping_backlog_time_begin(nm_ping_backlog *q)
{
    q->stamp_utc = true;
    if (q->mode == NM_PING_STORAGE_NVS && !q->rotating) {
        q->rotating = true;
        q->split = q->tail;
        q->first_slot = (unsigned)(q->head % NM_PING_NVS_PAGES);
    }
}
bool nm_ping_backlog_time_step(nm_ping_backlog *q, nm_model *model)
{
    if (!model->clock.correcting || !model->clock.remaining || q->head == q->tail)
        return false;
    nm_model candidate = {0};
    nm_ping_backlog *next = nm_bulk_malloc(sizeof(*next));
    if (!next)
        return false;
    *next = *q;
    bool ok = nm_model_clone(&candidate, model);
    yyjson_mut_doc *old = ok ? read_page(q, q->head) : NULL;
    yyjson_mut_val *old_array = GET(yyjson_mut_doc_get_root(old), "PingInfos");
    yyjson_mut_doc *page = nm_json_new();
    yyjson_mut_val *root = page ? yyjson_mut_obj(page) : NULL,
                   *array = page ? yyjson_mut_arr(page) : NULL;
    if (page)
        yyjson_mut_doc_set_root(page, root);
    ok = ok && old && root && array && yyjson_mut_obj_add_val(page, root, "PingInfos", array);
    size_t count = yyjson_mut_arr_size(old_array);
    uint64_t mask =
        q->windows ? q->window[0].mask : (count == 64 ? UINT64_MAX : (UINT64_C(1) << count) - 1);
    size_t kept = 0;
    for (size_t i = 0; i < count && ok; ++i) {
        if (!(mask & (UINT64_C(1) << i)))
            continue;
        nm_ping_record *ping =
            (nm_ping_record *)nm_record_decode(NM_PING, yyjson_mut_arr_get(old_array, i));
        ok = ping != NULL;
        if (ok && !discarded(q, ping->MonitorPingInfoID, q->head) &&
            (nm_model_info(model, ping->MonitorPingInfoID) ||
             nm_model_host(model, ping->MonitorPingInfoID))) {
            ok = nm_monitor_time_ping(ping, &candidate.clock);
            yyjson_mut_val *value = ok ? nm_record_encode(page, &ping->base) : NULL;
            ok = value && yyjson_mut_arr_append(array, value);
            ++kept;
        }
        if (ping) {
            for (size_t j = candidate.pings.count; j > 0; --j)
                if (((nm_ping_record *)candidate.pings.items[j - 1])->ID == ping->ID)
                    nm_records_remove(&candidate.pings, j - 1);
        }
        nm_record_release((nm_record *)ping);
    }
    if (ok) {
        nm_ping_storage_layout(q->rotating, q->split, q->first_slot);
        nm_ping_storage_begin(q->epoch, q->head, q->tail);
        if (kept)
            ok = write_page(next, page, array);
        ++next->head;
        next->count -= bits(mask) - kept;
        if (next->windows) {
            --next->windows;
            memmove(next->window, next->window + 1, next->windows * sizeof(*next->window));
        }
        --candidate.clock.remaining;
        if (!candidate.clock.remaining) {
            nm_monitor_time_finish(&candidate.clock);
            int64_t date = (int64_t)time(NULL) - INT64_C(1640995200);
            if (date >= 0 && date <= UINT32_MAX)
                nm_monitor_time_observe(&candidate.clock, (uint32_t)date);
        }
        prune_discards(next);
    }
    nm_model view = candidate;
    view.pings.count = 0;
    yyjson_mut_doc *snapshot = ok ? nm_model_encode(&view) : NULL,
                   *meta = ok ? metadata(next) : NULL;
    root = yyjson_mut_doc_get_root(snapshot);
    if (root)
        yyjson_mut_obj_remove_key(root, "PingBacklog");
    ok = ok && snapshot && meta &&
         yyjson_mut_obj_add_val(snapshot, root, "PingBacklog",
                                yyjson_mut_val_mut_copy(snapshot, yyjson_mut_doc_get_root(meta))) &&
         nm_storage_checkpoint_save_at(snapshot, time(NULL));
    if (ok) {
        nm_model_close(model);
        *model = candidate;
        memset(&candidate, 0, sizeof(candidate));
        uint64_t retired = q->head;
        next->durable_head = next->head;
        *q = *next;
        /* Cleanup is best effort and never determines correction durability. */
        (void)nm_ping_storage_delete(q->epoch, retired);
        nm_ping_storage_collect(q->epoch, q->head, q->tail);
    }
    yyjson_mut_doc_free(snapshot);
    yyjson_mut_doc_free(meta);
    yyjson_mut_doc_free(page);
    yyjson_mut_doc_free(old);
    nm_model_close(&candidate);
    free(next);
    return ok;
}

void nm_ping_backlog_reset(nm_ping_backlog *q)
{
    /* Uncommitted reset is still RAM-only. Advance head rather than reusing any
     * page referenced by the previous checkpoint before its replacement commits. */
    q->head = q->tail;
    q->count = 0;
    q->windows = 0;
    q->discards = 0;
    q->wrapped = false;
    q->sequence = 1;
}

bool nm_ping_backlog_ack(nm_ping_backlog *q, const nm_model *before, yyjson_mut_val *response)
{
    yyjson_mut_val *ids = GET(response, "RemoveMonitorPingInfoIDs");
    if (!yyjson_mut_arr_size(ids) || q->head == q->tail)
        return true;
    nm_ping_backlog *next = nm_bulk_malloc(sizeof(*next));
    if (!next)
        return false;
    *next = *q;
    prune_discards(next);
    size_t i, n;
    yyjson_mut_val *value;
    bool ok = true;
    yyjson_mut_arr_foreach(ids, i, n, value)
    {
        int32_t id;
        if (!nm_monitor_i32(value, &id)) {
            ok = false;
            break;
        }
        if (nm_model_host(before, id) || !nm_model_info(before, id))
            continue;
        size_t slot;
        for (slot = 0; slot < next->discards; ++slot)
            if (next->discard[slot].monitor_id == id)
                break;
        if (slot == NM_ESP_MAX_MONITORS) {
            ok = false;
            break;
        }
        next->discard[slot] = (ping_discard){.monitor_id = id, .before_page = q->tail};
        if (slot == next->discards)
            ++next->discards;
    }
    if (ok)
        *q = *next;
    free(next);
    return ok;
}

bool nm_ping_backlog_room(nm_ping_backlog *q, size_t maximum_results)
{
    nm_ping_storage_capacity space = nm_ping_storage_space();
    uint64_t pages = (maximum_results + NM_PING_PAGE_RECORDS - 1) / NM_PING_PAGE_RECORDS;
    /* FAT allocation units and directory updates can exceed JSON byte lengths.
     * Reserve 64 KiB per page on SD, 32 KiB per page in conservative NVS units. */
    uint64_t required_pages = pages + (q->capacity_paused ? 1 : 0);
    uint64_t needed = required_pages * (q->mode == NM_PING_STORAGE_SD ? 65536 : NM_PING_PAGE_BYTES);
    bool room = q->count <= UINT32_MAX - 1024 - maximum_results && space.healthy &&
                space.free_bytes > space.reserve_bytes &&
                space.free_bytes - space.reserve_bytes >= needed &&
                (q->mode != NM_PING_STORAGE_NVS ||
                 q->tail - q->durable_head + required_pages <= NM_PING_NVS_PAGES);
    q->capacity_paused = !room;
    return room && !q->failed && !q->read_failed;
}

bool nm_ping_backlog_sequence_safe(nm_ping_backlog *q, uint32_t sequence, size_t maximum_results)
{
    if (!q->wrapped && sequence >= q->sequence &&
        (uint64_t)sequence + maximum_results <= UINT32_MAX)
        return true;
    if (q->scan_sequence != sequence || q->scan_results != maximum_results) {
        q->scan_sequence = sequence;
        q->scan_results = maximum_results;
        q->scan_page = q->head;
    }
    if (q->scan_page < q->head)
        q->scan_page = q->head;
    /* Rollover checks must not scan a years-long backlog in one blocking call.
     * Publication and acknowledgements continue while the bounded scan advances. */
    for (unsigned checked = 0; q->scan_page < q->tail && checked < 8; ++checked) {
        uint64_t p = q->scan_page;
        yyjson_mut_doc *doc = read_page(q, p);
        if (!doc)
            return false;
        yyjson_mut_val *array = GET(yyjson_mut_doc_get_root(doc), "PingInfos");
        size_t i, n;
        yyjson_mut_val *item;
        bool safe = true;
        uint64_t mask =
            p - q->head < q->windows ? q->window[(size_t)(p - q->head)].mask : UINT64_MAX;
        yyjson_mut_arr_foreach(array, i, n, item)
        {
            if (!(mask & (UINT64_C(1) << i)))
                continue;
            uint64_t id;
            if (!nm_monitor_u64(GET(item, "ID"), &id) ||
                (id <= UINT32_MAX && (uint32_t)((uint32_t)id - sequence) < maximum_results)) {
                safe = false;
                break;
            }
        }
        yyjson_mut_doc_free(doc);
        if (!safe)
            return false;
        ++q->scan_page;
    }
    return q->scan_page == q->tail;
}

nm_ping_backlog_stats nm_ping_backlog_status(nm_ping_backlog *q, const nm_model *model,
                                             uint64_t now)
{
    nm_ping_storage_capacity space = nm_ping_storage_space();
    if (q->sample_time && now > q->sample_time && q->bytes_written > q->sample_bytes)
        q->bytes_per_hour = (q->bytes_written - q->sample_bytes) * 3600 / (now - q->sample_time);
    q->sample_time = now;
    q->sample_bytes = q->bytes_written;
    nm_ping_backlog_stats stats = {.mode = q->mode,
                                   .pending = nm_ping_backlog_pending(q, model),
                                   .free_bytes = space.free_bytes,
                                   .reserve_bytes = space.reserve_bytes,
                                   .paused = q->capacity_paused || q->failed || q->read_failed ||
                                             !space.healthy ||
                                             space.free_bytes <= space.reserve_bytes};
    if (q->bytes_per_hour && space.healthy && space.free_bytes > space.reserve_bytes) {
        uint64_t usable = space.free_bytes - space.reserve_bytes;
        if (q->mode == NM_PING_STORAGE_NVS) {
            uint64_t mean =
                q->pages_written ? q->bytes_written / q->pages_written : NM_PING_PAGE_BYTES;
            uint64_t page_space = (NM_PING_NVS_PAGES - (q->tail - q->durable_head)) * mean;
            if (usable > page_space)
                usable = page_space;
        }
        if (usable <= UINT64_MAX / 3600) {
            stats.estimate_known = true;
            stats.estimated_seconds = usable * 3600 / q->bytes_per_hour;
        }
    }
    return stats;
}
