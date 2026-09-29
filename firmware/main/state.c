#include "endpoint_status.h"
#include "esp_log.h"
#include "esp_random.h"
#include "message_publish.h"
#include "monitor_numbers.h"
#include "monitor_schedule.h"
#include "monitor_schedule_typed.h"
#include "nm_esp.h"
#include "nm_probe_pool.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *TAG = "nm_state";
struct nm_esp_state {
    nm_model core;
    bool (*yield)(void *);
    void *yield_context;
    nm_probe_executor *executor;
    uint64_t generation; /* Owner-task configuration/reset epoch; never serialized. */
};
#define GET yyjson_mut_obj_get
static void timestamp(char out[32])
{
    time_t now = time(NULL);
    struct tm utc;
    if (!gmtime_r(&now, &utc) || !strftime(out, 32, "%Y-%m-%dT%H:%M:%SZ", &utc))
        strcpy(out, "1970-01-01T00:00:00Z");
}
static bool save(const nm_model *model)
{
    yyjson_mut_doc *snapshot = nm_model_encode(model);
    bool ok = snapshot && nm_esp_storage_save("monitoring", yyjson_mut_doc_get_root(snapshot));
    yyjson_mut_doc_free(snapshot);
    return ok;
}
/* Apply a complete candidate in RAM only. Persistence belongs to cycle completion. */
static bool apply(nm_esp_state *s, nm_model *next, bool ok)
{
    if (ok) {
        nm_model_close(&s->core);
        s->core = *next;
        memset(next, 0, sizeof(*next));
        s->core.changed = false;
        s->core.schedule->changed = false;
    }
    nm_model_close(next);
    if (!ok)
        ESP_LOGE(TAG, "monitoring transaction rejected; active state unchanged");
    return ok;
}
static bool recoverable_parents(nm_model *core)
{
    for (size_t i = 0; i < core->pings.count; ++i) {
        int32_t id = ((nm_ping_record *)core->pings.items[i])->MonitorPingInfoID;
        if (!nm_model_info(core, id) && !nm_model_host(core, id)) {
            ESP_LOGE(TAG,
                     "saved ping references missing monitor %ld and has no configuration to "
                     "rebuild it; refusing silent data loss or an undrainable backlog",
                     (long)id);
            return false;
        }
    }
    return true;
}
nm_esp_state *nm_esp_state_new(const nm_esp_config *config)
{
    nm_esp_state *s = nm_bulk_calloc(1, sizeof(*s));
    if (!s)
        return NULL;
    yyjson_mut_doc *snapshot = nm_esp_storage_load("monitoring"), *data = NULL, *hosts = NULL;
    bool ok = snapshot || !nm_esp_storage_has_key("monitoring");
    if (ok && !snapshot) {
        data = nm_esp_storage_load("processor");
        hosts = nm_esp_storage_load("monitors");
        ok = (data || !nm_esp_storage_has_key("processor")) &&
             (hosts || !nm_esp_storage_has_key("monitors"));
    }
    if (ok)
        ok = config && nm_model_open(&s->core, yyjson_mut_doc_get_root(snapshot),
                                     yyjson_mut_doc_get_root(data), yyjson_mut_doc_get_root(hosts),
                                     config->max_monitors, config->max_pending_ping_infos);
    if (ok)
        ok = nm_schedule_configure(s->core.schedule, config->root);
    if (ok)
        ok = recoverable_parents(&s->core);
    yyjson_mut_doc_free(snapshot);
    yyjson_mut_doc_free(data);
    yyjson_mut_doc_free(hosts);
    if (!ok) {
        nm_model_close(&s->core);
        free(s);
        return NULL;
    }
    return s;
}
bool nm_esp_state_save(const nm_esp_state *s)
{
    return s && save(&s->core);
}
void nm_esp_state_free(nm_esp_state *s)
{
    if (s) {
        if (s->executor && s->executor->destroy)
            s->executor->destroy(s->executor->context);
        free(s->executor);
        nm_model_close(&s->core);
        free(s);
    }
}
void nm_esp_state_set_yield(nm_esp_state *s, bool (*yield)(void *), void *context)
{
    if (s) {
        s->yield = yield;
        s->yield_context = context;
    }
}
void nm_esp_state_set_probe_executor(nm_esp_state *s, nm_probe_executor *executor)
{
    if (!s)
        return;
    if (s->executor && s->executor->destroy)
        s->executor->destroy(s->executor->context);
    free(s->executor);
    s->executor = executor;
}
size_t nm_esp_state_monitor_count(const nm_esp_state *s)
{
    return s ? s->core.hosts.count : 0;
}
bool nm_esp_state_init(nm_esp_state *s, const nm_esp_config *config, yyjson_mut_val *request)
{
    nm_model next = {0};
    char when[32];
    timestamp(when);
    if (!s || !nm_model_clone(&next, &s->core))
        return false;
    bool ok = nm_model_init(&next, request, config->app_id, when);
    if (ok && !next.schedule->initialized)
        ok = nm_schedule_configure(next.schedule, config->root);
    ok = apply(s, &next, ok);
    if (ok)
        ++s->generation;
    return ok;
}
bool nm_esp_state_updates(nm_esp_state *s, const nm_esp_config *config, yyjson_mut_val *updates)
{
    nm_model next = {0};
    char when[32];
    timestamp(when);
    if (!s || !nm_model_clone(&next, &s->core))
        return false;
    bool ok = apply(s, &next, nm_model_updates(&next, updates, config->app_id, when));
    if (ok)
        ++s->generation;
    return ok;
}
bool nm_esp_state_ack(nm_esp_state *s, yyjson_mut_val *response)
{
    nm_model next = {0};
    if (!s || !nm_model_clone(&next, &s->core))
        return false;
    bool ok = apply(s, &next, nm_model_ack(&next, response));
    if (ok)
        ESP_LOGI(TAG, "application acknowledgement applied in RAM; pending_pings=%u",
                 (unsigned)s->core.pings.count);
    return ok;
}
bool nm_esp_state_user_event(nm_esp_state *s, yyjson_mut_val *event)
{
    nm_model next = {0};
    if (!s || !nm_model_clone(&next, &s->core))
        return false;
    bool ok = apply(s, &next, nm_model_user_event(&next, event));
    if (ok)
        ++s->generation;
    return ok;
}
static bool add(yyjson_mut_doc *doc, yyjson_mut_val *obj, const char *key, yyjson_mut_val *v)
{
    return v && yyjson_mut_obj_add_val(doc, obj, key, v);
}
static bool clone_field(yyjson_mut_doc *doc, yyjson_mut_val *dest, yyjson_mut_val *source,
                        const char *key)
{
    yyjson_mut_val *v = GET(source, key);
    return !v || add(doc, dest, key, yyjson_mut_val_mut_copy(doc, v));
}
bool nm_esp_state_alert(nm_esp_state *s, const nm_esp_config *config,
                        esp_mqtt_client_handle_t client, const char *operation, yyjson_mut_val *ids)
{
    nm_model next = {0};
    if (!s || !nm_model_clone(&next, &s->core))
        return false;
    size_t index, count;
    yyjson_mut_val *requested;
    yyjson_mut_arr_foreach(ids, index, count, requested)
    {
        int32_t id;
        if (nm_monitor_i32(requested, &id) && !nm_model_info(&next, id))
            ESP_LOGW(TAG,
                     "%s: monitor ID %ld is absent; continuing with other IDs (not a JSON "
                     "conversion error)",
                     operation, (long)id);
    }
    if (!apply(s, &next, nm_model_alert(&next, operation, ids, config->app_id)))
        return false;
    if (strcmp(operation, "processorResetAlerts"))
        return true;
    yyjson_mut_doc *doc = nm_json_new();
    if (!doc)
        return false;
    yyjson_mut_val *obj = yyjson_mut_obj(doc), *arr = yyjson_mut_arr(doc);
    yyjson_mut_doc_set_root(doc, obj);
    bool ok = yyjson_mut_obj_add_strcpy(doc, obj, "AppID", config->app_id) &&
              yyjson_mut_obj_add_strcpy(doc, obj, "AuthKey", config->auth_key) &&
              add(doc, obj, "AlertFlagObjs", arr);
    size_t i, n;
    yyjson_mut_val *id;
    yyjson_mut_arr_foreach(ids, i, n, id)
    {
        yyjson_mut_val *item = yyjson_mut_obj(doc);
        ok = ok && add(doc, item, "ID", yyjson_mut_val_mut_copy(doc, id)) &&
             yyjson_mut_obj_add_strcpy(doc, item, "AppID", config->app_id) &&
             yyjson_mut_arr_append(arr, item);
    }
    ok = ok && nm_esp_publish_event(config, client, "processor/out/reset-alerts", obj,
                                    NM_MESSAGE_JSON, "AlertServiceAlertObj");
    yyjson_mut_doc_free(doc);
    return ok;
}
static yyjson_mut_doc *wire_data(const nm_esp_config *config, const nm_model *model)
{
    yyjson_mut_doc *doc = nm_json_new();
    if (!doc)
        return NULL;
    yyjson_mut_val *obj = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, obj);
    const char *arrays[] = {"MonitorPingInfos",     "PingInfos",
                            "MonitorStatusAlerts",  "RemoveMonitorPingInfoIDs",
                            "SwapMonitorPingInfos", "RemovePingInfos"};
    bool ok = yyjson_mut_obj_add_strcpy(doc, obj, "AppID", config->app_id) &&
              yyjson_mut_obj_add_strcpy(doc, obj, "AuthKey", config->auth_key) &&
              yyjson_mut_obj_add_uint(doc, obj, "PiIDKey", model->sequence);
    for (size_t i = 0; i < sizeof(arrays) / sizeof(arrays[0]); ++i)
        ok = ok && add(doc, obj, arrays[i], yyjson_mut_arr(doc));
    if (!ok) {
        yyjson_mut_doc_free(doc);
        return NULL;
    }
    return doc;
}
/* Every bounded batch includes its parent info, including disabled hosts. All
 * fields are retained, and broker PUBACK never removes an application sample. */
static bool publication_continue(nm_esp_state *s, uint64_t generation)
{
    return (!s->yield || s->yield(s->yield_context)) && generation == s->generation;
}

static yyjson_mut_doc *pending_batch(const nm_esp_config *config, const nm_model *model)
{
    yyjson_mut_doc *doc = wire_data(config, model);
    if (!doc)
        return NULL;
    yyjson_mut_val *obj = yyjson_mut_doc_get_root(doc);
    bool built = true;
    for (size_t a = 0; a < model->removals.count; ++a)
        built =
            built && yyjson_mut_arr_append(
                         GET(obj, "RemoveMonitorPingInfoIDs"),
                         yyjson_mut_sint(doc, ((nm_swap_record *)model->removals.items[a])->ID));
    for (size_t a = 0; a < model->swaps.count; ++a)
        built = built && yyjson_mut_arr_append(GET(obj, "SwapMonitorPingInfos"),
                                               nm_record_encode(doc, model->swaps.items[a]));
    if (!built) {
        yyjson_mut_doc_free(doc);
        return NULL;
    }
    return doc;
}

/* Adds one monitor and up to 64 of its pending samples. cursor is committed
 * only after successful construction; the caller may roll back the arrays and
 * retry the chunk in a fresh batch when the encoded wire limit is reached. */
static bool append_pending_chunk(yyjson_mut_doc *doc, const nm_model *model,
                                 const nm_monitor_record *info, size_t *cursor, size_t *added,
                                 size_t max_pings)
{
    yyjson_mut_val *obj = yyjson_mut_doc_get_root(doc);
    yyjson_mut_val *infos = GET(obj, "MonitorPingInfos"), *pings = GET(obj, "PingInfos");
    if (!yyjson_mut_arr_append(infos, nm_record_encode(doc, &info->base)))
        return false;
    size_t next = *cursor;
    *added = 0;
    for (; next < model->pings.count && *added < max_pings; ++next) {
        const nm_ping_record *ping = (nm_ping_record *)model->pings.items[next];
        if (ping->MonitorPingInfoID != info->MonitorIPID)
            continue;
        if (!yyjson_mut_arr_append(pings, nm_record_encode(doc, &ping->base)))
            return false;
        ++*added;
    }
    *cursor = next;
    return true;
}

static bool send_pending_batch(yyjson_mut_doc *doc, const nm_esp_config *config,
                               esp_mqtt_client_handle_t client)
{
    return nm_esp_publish_event(config, client, "processor/out/data", yyjson_mut_doc_get_root(doc),
                                NM_MESSAGE_BROTLI_TUPLE, "ProcessorDataObj");
}

static bool publish_pending(nm_esp_state *s, const nm_model *model, uint64_t generation,
                            const nm_esp_config *config, esp_mqtt_client_handle_t client)
{
    yyjson_mut_doc *doc = pending_batch(config, model);
    if (!doc)
        return false;
    bool ok = true;
    size_t batch_chunks = 0;
    size_t count = model->infos.count;
    for (size_t h = 0; h < (count ? count : 1); ++h) {
        const nm_monitor_record *info =
            h < count ? (nm_monitor_record *)model->infos.items[h] : NULL;
        size_t cursor = 0;
        size_t max_pings = 64;
        do {
            if (!publication_continue(s, generation)) {
                ok = false;
                goto done;
            }
            if (!info)
                break;
            size_t original_cursor = cursor, added = 0;
            bool built = append_pending_chunk(doc, model, info, &cursor, &added, max_pings);
            if (!built) {
                ok = false;
                goto done;
            }
            yyjson_mut_val *obj = yyjson_mut_doc_get_root(doc);
            size_t wire_size =
                nm_esp_event_wire_size(config, obj, NM_MESSAGE_BROTLI_TUPLE, "ProcessorDataObj");
            if (!wire_size || wire_size > NM_ESP_MAX_PUBLICATION) {
                yyjson_mut_arr_remove_last(GET(obj, "MonitorPingInfos"));
                for (size_t i = 0; i < added; ++i)
                    yyjson_mut_arr_remove_last(GET(obj, "PingInfos"));
                if (!batch_chunks) {
                    if (added <= 1 || max_pings == 1) {
                        ok = false; /* One complete sample/parent is too large. */
                        goto done;
                    }
                    max_pings /= 2;
                    cursor = original_cursor;
                    continue;
                }
                if (!send_pending_batch(doc, config, client)) {
                    ok = false;
                    goto done;
                }
                yyjson_mut_doc_free(doc);
                doc = pending_batch(config, model);
                if (!doc) {
                    ok = false;
                    goto done;
                }
                batch_chunks = 0;
                cursor = original_cursor;
                continue;
            }
            ++batch_chunks;
            max_pings = 64;
        } while (cursor < model->pings.count);
    }
    if (publication_continue(s, generation))
        ok = send_pending_batch(doc, config, client) && ok;
    else
        ok = false;
done:
    yyjson_mut_doc_free(doc);
    return ok;
}
static bool publish_alerts(nm_esp_state *s, const nm_model *model, uint64_t generation,
                           const nm_esp_config *config, esp_mqtt_client_handle_t client)
{
    bool ok = true;
    for (size_t i = 0; i < model->infos.count; ++i) {
        if (!publication_continue(s, generation))
            return false;
        const nm_monitor_record *record = (nm_monitor_record *)model->infos.items[i];
        const nm_status_record *status = record->MonitorStatus;
        if (!status || !nm_record_has(&status->base, NM_S_IsUp) ||
            nm_record_null(&status->base, NM_S_IsUp))
            continue;
        yyjson_mut_doc *doc = wire_data(config, model);
        if (!doc)
            return false;
        yyjson_mut_val *obj = yyjson_mut_doc_get_root(doc),
                       *alert = nm_record_encode(doc, &status->base),
                       *info = nm_record_encode(doc, &record->base);
        bool built = alert && info;
        const char *fields[] = {"AppID",  "Address",      "EndPointType",   "Timeout",
                                "UserID", "AddUserEmail", "IsEmailVerified"};
        for (size_t a = 0; a < sizeof(fields) / sizeof(fields[0]); ++a)
            built = built && clone_field(doc, alert, info, fields[a]);
        yyjson_mut_obj_remove_key(alert, "ID");
        built = built &&
                add(doc, alert, "ID", yyjson_mut_val_mut_copy(doc, GET(info, "MonitorIPID"))) &&
                add(doc, alert, "UserName", yyjson_mut_null(doc)) &&
                yyjson_mut_arr_append(GET(obj, "MonitorStatusAlerts"), alert);
        bool sent =
            built && nm_esp_publish_event(config, client, "processor/out/status-alerts", obj,
                                          NM_MESSAGE_BROTLI_BASE64, "ProcessorDataObj");
        yyjson_mut_doc_free(doc);
        ok = sent && ok;
    }
    return ok;
}
/* Commands may replace the live model between messages. Keep an owned COW
 * snapshot, never a borrowed pointer into s->core across a yield. A reset or
 * configuration update cancels the old publication; acknowledgements remain
 * applied to durable live state and are never overwritten by this snapshot. */
static bool publish_all(nm_esp_state *s, const nm_esp_config *config,
                        esp_mqtt_client_handle_t client)
{
    nm_model snapshot = {0};
    if (!nm_model_clone(&snapshot, &s->core))
        return false;
    uint64_t generation = s->generation;
    bool alerts = publish_alerts(s, &snapshot, generation, config, client);
    bool data = publish_pending(s, &snapshot, generation, config, client);
    bool current = publication_continue(s, generation);
    nm_model_close(&snapshot);
    return alerts && data && current;
}

static double schedule_random(void *context)
{
    (void)context;
    return (double)esp_random() / 4294967296.0;
}
/* Apply one finished probe to a fresh candidate and commit it. Returns true
 * when a reply was consumed, so the caller can decrement its own accounting,
 * whether or not the monitor still existed; *cycle_ok turns false on a hard
 * clone/commit failure. */
static bool drain_probe(nm_esp_state *s, bool *cycle_ok)
{
    nm_probe_reply reply;
    if (!s->executor->poll(s->executor->context, &reply, 100))
        return false;
    if (reply.generation != s->generation) {
        ESP_LOGI(TAG, "discarding obsolete probe id=%ld after configuration/reset",
                 (long)reply.monitor_id);
        nm_esp_result_release(&reply.result);
        return true;
    }
    if (reply.result.disposition == NM_PROBE_LOCAL_FAILURE) {
        ESP_LOGW(TAG, "probe id=%ld inconclusive: %s; pausing until next cycle",
                 (long)reply.monitor_id, reply.result.message);
        *cycle_ok = false;
        nm_esp_result_release(&reply.result);
        return true;
    }
    nm_model next = {0};
    if (!nm_model_clone(&next, &s->core)) {
        *cycle_ok = false;
        nm_esp_result_release(&reply.result);
        return true;
    }
    bool applied = false;
    if (nm_model_host(&next, reply.monitor_id)) {
        char when[32];
        timestamp(when);
        uint32_t date = (uint32_t)((uint64_t)time(NULL) - UINT64_C(1640995200));
        uint16_t rtt = nm_endpoint_rtt(reply.result.ok, reply.result.elapsed_ms);
        ESP_LOGI(TAG, "probe id=%ld ok=%d elapsed_ms=%u", (long)reply.monitor_id, reply.result.ok,
                 reply.result.elapsed_ms);
        applied = nm_model_probe(&next, reply.monitor_id, reply.result.ok, rtt,
                                 *reply.result.status ? reply.result.status : reply.result.message,
                                 reply.result.detail_message ? reply.result.detail_message : reply.result.message,
                                 when, date);
    }
    if (!applied) {
        nm_model_close(&next);
        nm_esp_result_release(&reply.result);
        return true;
    }
    if (!apply(s, &next, true))
        *cycle_ok = false;
    nm_esp_result_release(&reply.result);
    return true;
}
/* Sequential probe path: probes on the processor task, RAM update per monitor. Used
 * when no executor is injected (host parity tests and the safe fallback). */
static bool run_sequential(nm_esp_state *s, const nm_esp_config *config)
{
    bool valid = true;
    size_t count = s->core.infos.count;
    if (count > SIZE_MAX / sizeof(int32_t))
        return false;
    int32_t *plan = count ? malloc(count * sizeof(*plan)) : NULL;
    if (count && !plan)
        return false;
    for (size_t i = 0; i < count; ++i)
        plan[i] = ((nm_monitor_record *)s->core.infos.items[i])->MonitorIPID;
    nm_model next = {0};
    for (size_t i = 0; i < count; ++i) {
        if (s->yield && !s->yield(s->yield_context))
            break;
        size_t pending = s->core.pings.count;
        if (pending >= config->max_pending_ping_infos) {
            ESP_LOGW(TAG,
                     "pending pings=%u limit=%u; probes paused until application acknowledgement",
                     (unsigned)pending, config->max_pending_ping_infos);
            break;
        }
        int32_t id = plan[i];
        if (!nm_model_clone(&next, &s->core)) {
            valid = false;
            break;
        }
        const nm_monitor_record *host = nm_model_host(&next, id), *info = nm_model_info(&next, id);
        if (!info) {
            nm_model_close(&next);
            continue;
        }
        const char *type = info->EndPointType;
        bool include = false;
        valid = nm_schedule_include(next.schedule, info, (int64_t)time(NULL), schedule_random, NULL,
                                    nm_schedule_daily_hash(id), &include);
        if (valid && include && host && nm_esp_endpoint_supported(type)) {
            char when[32];
            timestamp(when);
            uint32_t date = (uint32_t)((uint64_t)time(NULL) - UINT64_C(1640995200));
            nm_esp_result result = nm_esp_endpoint_run(info);
            if (result.disposition == NM_PROBE_LOCAL_FAILURE) {
                ESP_LOGW(TAG, "probe id=%ld inconclusive: %s; pausing until next cycle", (long)id,
                         result.message);
                nm_model_close(&next);
                nm_esp_result_release(&result);
                valid = false;
                break;
            }
            uint16_t rtt = nm_endpoint_rtt(result.ok, result.elapsed_ms);
            ESP_LOGI(TAG, "probe id=%ld type=%s ok=%d elapsed_ms=%u", (long)id, type, result.ok,
                     result.elapsed_ms);
            valid = nm_model_probe(&next, id, result.ok, rtt,
                                   *result.status ? result.status : result.message,
                                   result.detail_message ? result.detail_message : result.message,
                                   when, date);
            nm_esp_result_release(&result);
        }
        /* Never process commands against an uncommitted probe/schedule candidate. */
        valid = apply(s, &next, valid);
        if (!valid)
            break;
    }
    free(plan);
    return valid;
}
/* Concurrent probe path: scheduling and every model mutation stay on this task;
 * only endpoint I/O runs in the injected executor. */
static bool run_concurrent(nm_esp_state *s, const nm_esp_config *config)
{
    bool valid = true;
    size_t count = s->core.infos.count;
    if (count > SIZE_MAX / sizeof(int32_t))
        return false;
    int32_t *plan = count ? malloc(count * sizeof(*plan)) : NULL;
    if (count && !plan)
        return false;
    for (size_t i = 0; i < count; ++i)
        plan[i] = ((nm_monitor_record *)s->core.infos.items[i])->MonitorIPID;

    int capacity = s->executor->capacity > 0 ? s->executor->capacity : 1;
    int outstanding = 0;
    uint64_t generation = s->generation;
    nm_model next = {0};
    for (size_t i = 0; i < count; ++i) {
        if (s->yield && !s->yield(s->yield_context))
            break;
        if (generation != s->generation)
            break;
        /* Service commands during waits, before borrowing model pointers.
         * Each endpoint owns a bounded deadline; never abandon pool replies
         * at an unrelated wall-clock cycle deadline. */
        bool dispatch = true;
        while (outstanding >= capacity) {
            if (drain_probe(s, &valid))
                --outstanding;
            if (s->yield && !s->yield(s->yield_context))
                dispatch = false;
            if (!valid || !dispatch || generation != s->generation)
                break;
        }
        if (!valid || !dispatch || generation != s->generation)
            break;
        if (s->core.pings.count + (size_t)outstanding >= config->max_pending_ping_infos) {
            ESP_LOGW(TAG,
                     "pending pings=%u limit=%u; probes paused until application acknowledgement",
                     (unsigned)(s->core.pings.count + (size_t)outstanding),
                     config->max_pending_ping_infos);
            break;
        }
        int32_t id = plan[i];
        if (!nm_model_clone(&next, &s->core)) {
            valid = false;
            break;
        }
        const nm_monitor_record *host = nm_model_host(&next, id), *info = nm_model_info(&next, id);
        if (!info) {
            nm_model_close(&next);
            continue;
        }
        bool include = false;
        valid = nm_schedule_include(next.schedule, info, (int64_t)time(NULL), schedule_random, NULL,
                                    nm_schedule_daily_hash(id), &include);
        bool probe = valid && include && host && nm_esp_endpoint_supported(info->EndPointType);
        /* Apply the schedule advance before draining: otherwise this candidate
         * could overwrite a drained result in the active RAM model. */
        valid = apply(s, &next, valid);
        if (!valid)
            break;
        if (!probe)
            continue;
        if (!s->executor->submit(s->executor->context, id, generation, info)) {
            valid = false;
            break;
        }
        ++outstanding;
    }
    /* Reap in-flight probes so no reply leaks into a later cycle. */
    while (outstanding > 0) {
        if (drain_probe(s, &valid))
            --outstanding;
        if (s->yield)
            s->yield(s->yield_context);
    }
    free(plan);
    return valid;
}
bool nm_esp_state_cycle(nm_esp_state *s, const nm_esp_config *config,
                        esp_mqtt_client_handle_t client)
{
    if (!s || time(NULL) < 1640995200)
        return false;
    nm_model next = {0};
    char when[32];
    timestamp(when);
    bool valid = nm_model_clone(&next, &s->core) && next.hosts.count <= config->max_monitors &&
                 nm_model_reconcile(&next, config->app_id, when);
    valid = valid && nm_schedule_prepare(next.schedule, &next.infos, (int64_t)time(NULL));
    bool prepared = apply(s, &next, valid);
    bool probes = prepared && (s->executor ? run_concurrent(s, config) : run_sequential(s, config));
    /* Delivery has priority over persistence. Never short-circuit either attempt.
     * Publication-time acknowledgements update RAM before the snapshot. */
    bool sent = publish_all(s, config, client);
    /* Exactly one snapshot attempt per cycle, after all accepted probe jobs drain.
     * Save even empty/paused/failed cycles. No per-probe or acknowledgement writes.
     * A failed save preserves RAM results and the previous durable snapshot. */
    bool saved = nm_esp_state_save(s);
    if (!saved)
        ESP_LOGE(TAG, "cycle snapshot save failed; monitoring state retained in RAM");
    return probes && saved && sent;
}
