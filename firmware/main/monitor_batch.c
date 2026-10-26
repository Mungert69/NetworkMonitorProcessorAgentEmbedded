#include "monitor_batch.h"
#include "message_publish.h"
#include "status_led.h"
#define GET yyjson_mut_obj_get
static bool add(yyjson_mut_doc *doc, yyjson_mut_val *obj, const char *key, yyjson_mut_val *value)
{
    return value && yyjson_mut_obj_add_val(doc, obj, key, value);
}
yyjson_mut_doc *nm_monitor_batch_payload(const nm_esp_config *config, const nm_model *model)
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
static yyjson_mut_doc *pending_batch(const nm_esp_config *config, const nm_model *model)
{
    yyjson_mut_doc *doc = nm_monitor_batch_payload(config, model);
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
    bool accepted =
        nm_esp_publish_event(config, client, "processor/out/data", yyjson_mut_doc_get_root(doc),
                             NM_MESSAGE_BROTLI_TUPLE, "ProcessorDataObj");
    if (accepted)
        nm_status_led_sent();
    return accepted;
}

bool nm_monitor_batch_send(const nm_esp_config *config, esp_mqtt_client_handle_t client,
                           const nm_model *model, bool (*proceed)(void *), void *context)
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
            if (proceed && !proceed(context)) {
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
    if ((!proceed || proceed(context)))
        ok = send_pending_batch(doc, config, client) && ok;
    else
        ok = false;
done:
    yyjson_mut_doc_free(doc);
    return ok;
}
