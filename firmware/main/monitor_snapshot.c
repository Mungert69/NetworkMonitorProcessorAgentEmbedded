#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "monitor_model.h"
#include "monitor_numbers.h"
#include "monitor_schedule_typed.h"
#include "nm_json.h"
#include <limits.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define GET yyjson_mut_obj_get
#define TRY(x)                                                                                     \
    do {                                                                                           \
        if (!(x))                                                                                  \
            return false;                                                                          \
    } while (0)
#include "monitor_record_internal.h"
static nm_records *collections(nm_model *m, size_t i)
{
    switch (i) {
    case 0:
        return &m->hosts;
    case 1:
        return &m->infos;
    case 2:
        return &m->pings;
    case 3:
        return &m->removepings;
    case 4:
        return &m->removals;
    default:
        return &m->swaps;
    }
}
static const char *collection_names[] = {
    "MonitorIPs",      "MonitorPingInfos",         "PingInfos",
    "RemovePingInfos", "RemoveMonitorPingInfoIDs", "SwapMonitorPingInfos"};
static const nm_record_kind collection_kinds[] = {NM_MONITOR, NM_MONITOR, NM_PING,
                                                  NM_PING,    NM_SWAP,    NM_SWAP};
void nm_model_close(nm_model *m)
{
    if (!m)
        return;
    for (size_t i = 0; i < 6; ++i)
        nm_records_free(collections(m, i));
    nm_record_release((nm_record *)m->params);
    nm_record_release((nm_record *)m->flow);
    nm_schedule_close(m->schedule);
    free(m->schedule);
    nm_extension_release(m->root_extra);
    nm_extension_release(m->data_extra);
    memset(m, 0, sizeof(*m));
}
bool nm_model_clone(nm_model *out, const nm_model *m)
{
    memset(out, 0, sizeof(*out));
    out->sequence = m->sequence;
    out->params = (nm_params_record *)nm_record_retain((nm_record *)m->params);
    out->flow = (nm_flow_record *)nm_record_retain((nm_record *)m->flow);
    out->root_extra = nm_extension_retain(m->root_extra);
    out->data_extra = nm_extension_retain(m->data_extra);
    if (!out->params || !out->flow || (m->root_extra && !out->root_extra) ||
        (m->data_extra && !out->data_extra))
        goto fail;
    out->schedule = nm_bulk_calloc(1, sizeof(*out->schedule));
    if (!out->schedule || !nm_schedule_clone(out->schedule, m->schedule))
        goto fail;
    for (size_t i = 0; i < 6; ++i)
        if (!nm_records_clone(collections(out, i), collections((nm_model *)m, i)))
            goto fail;
    return true;
fail:
    nm_model_close(out);
    return false;
}
bool nm_model_open(nm_model *m, yyjson_mut_val *snapshot, yyjson_mut_val *legacy,
                   yyjson_mut_val *hosts, size_t max_monitors, size_t max_pings)
{
    memset(m, 0, sizeof(*m));
    if (!max_monitors || !max_pings)
        return false;
    m->schedule = nm_bulk_calloc(1, sizeof(*m->schedule));
    if (!m->schedule || !nm_schedule_open(m->schedule, GET(snapshot, "Schedule"), max_monitors))
        goto fail;
    for (size_t i = 0; i < 6; ++i)
        collections(m, i)->limit = (i == 2 || i == 3) ? max_pings : max_monitors;
    yyjson_mut_val *data = snapshot ? GET(snapshot, "ProcessorData") : legacy;
    if ((snapshot && !yyjson_mut_is_obj(snapshot)) || (data && !yyjson_mut_is_obj(data)))
        goto fail;
    yyjson_mut_val *params = snapshot ? GET(snapshot, "PingParams") : NULL,
                   *flow = snapshot ? GET(snapshot, "AgentUserFlow") : NULL;
    m->params = (nm_params_record *)(params ? nm_record_decode(NM_PARAMS, params)
                                            : nm_record_new(NM_PARAMS));
    m->flow = (nm_flow_record *)(flow ? nm_record_decode(NM_FLOW, flow) : nm_record_new(NM_FLOW));
    if (!m->params || !m->flow)
        goto fail;
    m->sequence = 1;
    if (data && GET(data, "PiIDKey") && !nm_monitor_u32(GET(data, "PiIDKey"), &m->sequence))
        goto fail;
    for (size_t c = 0; c < 6; ++c) {
        yyjson_mut_val *a = c          ? GET(data, collection_names[c])
                            : snapshot ? GET(snapshot, "MonitorIPs")
                                       : hosts;
        if (!a) {
            if (snapshot)
                goto fail;
            continue;
        }
        if (!yyjson_mut_is_arr(a) || yyjson_mut_arr_size(a) > collections(m, c)->limit)
            goto fail;
        size_t i, n;
        yyjson_mut_val *v;
        yyjson_mut_arr_foreach(a, i, n, v)
        {
            nm_record *r;
            if (c == 4) {
                int32_t id;
                if (!nm_monitor_i32(v, &id))
                    goto fail;
                nm_swap_record *removed = (nm_swap_record *)nm_record_new(NM_SWAP);
                if (!removed)
                    goto fail;
                removed->ID = id;
                nm_record_mark(&removed->base, NM_W_ID, false);
                r = &removed->base;
            } else
                r = nm_record_decode(collection_kinds[c], v);
            if (!r)
                goto fail;
            bool required = true;
            if (c < 2)
                required = nm_record_has(r, c ? NM_M_MonitorIPID : NM_M_ID);
            if (c == 2)
                required = nm_record_has(r, NM_P_ID) && nm_record_has(r, NM_P_MonitorPingInfoID);
            if (c == 3)
                required = nm_record_has(r, NM_P_ID);
            if (c == 5)
                required = nm_record_has(r, NM_W_ID);
            if (!required || !nm_records_append(collections(m, c), r)) {
                nm_record_release(r);
                goto fail;
            }
        }
    }
    yyjson_mut_doc *rest = snapshot ? nm_json_clone(snapshot) : nm_json_new();
    if (!rest)
        goto fail;
    if (!snapshot)
        yyjson_mut_doc_set_root(rest, yyjson_mut_obj(rest));
    yyjson_mut_val *root = yyjson_mut_doc_get_root(rest);
    yyjson_mut_obj_remove_key(root, "MonitorIPs");
    yyjson_mut_obj_remove_key(root, "ProcessorData");
    yyjson_mut_obj_remove_key(root, "PingParams");
    yyjson_mut_obj_remove_key(root, "AgentUserFlow");
    yyjson_mut_obj_remove_key(root, "Schedule");
    m->root_extra = nm_extension_create(root);
    yyjson_mut_doc_free(rest);
    if (!m->root_extra)
        goto fail;
    rest = data ? nm_json_clone(data) : nm_json_new();
    if (!rest)
        goto fail;
    if (!data)
        yyjson_mut_doc_set_root(rest, yyjson_mut_obj(rest));
    root = yyjson_mut_doc_get_root(rest);
    for (size_t i = 1; i < 6; ++i)
        yyjson_mut_obj_remove_key(root, collection_names[i]);
    yyjson_mut_obj_remove_key(root, "PiIDKey");
    const char *remaining[] = {"MonitorStatusAlerts", "PredictStatusAlerts", "StatusList",
                               "MonitorIPs"};
    for (size_t i = 0; i < 4; ++i)
        if (!GET(root, remaining[i]) &&
            !yyjson_mut_obj_add_val(rest, root, remaining[i], yyjson_mut_arr(rest))) {
            yyjson_mut_doc_free(rest);
            goto fail;
        }
    m->data_extra = nm_extension_create(root);
    yyjson_mut_doc_free(rest);
    if (!m->data_extra)
        goto fail;
    return true;
fail:
    nm_model_close(m);
    return false;
}
yyjson_mut_doc *nm_model_encode(const nm_model *m)
{
    yyjson_mut_doc *doc = nm_json_new();
    if (!doc)
        return NULL;
    yyjson_mut_val *root = nm_extension_decode(doc, m->root_extra),
                   *data = nm_extension_decode(doc, m->data_extra);
    yyjson_mut_doc_set_root(doc, root);
    if (!root || !data || !yyjson_mut_obj_add_val(doc, root, "ProcessorData", data) ||
        !yyjson_mut_obj_add_val(doc, root, "Schedule", nm_schedule_encode(doc, m->schedule)) ||
        !yyjson_mut_obj_add_val(doc, root, "PingParams",
                                nm_record_encode(doc, (nm_record *)m->params)) ||
        !yyjson_mut_obj_add_val(doc, root, "AgentUserFlow",
                                nm_record_encode(doc, (nm_record *)m->flow)) ||
        !yyjson_mut_obj_add_uint(doc, data, "PiIDKey", m->sequence))
        goto fail;
    for (size_t i = 0; i < 6; ++i) {
        const nm_records *a = collections((nm_model *)m, i);
        yyjson_mut_val *arr = yyjson_mut_arr(doc);
        if (!arr || !yyjson_mut_obj_add_val(doc, i ? data : root, collection_names[i], arr))
            goto fail;
        for (size_t j = 0; j < a->count; ++j) {
            yyjson_mut_val *value = i == 4
                                        ? yyjson_mut_sint(doc, ((nm_swap_record *)a->items[j])->ID)
                                        : nm_record_encode(doc, a->items[j]);
            if (!value || !yyjson_mut_arr_append(arr, value))
                goto fail;
        }
    }
    return doc;
fail:
    yyjson_mut_doc_free(doc);
    return NULL;
}
