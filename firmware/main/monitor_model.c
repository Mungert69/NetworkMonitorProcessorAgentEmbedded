#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "monitor_model.h"
#include "endpoint_measurement.h"
#include "monitor_numbers.h"
#include "monitor_record_internal.h"
#include "monitor_schedule_typed.h"
#include "nm_json.h"
#include <limits.h>
#include <float.h>
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
static size_t find_monitor(const nm_records *a, int32_t id, bool host)
{
    for (size_t i = 0; i < a->count; ++i) {
        const nm_monitor_record *r = (const nm_monitor_record *)a->items[i];
        if ((host ? r->ID : r->MonitorIPID) == id)
            return i;
    }
    return SIZE_MAX;
}
nm_monitor_record *nm_model_info(const nm_model *m, int32_t id)
{
    size_t i = find_monitor(&m->infos, id, false);
    return i == SIZE_MAX ? NULL : (nm_monitor_record *)m->infos.items[i];
}
nm_monitor_record *nm_model_host(const nm_model *m, int32_t id)
{
    size_t i = find_monitor(&m->hosts, id, true);
    return i == SIZE_MAX ? NULL : (nm_monitor_record *)m->hosts.items[i];
}
static nm_monitor_record *edit_info(nm_model *m, int32_t id)
{
    return (nm_monitor_record *)nm_records_edit(&m->infos, find_monitor(&m->infos, id, false));
}
static nm_status_record *edit_status(nm_monitor_record *info)
{
    if (!info || !info->MonitorStatus)
        return NULL;
    nm_status_record *s = info->MonitorStatus;
    if (s->base.references > 1) {
        s = (nm_status_record *)nm_record_copy(&s->base);
        if (!s)
            return NULL;
        nm_record_release(&info->MonitorStatus->base);
        info->MonitorStatus = s;
    }
    return s;
}
#define MSET(r, f, v)                                                                              \
    do {                                                                                           \
        (r)->f = (v);                                                                              \
        nm_record_mark(&(r)->base, NM_M_##f, false);                                               \
    } while (0)
#define SSET(r, f, v)                                                                              \
    do {                                                                                           \
        (r)->f = (v);                                                                              \
        nm_record_mark(&(r)->base, NM_S_##f, false);                                               \
    } while (0)
#define PSET(r, f, v)                                                                              \
    do {                                                                                           \
        (r)->f = (v);                                                                              \
        nm_record_mark(&(r)->base, NM_P_##f, false);                                               \
    } while (0)
#define MSTR(r, f, v) nm_record_string(&(r)->base, NM_M_##f, (v))
#define SSTR(r, f, v) nm_record_string(&(r)->base, NM_S_##f, (v))
#define PSTR(r, f, v) nm_record_string(&(r)->base, NM_P_##f, (v))
static bool has_removal(const nm_records *a, int32_t id)
{
    for (size_t i = 0; i < a->count; ++i)
        if (((nm_swap_record *)a->items[i])->ID == id)
            return true;
    return false;
}
static bool has_pending(const nm_model *m, int32_t id)
{
    for (size_t i = 0; i < m->pings.count; ++i)
        if (((nm_ping_record *)m->pings.items[i])->MonitorPingInfoID == id)
            return true;
    return false;
}
static void prune(nm_model *m)
{
    for (size_t i = m->infos.count; i > 0; --i) {
        int32_t id = ((nm_monitor_record *)m->infos.items[i - 1])->MonitorIPID;
        if (!nm_model_host(m, id) && !has_pending(m, id) && !has_removal(&m->removals, id) &&
            !has_removal(&m->swaps, id)) {
            nm_records_remove(&m->infos, i - 1);
            m->changed = true;
        }
    }
}
static int32_t timeout(const nm_model *m)
{
    return nm_record_has(&m->params->base, NM_PARAM_Timeout) ? m->params->Timeout : 59000;
}
static bool fill(nm_model *m, nm_monitor_record *info, const nm_monitor_record *host,
                 const char *app, const char *when)
{
    bool fresh = !nm_record_has(&info->base, NM_M_MonitorIPID);
    MSET(info, ID, host->ID);
    bool changed_limits =
        info->LowThreshold != host->LowThreshold || info->HighThreshold != host->HighThreshold ||
        nm_record_null(&info->base, NM_M_LowThreshold) !=
            nm_record_null(&host->base, NM_M_LowThreshold) ||
        nm_record_null(&info->base, NM_M_HighThreshold) !=
            nm_record_null(&host->base, NM_M_HighThreshold) ||
        (info->EndPointType && host->EndPointType &&
         strcmp(info->EndPointType, host->EndPointType)) ||
        strcmp(info->Args ? info->Args : "", host->Args ? host->Args : "") ||
        strcmp(info->Username ? info->Username : "", host->Username ? host->Username : "");
    if (fresh || changed_limits) {
        nm_extension_release(info->MeasurementBreach);
        info->MeasurementBreach = NULL;
        nm_record_mark(&info->base, NM_M_MeasurementBreach, true);
    }
    info->LowThreshold = host->LowThreshold;
    info->HighThreshold = host->HighThreshold;
    nm_record_mark(&info->base, NM_M_LowThreshold,
                   !nm_record_has(&host->base, NM_M_LowThreshold) ||
                       nm_record_null(&host->base, NM_M_LowThreshold));
    nm_record_mark(&info->base, NM_M_HighThreshold,
                   !nm_record_has(&host->base, NM_M_HighThreshold) ||
                       nm_record_null(&host->base, NM_M_HighThreshold));
    MSET(info, MonitorIPID, host->ID);
    MSET(info, MonitorPingInfoID, host->ID);
    TRY(MSTR(info, AppID, app));
#define CPSTR(f) TRY(MSTR(info, f, host->f))
    CPSTR(Address);
    CPSTR(EndPointType);
    CPSTR(UserID);
    CPSTR(Username);
    CPSTR(Password);
    CPSTR(Args);
    CPSTR(AddUserEmail);
#undef CPSTR
    MSET(info, Port, host->Port);
    MSET(info, Enabled, host->Enabled);
    MSET(info, IsEmailVerified, host->IsEmailVerified);
    MSET(info, SkipCycles, host->SkipCycles);
    if (!nm_record_has(&host->base, NM_M_SkipCycles) ||
        nm_record_null(&host->base, NM_M_SkipCycles))
        nm_record_mark(&info->base, NM_M_SkipCycles, true);
    MSET(info, Timeout,
         nm_endpoint_configured_timeout(host->EndPointType, host->Timeout, timeout(m)));
    TRY(MSTR(info, Host, info->Address));
    if (!fresh)
        return true;
    MSET(info, DataSetID, 0);
    MSET(info, PacketsSent, 0);
    MSET(info, PacketsRecieved, 0);
    MSET(info, PacketsLost, 0);
    MSET(info, PacketsLostPercentage, 0);
    MSET(info, RoundTripTimeAverage, 0);
    MSET(info, RoundTripTimeMinimum, 9999);
    MSET(info, RoundTripTimeMaximum, 0);
    MSET(info, RoundTripTimeTotal, 0);
    MSET(info, IsArchived, false);
    MSET(info, IsDirtyDownCount, false);
    TRY(MSTR(info, DateStarted, when) && MSTR(info, DateEnded, when) && MSTR(info, Status, "") &&
        MSTR(info, SiteHash, NULL));
    /* Opaque, unmodified fields are retained without a resident JSON tree. */
    static const char defaults[] =
        "{\"PredictStatus\":null,\"MessageForUser\":null,\"AgentLocation\":null,\"ModelConfig\":"
        "null,\"EffectiveModelParameters\":null,\"PingInfos\":[]}";
    nm_extension *e = nm_extension_from_json(defaults, sizeof(defaults) - 1);
    TRY(e);
    nm_extension_release(info->base.extension);
    info->base.extension = e;
    nm_status_record *s = (nm_status_record *)nm_record_new(NM_STATUS);
    TRY(s);
    info->MonitorStatus = s;
    nm_record_mark(&info->base, NM_M_MonitorStatus, false);
    SSET(s, ID, 0);
    SSET(s, MonitorPingInfoID, 0);
    SSET(s, DownCount, 0);
    SSET(s, AlertFlag, false);
    SSET(s, AlertSent, false);
    nm_record_mark(&s->base, NM_S_IsUp, true);
    TRY(SSTR(s, EventTime, NULL) && SSTR(s, Message, ""));
    return true;
}
bool nm_model_reconcile(nm_model *m, const char *app, const char *when)
{
    for (size_t i = 0; i < m->hosts.count; ++i) {
        nm_monitor_record *h = (nm_monitor_record *)m->hosts.items[i];
        if (!nm_model_info(m, h->ID)) {
            nm_monitor_record *info = (nm_monitor_record *)nm_record_new(NM_MONITOR);
            TRY(info);
            if (!fill(m, info, h, app, when) || !nm_records_append(&m->infos, &info->base)) {
                nm_record_release(&info->base);
                return false;
            }
            m->changed = true;
        }
    }
    for (size_t i = 0; i < m->infos.count; ++i) {
        nm_monitor_record *info = (nm_monitor_record *)m->infos.items[i];
        if (!nm_model_host(m, info->MonitorIPID) && info->Enabled) {
            info = (nm_monitor_record *)nm_records_edit(&m->infos, i);
            TRY(info);
            MSET(info, Enabled, false);
            m->changed = true;
        }
    }
    return true;
}
bool nm_model_updates(nm_model *m, yyjson_mut_val *updates, const char *app, const char *when)
{
    TRY(yyjson_mut_is_arr(updates));
    size_t i, n;
    yyjson_mut_val *v;
    yyjson_mut_arr_foreach(updates, i, n, v)
    {
        nm_monitor_record *h = (nm_monitor_record *)nm_record_decode(NM_MONITOR, v);
        if (!h)
            return false;
        if (!nm_record_has(&h->base, NM_M_ID) || h->ID < 0) {
            nm_record_release(&h->base);
            return false;
        }
        int32_t id = h->ID;
        bool deleted = h->Delete, swapping = h->IsSwapping;
        if (h->DeleteAll) {
            while (m->hosts.count)
                nm_records_remove(&m->hosts, m->hosts.count - 1);
            nm_record_release(&h->base);
            m->changed = true;
            continue;
        }
        size_t old = find_monitor(&m->hosts, id, true);
        if (old != SIZE_MAX)
            nm_records_remove(&m->hosts, old);
        nm_monitor_record *info = nm_model_info(m, id);
        if (deleted) {
            if (info && !swapping && !has_removal(&m->removals, id)) {
                nm_swap_record *r = (nm_swap_record *)nm_record_new(NM_SWAP);
                if (!r) {
                    nm_record_release(&h->base);
                    return false;
                }
                r->ID = id;
                nm_record_mark(&r->base, NM_W_ID, false);
                if (!nm_records_append(&m->removals, &r->base)) {
                    nm_record_release(&r->base);
                    nm_record_release(&h->base);
                    return false;
                }
            }
            nm_record_release(&h->base);
            if (info) {
                info = edit_info(m, id);
                TRY(info);
                MSET(info, Enabled, false);
            }
            m->changed = true;
            continue;
        }
        if (!nm_records_append(&m->hosts, &h->base)) {
            nm_record_release(&h->base);
            return false;
        }
        yyjson_mut_val *supplied = GET(v, "MonitorPingInfo");
        if (!info && swapping && yyjson_mut_is_obj(supplied)) {
            info = (nm_monitor_record *)nm_record_decode(NM_MONITOR, supplied);
            TRY(info);
            if (!nm_record_has(&info->base, NM_M_MonitorIPID) || info->MonitorIPID != id ||
                !MSTR(info, AppID, app) || !nm_records_append(&m->infos, &info->base)) {
                nm_record_release(&info->base);
                return false;
            }
            nm_swap_record *r = (nm_swap_record *)nm_record_new(NM_SWAP);
            TRY(r);
            r->ID = id;
            nm_record_mark(&r->base, NM_W_ID, false);
            if (!nm_record_string(&r->base, NM_W_AppID, app) ||
                !nm_records_append(&m->swaps, &r->base)) {
                nm_record_release(&r->base);
                return false;
            }
        } else {
            if (info)
                info = edit_info(m, id);
            else {
                info = (nm_monitor_record *)nm_record_new(NM_MONITOR);
                TRY(info);
                if (!nm_records_append(&m->infos, &info->base)) {
                    nm_record_release(&info->base);
                    return false;
                }
            }
            TRY(info && fill(m, info, h, app, when));
        }
        m->changed = true;
    }
    prune(m);
    return m->hosts.count <= m->hosts.limit && m->infos.count <= m->infos.limit &&
           m->removals.count <= m->removals.limit && m->swaps.count <= m->swaps.limit;
}
bool nm_model_init(nm_model *m, yyjson_mut_val *request, const char *app, const char *when)
{
    TRY(yyjson_mut_is_obj(request));
    if (yyjson_mut_is_true(GET(request, "TotalReset"))) {
        nm_model fresh;
        TRY(nm_model_open(&fresh, NULL, NULL, NULL, m->hosts.limit, m->pings.limit));
        nm_model_close(m);
        *m = fresh;
        m->changed = true;
    }
    if (yyjson_mut_is_true(GET(request, "Reset"))) {
        for (size_t i = 0; i < m->infos.count; ++i) {
            nm_monitor_record *info = (nm_monitor_record *)nm_records_edit(&m->infos, i);
            TRY(info);
            MSET(info, PacketsSent, 0);
            MSET(info, PacketsRecieved, 0);
            MSET(info, PacketsLost, 0);
            MSET(info, PacketsLostPercentage, 0);
            MSET(info, RoundTripTimeAverage, 0);
            MSET(info, RoundTripTimeMaximum, 0);
            MSET(info, RoundTripTimeTotal, 0);
            MSET(info, RoundTripTimeMinimum, timeout(m));
            TRY(MSTR(info, DateStarted, when));
        }
        while (m->pings.count)
            nm_records_remove(&m->pings, m->pings.count - 1);
        m->sequence = 1;
        m->changed = true;
    }
    yyjson_mut_val *params = GET(request, "PingParams");
    if (params && !yyjson_mut_is_null(params)) {
        nm_params_record *p = (nm_params_record *)nm_record_decode(NM_PARAMS, params);
        TRY(p);
        nm_record_release(&m->params->base);
        m->params = p;
        m->changed = true;
    }
    yyjson_mut_val *hosts = GET(request, "MonitorIPs");
    if (hosts && !yyjson_mut_is_null(hosts)) {
        TRY(yyjson_mut_is_arr(hosts) && yyjson_mut_arr_size(hosts) <= m->hosts.limit);
        while (m->hosts.count)
            nm_records_remove(&m->hosts, m->hosts.count - 1);
        m->changed = true;
        TRY(nm_model_updates(m, hosts, app, when));
    }
    return true;
}
bool nm_model_ack(nm_model *m, yyjson_mut_val *response)
{
    TRY(yyjson_mut_is_obj(response));
    const char *names[] = {"RemovePingInfos", "RemoveMonitorPingInfoIDs", "SwapMonitorPingInfos"};
    for (size_t a = 0; a < 3; ++a) {
        yyjson_mut_val *acks = GET(response, names[a]);
        if (!acks || yyjson_mut_is_null(acks))
            continue;
        TRY(yyjson_mut_is_arr(acks));
        size_t i, n;
        yyjson_mut_val *v;
        yyjson_mut_arr_foreach(acks, i, n, v)
        {
            uint64_t wide = 0;
            int32_t id = 0;
            if (a == 0)
                TRY(nm_monitor_u64(GET(v, "ID"), &wide));
            else
                TRY(nm_monitor_i32(a == 1 ? v : GET(v, "ID"), &id));
            nm_records *pending = a == 0 ? &m->pings : a == 1 ? &m->removals : &m->swaps;
            for (size_t j = pending->count; j > 0; --j) {
                bool same = a == 0 ? ((nm_ping_record *)pending->items[j - 1])->ID == wide
                                   : ((nm_swap_record *)pending->items[j - 1])->ID == id;
                if (same) {
                    nm_records_remove(pending, j - 1);
                    m->changed = true;
                }
            }
            if (a == 1 && !nm_model_host(m, id)) {
                for (size_t j = m->pings.count; j > 0; --j)
                    if (((nm_ping_record *)m->pings.items[j - 1])->MonitorPingInfoID == id) {
                        nm_records_remove(&m->pings, j - 1);
                        m->changed = true;
                    }
                size_t j = find_monitor(&m->infos, id, false);
                if (j != SIZE_MAX) {
                    nm_records_remove(&m->infos, j);
                    m->changed = true;
                }
            }
        }
    }
    prune(m);
    return true;
}
bool nm_model_alert(nm_model *m, const char *operation, yyjson_mut_val *ids, const char *app)
{
    bool reset = !strcmp(operation, "processorResetAlerts"),
         flag = !strcmp(operation, "processorAlertFlag"),
         sent = !strcmp(operation, "processorAlertSent");
    TRY((reset || flag || sent) && yyjson_mut_is_arr(ids));
    size_t i, n;
    yyjson_mut_val *v;
    yyjson_mut_arr_foreach(ids, i, n, v)
    {
        int32_t id;
        TRY(nm_monitor_i32(v, &id));
        nm_monitor_record *info = nm_model_info(m, id);
        if (!info || (reset && (!info->AppID || strcmp(info->AppID, app))))
            continue;
        info = edit_info(m, id);
        TRY(info);
        nm_status_record *s = edit_status(info);
        TRY(s);
        if (reset) {
            SSET(s, AlertFlag, false);
            SSET(s, AlertSent, false);
            SSET(s, DownCount, 0);
            nm_extension_release(info->MeasurementBreach);
            info->MeasurementBreach = NULL;
            nm_record_mark(&info->base, NM_M_MeasurementBreach, true);
            MSET(info, IsDirtyDownCount, true);
            if (info->EndPointType && !strcmp(info->EndPointType, "sitehash"))
                TRY(MSTR(info, SiteHash, NULL));
        } else if (flag)
            SSET(s, AlertFlag, true);
        else
            SSET(s, AlertSent, true);
        m->changed = true;
    }
    return true;
}
bool nm_model_user_event(nm_model *m, yyjson_mut_val *event)
{
    TRY(yyjson_mut_is_obj(event));
    nm_flow_record *incoming = (nm_flow_record *)nm_record_decode(NM_FLOW, event);
    TRY(incoming);
    nm_flow_record *copy = (nm_flow_record *)nm_record_copy(&m->flow->base);
    if (!copy) {
        nm_record_release(&incoming->base);
        return false;
    }
    if (nm_record_has(&incoming->base, NM_F_IsLoggedInWebsite) &&
        !nm_record_null(&incoming->base, NM_F_IsLoggedInWebsite)) {
        copy->IsLoggedInWebsite = incoming->IsLoggedInWebsite;
        nm_record_mark(&copy->base, NM_F_IsLoggedInWebsite, false);
        m->changed = true;
    }
    if (nm_record_has(&incoming->base, NM_F_IsHostsAdded) &&
        !nm_record_null(&incoming->base, NM_F_IsHostsAdded)) {
        copy->IsHostsAdded = incoming->IsHostsAdded;
        nm_record_mark(&copy->base, NM_F_IsHostsAdded, false);
        m->changed = true;
    }
    nm_record_release(&incoming->base);
    nm_record_release(&m->flow->base);
    m->flow = copy;
    return true;
}
bool nm_model_measurement_alert(nm_model *m, int32_t id, uint16_t sample, double scale,
                                double offset, const char *unit, const char *when)
{
    nm_monitor_record *info = edit_info(m, id);
    TRY(info);
    if (info->MeasurementBreach || sample == UINT16_MAX)
        return true;
    bool low = nm_record_has(&info->base, NM_M_LowThreshold) &&
               !nm_record_null(&info->base, NM_M_LowThreshold);
    bool high = nm_record_has(&info->base, NM_M_HighThreshold) &&
                !nm_record_null(&info->base, NM_M_HighThreshold);
    if ((!low && !high) || !isfinite(scale) || scale <= 0 || !isfinite(offset))
        return true;
    if ((low && !isfinite(info->LowThreshold)) || (high && !isfinite(info->HighThreshold)) ||
        (low && high && info->LowThreshold >= info->HighThreshold))
        return true;
    double value = sample * scale + offset;
    if (!isfinite(value))
        return true;
    double tolerance = 8 * DBL_EPSILON * (fabs(sample * scale) + fabs(offset) + fabs(value));
    const char *direction = low && value < info->LowThreshold - tolerance     ? "low"
                            : high && value > info->HighThreshold + tolerance ? "high"
                                                                              : NULL;
    if (!direction)
        return true;
    yyjson_mut_doc *doc = nm_json_new();
    TRY(doc);
    yyjson_mut_val *breach = yyjson_mut_obj(doc);
    bool ok = breach && yyjson_mut_obj_add_str(doc, breach, "Direction", direction) &&
              yyjson_mut_obj_add_real(doc, breach, "Value", value) &&
              yyjson_mut_obj_add_real(doc, breach, "Limit",
                                      !strcmp(direction, "low") ? info->LowThreshold
                                                                : info->HighThreshold) &&
              yyjson_mut_obj_add_str(doc, breach, "Unit", unit ? unit : "raw value") &&
              yyjson_mut_obj_add_str(doc, breach, "ObservedAt", when);
    nm_extension *encoded = ok ? nm_extension_create(breach) : NULL;
    yyjson_mut_doc_free(doc);
    TRY(encoded);
    info->MeasurementBreach = encoded;
    nm_record_mark(&info->base, NM_M_MeasurementBreach, false);
    m->changed = true;
    return true;
}

bool nm_model_probe(nm_model *m, int32_t id, bool up, uint16_t rtt, const char *status,
                    const char *message, const char *when, uint32_t date)
{
    TRY(m->pings.count < m->pings.limit && nm_model_host(m, id));
    for (size_t i = 0; i < m->pings.count; ++i)
        TRY(((nm_ping_record *)m->pings.items[i])->ID != m->sequence);
    nm_monitor_record *info = edit_info(m, id);
    TRY(info);
    nm_status_record *s = edit_status(info);
    TRY(s);
    MSET(info, PacketsSent, nm_monitor_add_i32(info->PacketsSent, 1));
    if (up) {
        MSET(info, PacketsRecieved, nm_monitor_add_i32(info->PacketsRecieved, 1));
        MSET(info, RoundTripTimeTotal, nm_monitor_add_i32(info->RoundTripTimeTotal, rtt));
        if (info->RoundTripTimeMinimum > rtt)
            MSET(info, RoundTripTimeMinimum, rtt);
        if (info->RoundTripTimeMaximum < rtt)
            MSET(info, RoundTripTimeMaximum, rtt);
        MSET(info, RoundTripTimeAverage,
             (float)info->RoundTripTimeTotal / (float)info->PacketsRecieved);
        SSET(s, DownCount, 0);
        MSET(info, IsDirtyDownCount, false);
    } else {
        MSET(info, PacketsLost, nm_monitor_add_i32(info->PacketsLost, 1));
        SSET(s, DownCount, nm_monitor_add_i32(s->DownCount, 1));
    }
    MSET(info, PacketsLostPercentage,
         (float)((double)info->PacketsLost / (double)info->PacketsSent * 100));
    if (info->IsDirtyDownCount) {
        SSET(s, DownCount, 0);
        MSET(info, IsDirtyDownCount, false);
    }
    SSET(s, IsUp, up);
    TRY(SSTR(s, EventTime, when) && SSTR(s, Message, message) && MSTR(info, Status, message));
    nm_ping_record *p = (nm_ping_record *)nm_record_new(NM_PING);
    TRY(p);
    PSET(p, ID, m->sequence);
    PSET(p, MonitorPingInfoID, id);
    PSET(p, RoundTripTime, rtt);
    PSET(p, DateSentInt, date);
    PSET(p, StatusID, 0);
    PSET(p, RoundTripTimeInt, 0);
    _Static_assert(sizeof(time_t) >= 8, "full uint DateSentInt needs 64-bit time_t");
    time_t instant = (time_t)(UINT64_C(1640995200) + date);
    struct tm utc;
    char timestamp[32];
    bool ok = gmtime_r(&instant, &utc) &&
              strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &utc) &&
              PSTR(p, DateSent, timestamp) && PSTR(p, Status, status) &&
              nm_records_append(&m->pings, &p->base);
    if (!ok) {
        nm_record_release(&p->base);
        return false;
    }
    ++m->sequence;
    m->changed = true;
    return true;
}
