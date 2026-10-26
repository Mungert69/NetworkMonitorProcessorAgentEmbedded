#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "monitor_time.h"
#include "monitor_numbers.h"
#include "monitor_record_internal.h"
#include "nm_json.h"
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#define GET yyjson_mut_obj_get
bool nm_monitor_time_decode(nm_time_state *s, yyjson_mut_val *v)
{
    memset(s, 0, sizeof(*s));
    if (!v)
        return true;
    uint32_t version;
    if (!yyjson_mut_is_obj(v) || !nm_monitor_u32(GET(v, "Version"), &version) || version != 1 ||
        !yyjson_mut_is_bool(GET(v, "Valid")) || !yyjson_mut_is_bool(GET(v, "Correcting")) ||
        !yyjson_mut_is_bool(GET(v, "TargetValid")) || !nm_monitor_u32(GET(v, "Low"), &s->low) ||
        !nm_monitor_u32(GET(v, "High"), &s->high) ||
        !nm_monitor_u32(GET(v, "TargetLow"), &s->target_low) ||
        !nm_monitor_u32(GET(v, "TargetHigh"), &s->target_high) ||
        !nm_monitor_u64(GET(v, "Remaining"), &s->remaining) || !yyjson_mut_is_int(GET(v, "Offset")))
        return false;
    if (yyjson_mut_is_uint(GET(v, "Offset")) && yyjson_mut_get_uint(GET(v, "Offset")) > UINT32_MAX)
        return false;
    s->offset = yyjson_mut_get_sint(GET(v, "Offset"));
    s->valid = yyjson_mut_is_true(GET(v, "Valid"));
    s->correcting = yyjson_mut_is_true(GET(v, "Correcting"));
    s->target_valid = yyjson_mut_is_true(GET(v, "TargetValid"));
    s->present = true;
    return (!s->valid || s->low <= s->high) &&
           (!s->target_valid || s->target_low <= s->target_high) &&
           s->offset >= -(int64_t)UINT32_MAX && s->offset <= UINT32_MAX &&
           (s->correcting
                ? (s->remaining != 0 && (!s->valid || (s->target_valid && s->target_low <= s->low &&
                                                       s->target_high >= s->high)))
                : !s->remaining);
}
yyjson_mut_val *nm_monitor_time_encode(yyjson_mut_doc *d, const nm_time_state *s)
{
    yyjson_mut_val *v = yyjson_mut_obj(d);
    bool ok = v && yyjson_mut_obj_add_uint(d, v, "Version", 1) &&
              yyjson_mut_obj_add_bool(d, v, "Valid", s->valid) &&
              yyjson_mut_obj_add_bool(d, v, "Correcting", s->correcting) &&
              yyjson_mut_obj_add_bool(d, v, "TargetValid", s->target_valid) &&
              yyjson_mut_obj_add_uint(d, v, "Low", s->low) &&
              yyjson_mut_obj_add_uint(d, v, "High", s->high) &&
              yyjson_mut_obj_add_uint(d, v, "TargetLow", s->target_low) &&
              yyjson_mut_obj_add_uint(d, v, "TargetHigh", s->target_high) &&
              yyjson_mut_obj_add_uint(d, v, "Remaining", s->remaining) &&
              yyjson_mut_obj_add_sint(d, v, "Offset", s->offset);
    return ok ? v : NULL;
}
static void range(bool *valid, uint32_t *low, uint32_t *high, uint32_t date)
{
    if (!*valid) {
        *low = *high = date;
        *valid = true;
    } else {
        if (date < *low)
            *low = date;
        if (date > *high)
            *high = date;
    }
}
void nm_monitor_time_observe(nm_time_state *s, uint32_t date)
{
    s->present = true;
    range(&s->valid, &s->low, &s->high, date);
}
void nm_monitor_time_finish(nm_time_state *s)
{
    s->valid = s->target_valid;
    s->low = s->target_low;
    s->high = s->target_high;
    s->remaining = 0;
    s->correcting = false;
}
static bool shifted(uint32_t date, int64_t offset, uint32_t *out)
{
    if (offset < -(int64_t)UINT32_MAX || offset > UINT32_MAX)
        return false;
    int64_t value = (int64_t)date + offset;
    if (value < 0 || value > UINT32_MAX)
        return false;
    *out = (uint32_t)value;
    return true;
}
static bool format_utc(int64_t seconds, char out[32])
{
    time_t t = (time_t)seconds;
    struct tm utc;
    if (!gmtime_r(&t, &utc) || utc.tm_year < -1899 || utc.tm_year > 8099)
        return false;
    return snprintf(out, 32, "%04d-%02d-%02dT%02d:%02d:%02dZ", utc.tm_year + 1900, utc.tm_mon + 1,
                    utc.tm_mday, utc.tm_hour, utc.tm_min, utc.tm_sec) == 20;
}
static bool format(uint32_t date, char out[32])
{
    return format_utc((int64_t)date + INT64_C(1640995200), out);
}
/* Exact UTC ISO timestamps (optional fractional seconds preserved); no local TZ.
 * Civil-day conversion avoids nonportable timegm and dates through double. */
static bool shift_text(const char *text, int64_t offset, char out[48])
{
    if (!text)
        return true;
    int y, m, d, h, n, s, consumed = 0;
    if (sscanf(text, "%4d-%2d-%2dT%2d:%2d:%2d%n", &y, &m, &d, &h, &n, &s, &consumed) != 6 ||
        consumed != 19 || y < 1 || m < 1 || m > 12 || d < 1 || d > 31 || h < 0 || h > 23 || n < 0 ||
        n > 59 || s < 0 || s > 59)
        return false;
    const char *suffix = text + 19;
    size_t suffix_len = strlen(suffix);
    if (!suffix_len || suffix_len > 10 || suffix[suffix_len - 1] != 'Z' ||
        (suffix_len > 1 && (suffix[0] != '.' || suffix_len < 3)))
        return false;
    for (size_t i = 1; i + 1 < suffix_len; ++i)
        if (suffix[i] < '0' || suffix[i] > '9')
            return false;
    int year = y - (m <= 2), era = year / 400;
    unsigned yo = (unsigned)(year - era * 400), mp = (unsigned)(m + (m > 2 ? -3 : 9));
    int64_t days = (int64_t)era * 146097 + yo * 365 + yo / 4 - yo / 100 + (153 * mp + 2) / 5 +
                   (unsigned)d - 1 - 719468;
    int64_t seconds = days * 86400 + h * 3600 + n * 60 + s;
    if (offset < -(int64_t)UINT32_MAX || offset > UINT32_MAX)
        return false;
    char canonical[32];
    /* Reject normalized invalid dates such as February 31. */
    if (!format_utc(seconds, canonical) || strncmp(canonical, text, 19) ||
        !format_utc(seconds + offset, canonical))
        return false;
    memcpy(out, canonical, 19);
    memcpy(out + 19, suffix, suffix_len + 1);
    return true;
}
static bool record_date(nm_record *r, unsigned field, const char *value, int64_t offset)
{
    if (!nm_record_has(r, field) || nm_record_null(r, field) || !value)
        return true;
    char out[48];
    return shift_text(value, offset, out) && nm_record_string(r, field, out);
}
bool nm_monitor_time_ping(nm_ping_record *p, nm_time_state *s)
{
    if (!nm_record_has(&p->base, NM_P_DateSentInt) || nm_record_null(&p->base, NM_P_DateSentInt))
        return false;
    uint32_t value = p->DateSentInt;
    if (!s->valid || value < s->low || value > s->high) {
        if (!shifted(value, s->offset, &value))
            return false;
        char out[32];
        if (nm_record_has(&p->base, NM_P_DateSent) && !nm_record_null(&p->base, NM_P_DateSent) &&
            (!format(value, out) || !nm_record_string(&p->base, NM_P_DateSent, out)))
            return false;
        p->DateSentInt = value;
    }
    range(&s->target_valid, &s->target_low, &s->target_high, value);
    return true;
}
bool nm_monitor_time_begin(nm_model *m, int64_t offset, uint64_t pages)
{
    nm_time_state *s = &m->clock;
    if (s->correcting || offset < -(int64_t)UINT32_MAX || offset > UINT32_MAX)
        return false;
    s->present = true;
    s->correcting = true;
    s->offset = offset;
    s->remaining = pages;
    s->target_valid = s->valid;
    s->target_low = s->low;
    s->target_high = s->high;
    for (size_t i = 0; i < m->infos.count; ++i) {
        nm_monitor_record *p = (nm_monitor_record *)nm_records_edit(&m->infos, i);
        if (!p || !record_date(&p->base, NM_M_DateStarted, p->DateStarted, offset) ||
            !record_date(&p->base, NM_M_DateEnded, p->DateEnded, offset))
            return false;
        if (p->MonitorStatus) {
            nm_status_record *status = (nm_status_record *)nm_record_copy(&p->MonitorStatus->base);
            if (!status)
                return false;
            nm_record_release(&p->MonitorStatus->base);
            p->MonitorStatus = status;
            if (!record_date(&status->base, NM_S_EventTime, status->EventTime, offset))
                return false;
        }
        if (p->MeasurementBreach) {
            yyjson_mut_doc *doc = nm_json_new();
            yyjson_mut_val *v = doc ? nm_extension_decode(doc, p->MeasurementBreach) : NULL;
            yyjson_mut_val *observed = GET(v, "ObservedAt");
            bool ok = v != NULL;
            if (yyjson_mut_is_str(observed)) {
                char out[48];
                ok = shift_text(yyjson_mut_get_str(observed), offset, out) &&
                     nm_json_put_str(doc, v, "ObservedAt", out);
            } else if (observed && !yyjson_mut_is_null(observed))
                ok = false;
            nm_extension *copy = ok ? nm_extension_create(v) : NULL;
            yyjson_mut_doc_free(doc);
            if (!copy)
                return false;
            nm_extension_release(p->MeasurementBreach);
            p->MeasurementBreach = copy;
        }
    }
    if (!pages) {
        for (size_t i = 0; i < m->pings.count; ++i) {
            nm_ping_record *p = (nm_ping_record *)nm_records_edit(&m->pings, i);
            if (!p || !nm_monitor_time_ping(p, s))
                return false;
        }
        nm_monitor_time_finish(s);
    }
    return true;
}
