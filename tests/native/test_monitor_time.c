#include "monitor_time.h"
#include "monitor_record_internal.h"
#include "nm_json.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define ROOT yyjson_mut_doc_get_root
#define GET yyjson_mut_obj_get
static nm_ping_record *ping(uint32_t date)
{
    nm_ping_record *p = (nm_ping_record *)nm_record_new(NM_PING);
    assert(p);
    p->DateSentInt = date;
    nm_record_mark(&p->base, NM_P_DateSentInt, false);
    assert(nm_record_string(&p->base, NM_P_DateSent, "2026-01-01T00:00:00Z"));
    return p;
}
static void numbers(void)
{
    const uint32_t values[] = {0, 1, 99, 100, 150, 200, 201, UINT32_MAX - 1, UINT32_MAX};
    const int64_t offsets[] = {-(int64_t)UINT32_MAX, -1000, -1, 0, 1, 1000, UINT32_MAX};
    for (size_t i = 0; i < sizeof(values) / sizeof(*values); ++i)
        for (size_t j = 0; j < sizeof(offsets) / sizeof(*offsets); ++j)
            for (unsigned valid = 0; valid < 2; ++valid) {
                nm_time_state s = {.valid = valid, .low = 100, .high = 200, .offset = offsets[j]};
                nm_ping_record *p = ping(values[i]);
                int64_t expected = values[i];
                if (!valid || values[i] < 100 || values[i] > 200)
                    expected += offsets[j];
                bool ok = nm_monitor_time_ping(p, &s);
                assert(ok == (expected >= 0 && expected <= UINT32_MAX));
                if (ok) {
                    assert(p->DateSentInt == (uint32_t)expected);
                    assert(s.target_valid);
                }
                nm_record_release(&p->base);
            }
}
static nm_model model(const char *started)
{
    nm_model m = {0};
    assert(nm_model_open(&m, NULL, NULL, NULL, 10, 100));
    const char *request = "{\"MonitorIPs\":[{\"ID\":7,\"Enabled\":true,\"Address\":\"test\","
                          "\"EndPointType\":\"http\"}]}";
    yyjson_mut_doc *d = nm_json_read(request, strlen(request));
    assert(d);
    assert(nm_model_init(&m, ROOT(d), "test", started));
    yyjson_mut_doc_free(d);
    return m;
}
static void dates(void)
{
    const char *dates[] = {"2024-02-28T23:59:59Z", "2024-02-29T23:59:59.1234567Z",
                           "2026-12-31T23:59:59Z"};
    const char *expected[] = {"2024-02-29T00:00:00Z", "2024-03-01T00:00:00.1234567Z",
                              "2027-01-01T00:00:00Z"};
    for (size_t i = 0; i < 3; ++i) {
        nm_model m = model(dates[i]), candidate = {0};
        assert(nm_model_clone(&candidate, &m));
        assert(nm_monitor_time_begin(&candidate, 1, 0));
        nm_monitor_record *p = nm_model_info(&candidate, 7);
        assert(!strcmp(p->DateStarted, expected[i]) && !strcmp(p->DateEnded, expected[i]));
        assert(!strcmp(nm_model_info(&m, 7)->DateStarted, dates[i]));
        assert(!candidate.clock.correcting);
        yyjson_mut_doc *d = nm_model_encode(&candidate);
        assert(d);
        nm_model restored = {0};
        assert(nm_model_open(&restored, ROOT(d), NULL, NULL, 10, 100));
        assert(restored.clock.present && !restored.clock.correcting);
        nm_model_close(&restored);
        yyjson_mut_doc_free(d);
        nm_model_close(&candidate);
        nm_model_close(&m);
    }
    nm_model old = model("0001-01-01T00:00:00Z");
    assert(nm_monitor_time_begin(&old, 1, 0));
    assert(!strcmp(nm_model_info(&old, 7)->DateStarted, "0001-01-01T00:00:01Z"));
    nm_model_close(&old);
    nm_model bad = model("2024-02-31T00:00:00Z");
    assert(!nm_monitor_time_begin(&bad, 1, 0));
    nm_model_close(&bad);
}
static void nested_and_optional(void)
{
    nm_model m = model("2026-01-01T00:00:00Z");
    nm_monitor_record *p = nm_model_info(&m, 7);
    assert(nm_record_string(&p->MonitorStatus->base, NM_S_EventTime, "2026-01-01T00:00:00Z"));
    const char *json = "{\"ObservedAt\":\"2026-01-01T00:00:00.123Z\",\"Extra\":42}";
    yyjson_mut_doc *d = nm_json_read(json, strlen(json));
    assert(d);
    p->MeasurementBreach = nm_extension_create(ROOT(d));
    nm_record_mark(&p->base, NM_M_MeasurementBreach, false);
    yyjson_mut_doc_free(d);
    nm_model candidate = {0};
    assert(nm_model_clone(&candidate, &m));
    assert(nm_monitor_time_begin(&candidate, -1, 0));
    p = nm_model_info(&candidate, 7);
    assert(!strcmp(p->MonitorStatus->EventTime, "2025-12-31T23:59:59Z"));
    d = nm_json_new();
    yyjson_mut_val *breach = nm_extension_decode(d, p->MeasurementBreach);
    assert(yyjson_mut_equals_str(GET(breach, "ObservedAt"), "2025-12-31T23:59:59.123Z"));
    assert(yyjson_mut_get_uint(GET(breach, "Extra")) == 42);
    yyjson_mut_doc_free(d);
    assert(!strcmp(nm_model_info(&m, 7)->MonitorStatus->EventTime, "2026-01-01T00:00:00Z"));
    nm_model_close(&candidate);
    nm_model_close(&m);
    nm_ping_record *sample = ping(0);
    nm_time_state state = {.offset = 1};
    assert(nm_record_string(&sample->base, NM_P_DateSent, NULL));
    assert(nm_monitor_time_ping(sample, &state));
    assert(nm_record_null(&sample->base, NM_P_DateSent));
    nm_record_release(&sample->base);
    sample = (nm_ping_record *)nm_record_new(NM_PING);
    assert(!nm_monitor_time_ping(sample, &state));
    nm_record_release(&sample->base);
}
static void metadata(void)
{
    nm_time_state s = {.present = true,
                       .valid = true,
                       .low = 10,
                       .high = 20,
                       .correcting = true,
                       .target_valid = true,
                       .target_low = 10,
                       .target_high = 200,
                       .offset = 100,
                       .remaining = 33},
                  out;
    yyjson_mut_doc *d = nm_json_new();
    yyjson_mut_val *v = nm_monitor_time_encode(d, &s);
    assert(v && nm_monitor_time_decode(&out, v));
    assert(out.offset == 100 && out.remaining == 33 && out.correcting && out.high == 20 &&
           out.target_high == 200);
    assert(nm_json_put(d, v, "Remaining", yyjson_mut_uint(d, 1)));
    assert(nm_json_put(d, v, "Correcting", yyjson_mut_bool(d, false)));
    assert(!nm_monitor_time_decode(&out, v));
    assert(nm_json_put(d, v, "Correcting", yyjson_mut_bool(d, true)));
    assert(nm_json_put(d, v, "Offset", yyjson_mut_uint(d, UINT64_MAX)));
    assert(!nm_monitor_time_decode(&out, v));
    yyjson_mut_doc_free(d);
}
int main(void)
{
    numbers();
    dates();
    nested_and_optional();
    metadata();
    puts("time correction numeric/range/calendar/COW/metadata tests passed");
}
