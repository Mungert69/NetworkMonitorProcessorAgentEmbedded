/* Shared assertions: CMake runs these against the pre-refactor reference and
 * against the actual typed firmware core via test_typed_core.c. The JSON view
 * in the latter is a test boundary adapter, not the firmware's runtime state.
 * Use the root CMake/CTest targets with address/undefined-behaviour sanitizers.
 *
 * Numeric wire expectations come from the source-linked System.Text.Json oracle.
 * State expectations additionally reference the sibling .NET agent:
 * Services/MonitorPingCollection.cs (Merge, Zero), MonitorPingProcessor.cs
 * (UpdateMonitorPingInfosFromMonitorIPQueue, ProcessesMonitorReturnData,
 * ResetAlerts, PiID assignment), and NetworkMonitorLib/Utils/
 * SwapMonitorPingInfoComparer.cs. These are regression expectations, not xfails.
 * Mutation APIs operate on disposable candidates; only successful commit may
 * replace live RAM. Deliberately do not require a failed candidate to roll back.
 * Intentional firmware adaptations: ID collision pauses instead of dropping a
 * duplicate .NET dictionary sample; TotalReset resets the live key to 1 rather
 * than retaining .NET's stale live key; deleted hosts retain disabled info until
 * their pending records are acknowledged rather than leaving orphan .NET pings.
 * An application dataset-delete acknowledgement retires residual pings/info for
 * absent active hosts; this intentionally fixes .NET's orphan retention bug.
 * Retained info and removal/swap queues share max_hosts as their metadata bound.
 * Numeric core fixtures intentionally permit arbitrary parent IDs; legacy
 * publishability/parent validation belongs to the state adapter, not this suite.
 * Fixture limits: all eight PingInfo properties are compared for imported state
 * and surviving acknowledgements, including nulls, escaping and exact integers.
 * Synthetic FutureMetadata below checks firmware forward-compatible retention;
 * it is not a .NET model property (default STJ ignores unknown properties).
 * Probe rollover additionally compares all eight emitted fields against the
 * fixture's uint-max date plus supplied probe values. This is not exhaustive
 * coverage of every timestamp, string encoding or nullable probe input.
 * MonitorPingInfo has no source-linked fixture because of its dependency graph;
 * its transitions/retention and computed ID/Host aliases are manually traced,
 * not an exhaustive generated schema/default-value comparison. No stub models.
 */
#include "monitor_core.h"
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GET yyjson_mut_obj_get
#define ROOT yyjson_mut_doc_get_root
#define COUNT(a) (sizeof(a) / sizeof((a)[0]))
#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "  %s:%d: %s\n", __func__, __LINE__, #x); return false; \
} } while (0)
#define EXPECT_CASE(x, name) do { if (!(x)) { \
    fprintf(stderr, "  %s:%d: %s [%s]\n", __func__, __LINE__, #x, (name)); \
    expectation_failures++; \
} } while (0)

static const char *fixture_dir = "tests/fixtures/dotnet";
static const char *app = "parity-agent";
static const char *when = "2026-09-27T12:00:00Z";
static unsigned expectation_failures;
/* Per-test ownership pool permits fail-fast assertions without leaking documents. */
static yyjson_mut_doc *documents[512];
static size_t document_count;
static nm_monitor_core cores[256];
static size_t core_count;

static void must(bool condition, const char *message)
{
    if (!condition) { fprintf(stderr, "Test infrastructure: %s\n", message); exit(2); }
}
static yyjson_mut_doc *own(yyjson_mut_doc *doc)
{
    must(doc != NULL && document_count < COUNT(documents), "document allocation/pool");
    documents[document_count++] = doc;
    return doc;
}
static yyjson_mut_doc *parse(const char *json)
{
    yyjson_doc *immutable = yyjson_read(json, strlen(json), 0);
    must(immutable != NULL, "invalid test JSON");
    yyjson_mut_doc *doc = yyjson_doc_mut_copy(immutable, NULL);
    yyjson_doc_free(immutable);
    return own(doc);
}
static yyjson_mut_doc *fixture(const char *name)
{
    char path[4096];
    int length = snprintf(path, sizeof(path), "%s/%s", fixture_dir, name);
    must(length > 0 && (size_t)length < sizeof(path), "fixture path too long");
    yyjson_read_err error;
    yyjson_doc *immutable = yyjson_read_file(path, 0, NULL, &error);
    if (!immutable) fprintf(stderr, "Cannot read %s: %s\n", path, error.msg);
    must(immutable != NULL, "missing or invalid .NET fixture");
    yyjson_mut_doc *doc = yyjson_doc_mut_copy(immutable, NULL);
    yyjson_doc_free(immutable);
    return own(doc);
}
static nm_monitor_core *new_core(void)
{
    must(core_count < COUNT(cores), "core pool full");
    nm_monitor_core *core = &cores[core_count++];
    core->doc = NULL;
    return core;
}
static nm_monitor_core *empty_core(void)
{
    nm_monitor_core *core = new_core();
    must(nm_monitor_open(core, NULL, NULL, NULL), "open empty core");
    return core;
}
static nm_monitor_core *clone_core(nm_monitor_core *source)
{
    nm_monitor_core *copy = new_core();
    must(nm_monitor_clone(copy, source), "clone core");
    return copy;
}
static void cleanup(void)
{
    for (size_t i = 0; i < core_count; i++) nm_monitor_close(&cores[i]);
    for (size_t i = 0; i < document_count; i++) yyjson_mut_doc_free(documents[i]);
    core_count = document_count = 0;
}
static void set(yyjson_mut_doc *doc, yyjson_mut_val *object, const char *key,
                yyjson_mut_val *value)
{
    must(value && yyjson_mut_obj_put(object, yyjson_mut_strcpy(doc, key), value), "set property");
}
static void set_copy(nm_monitor_core *core, yyjson_mut_val *object,
                     const char *key, yyjson_mut_val *value)
{
    set(core->doc, object, key, yyjson_mut_val_mut_copy(core->doc, value));
}
static void set_uint(nm_monitor_core *core, yyjson_mut_val *object,
                     const char *key, uint64_t value)
{
    set(core->doc, object, key, yyjson_mut_uint(core->doc, value));
}
static void set_int(nm_monitor_core *core, yyjson_mut_val *object,
                    const char *key, int32_t value)
{
    set(core->doc, object, key, yyjson_mut_sint(core->doc, value));
}
static yyjson_mut_val *queue(nm_monitor_core *core, const char *name)
{ return GET(nm_monitor_data(core), name); }
static yyjson_mut_val *info(nm_monitor_core *core)
{ return yyjson_mut_arr_get_first(queue(core, "MonitorPingInfos")); }
static yyjson_mut_val *host(nm_monitor_core *core)
{ return yyjson_mut_arr_get_first(nm_monitor_hosts(core)); }
static bool integer_is(yyjson_mut_val *value, int32_t expected)
{
    int32_t actual;
    return nm_monitor_i32(value, &actual) && actual == expected;
}
static bool uint_is(yyjson_mut_val *value, uint64_t expected)
{
    uint64_t actual;
    return nm_monitor_u64(value, &actual) && actual == expected;
}
static bool contains_id(yyjson_mut_val *array, uint64_t id)
{
    size_t i, n; yyjson_mut_val *value;
    yyjson_mut_arr_foreach(array, i, n, value)
        if (uint_is(GET(value, "ID"), id)) return true;
    return false;
}
static yyjson_mut_val *saved_root(nm_monitor_core *core)
{ return ROOT(own(yyjson_mut_doc_mut_copy(core->doc, NULL))); }
static bool update(nm_monitor_core *core, const char *json)
{ return nm_monitor_updates(core, ROOT(parse(json)), app, 16, when); }
static nm_monitor_core *configured_core(void)
{
    nm_monitor_core *core = empty_core();
    must(nm_monitor_init(core, ROOT(parse(
        "{\"PingParams\":{\"Timeout\":1000,\"AlertThreshold\":3,\"HostLimit\":16},"
        "\"MonitorIPs\":[{\"ID\":7,\"Address\":\"example.test\",\"Enabled\":true,"
        "\"EndPointType\":\"sitehash\",\"Port\":65535,\"SkipCycles\":null,"
        "\"UserID\":\"owner\",\"Username\":\"user\",\"Password\":\"test-only\","
        "\"Args\":\"x=1\",\"AddUserEmail\":\"test@example.test\",\"IsEmailVerified\":true}]}")),
        app, 16, when), "configure test host");
    return core;
}

static bool test_fixture_exact_ack(void)
{
    yyjson_mut_doc *pings = fixture("ping-info.json");
    yyjson_mut_doc *removals = fixture("remove-ping-info.json");
    const uint64_t required[] = {UINT64_C(2147483647), UINT64_C(2147483648),
        UINT64_C(2147483649), UINT64_C(4294967295), UINT64_C(9007199254740992),
        UINT64_C(9007199254740993), UINT64_MAX};
    nm_monitor_core *live = empty_core();
    set_copy(live, nm_monitor_data(live), "PingInfos", ROOT(pings));
    const char *fields[] = {"ID", "DateSent", "Status", "StatusID", "RoundTripTime",
        "RoundTripTimeInt", "MonitorPingInfoID", "DateSentInt"};
    yyjson_mut_val *metadata = ROOT(parse(
        "{\"precise\":18446744073709551615,\"nested\":[null,true,\"future\\nvalue\"]}"));
    size_t pi, pn; yyjson_mut_val *ping;
    yyjson_mut_arr_foreach(queue(live, "PingInfos"), pi, pn, ping) {
        yyjson_mut_val *oracle = yyjson_mut_arr_get(ROOT(pings), pi);
        CHECK(yyjson_mut_obj_size(oracle) == COUNT(fields));
        for (size_t f = 0; f < COUNT(fields); f++) {
            CHECK(GET(oracle, fields[f]) != NULL);
            CHECK(yyjson_mut_equals(GET(ping, fields[f]), GET(oracle, fields[f])));
        }
        set_copy(live, ping, "FutureMetadata", metadata);
    }
    nm_monitor_core *restored = new_core();
    CHECK(nm_monitor_open(restored, nm_monitor_root(live), NULL, NULL));
    CHECK(yyjson_mut_equals(queue(restored, "PingInfos"), queue(live, "PingInfos")));
    for (size_t i = 0; i < COUNT(required); i++) {
        CHECK(contains_id(ROOT(pings), required[i]));
        CHECK(contains_id(ROOT(removals), required[i]));
    }
    size_t index, count; yyjson_mut_val *removal;
    yyjson_mut_arr_foreach(ROOT(removals), index, count, removal) {
        nm_monitor_core *candidate = clone_core(restored);
        yyjson_mut_doc *ack = parse("{\"RemovePingInfos\":[]}");
        yyjson_mut_val *item = yyjson_mut_val_mut_copy(ack, removal);
        /* .NET dictionary removal keys by ID, regardless of parent ID. */
        set(ack, item, "MonitorPingInfoID", yyjson_mut_sint(ack, 17));
        CHECK(yyjson_mut_arr_append(GET(ROOT(ack), "RemovePingInfos"), item));
        CHECK(nm_monitor_ack(candidate, ROOT(ack)));
        uint64_t removed;
        CHECK(nm_monitor_u64(GET(removal, "ID"), &removed));
        CHECK(yyjson_mut_arr_size(queue(candidate, "PingInfos")) + 1 == count);
        CHECK(!contains_id(queue(candidate, "PingInfos"), removed));
        size_t j, n; yyjson_mut_val *original;
        yyjson_mut_arr_foreach(queue(live, "PingInfos"), j, n, original) {
            uint64_t id;
            CHECK(nm_monitor_u64(GET(original, "ID"), &id));
            CHECK(contains_id(queue(candidate, "PingInfos"), id) == (id != removed));
            if (id != removed) {
                size_t k, kn; yyjson_mut_val *survivor;
                yyjson_mut_arr_foreach(queue(candidate, "PingInfos"), k, kn, survivor)
                    if (uint_is(GET(survivor, "ID"), id))
                        CHECK(yyjson_mut_equals(survivor, original));
            }
        }
        CHECK(nm_monitor_ack(candidate, ROOT(ack))); /* replay is idempotent */
        CHECK(yyjson_mut_arr_size(queue(candidate, "PingInfos")) + 1 == count);
        CHECK(yyjson_mut_equals(queue(restored, "PingInfos"), queue(live, "PingInfos")));
        nm_monitor_core *reopened = new_core();
        CHECK(nm_monitor_open(reopened, nm_monitor_root(candidate), NULL, NULL));
        CHECK(yyjson_mut_equals(nm_monitor_root(reopened), nm_monitor_root(candidate)));
    }
    return true;
}

static bool test_oracle_ping_numeric_validation(void)
{
    yyjson_mut_doc *cases = fixture("deserialization-cases.json");
    const char *fields[] = {"ID", "DateSentInt", "StatusID", "RoundTripTime", "MonitorPingInfoID"};
    unsigned examined = 0, rejected = 0, nullable = 0;
    size_t i, n; yyjson_mut_val *test;
    yyjson_mut_arr_foreach(ROOT(cases), i, n, test) {
        if (!yyjson_mut_equals_str(GET(test, "Model"), "PingInfo")) continue;
        const char *input = yyjson_mut_get_str(GET(test, "Input"));
        /* Only valid JSON objects containing exactly one numeric model field.
         * Other oracle cases test STJ parsing/model semantics beyond this API. */
        yyjson_doc *raw = yyjson_read(input, strlen(input), 0);
        if (!raw) continue;
        yyjson_mut_doc *doc = own(yyjson_doc_mut_copy(raw, NULL));
        yyjson_doc_free(raw);
        yyjson_mut_val *value = ROOT(doc);
        if (!yyjson_mut_is_obj(value) || yyjson_mut_obj_size(value) != 1) continue;
        bool numeric = false;
        for (size_t j = 0; j < COUNT(fields); j++) if (GET(value, fields[j])) numeric = true;
        if (!numeric) continue;
        bool accepted = yyjson_mut_is_true(GET(test, "Accepted"));
        if (yyjson_mut_is_null(GET(value, "RoundTripTime"))) nullable++;
        if (!GET(value, "ID")) set(doc, value, "ID", yyjson_mut_uint(doc, 0));
        if (!GET(value, "MonitorPingInfoID"))
            set(doc, value, "MonitorPingInfoID", yyjson_mut_sint(doc, 0));
        nm_monitor_core *seed = empty_core();
        CHECK(yyjson_mut_arr_append(queue(seed, "PingInfos"), yyjson_mut_val_mut_copy(seed->doc, value)));
        nm_monitor_core *loaded = new_core();
        bool actual = nm_monitor_open(loaded, nm_monitor_root(seed), NULL, NULL);
        EXPECT_CASE(actual == accepted, yyjson_mut_get_str(GET(test, "Name")));
        if (!actual) CHECK(loaded->doc == NULL);
        examined++;
        if (!accepted) rejected++;
    }
    CHECK(examined >= 50 && rejected >= 40 && nullable == 1);
    printf("  checked %u source-linked PingInfo numeric cases (%u rejected by .NET)\n", examined, rejected);
    return true;
}

static bool test_oracle_ack_numeric_validation(void)
{
    yyjson_mut_doc *cases = fixture("deserialization-cases.json");
    unsigned examined = 0;
    size_t i, n; yyjson_mut_val *test;
    yyjson_mut_arr_foreach(ROOT(cases), i, n, test) {
        const char *key;
        if (yyjson_mut_equals_str(GET(test, "Model"), "RemovePingInfo")) key = "RemovePingInfos";
        else if (yyjson_mut_equals_str(GET(test, "Model"), "SwapMonitorPingInfo")) key = "SwapMonitorPingInfos";
        else continue;
        yyjson_mut_doc *input = parse(yyjson_mut_get_str(GET(test, "Input")));
        if (!GET(ROOT(input), "ID")) continue;
        yyjson_mut_doc *ack = parse("{}");
        yyjson_mut_val *items = yyjson_mut_arr(ack);
        set(ack, ROOT(ack), key, items);
        CHECK(yyjson_mut_arr_append(items, yyjson_mut_val_mut_copy(ack, ROOT(input))));
        nm_monitor_core *core = empty_core();
        bool actual = nm_monitor_ack(core, ROOT(ack));
        EXPECT_CASE(actual == yyjson_mut_is_true(GET(test, "Accepted")),
                    yyjson_mut_get_str(GET(test, "Name")));
        examined++;
    }
    CHECK(examined >= 20);
    return true;
}

static bool test_integer_helpers(void)
{
    yyjson_mut_doc *doc = parse("[0,2147483647,2147483648,4294967295,4294967296,"
        "9007199254740993,18446744073709551615,-1,-2147483648,-2147483649,"
        "1.0,1e0,\"1\",true,null,{},[]]");
    const bool u64_ok[] = {true,true,true,true,true,true,true,false,false,false,false,false,false,false,false,false,false};
    const bool u32_ok[] = {true,true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,false};
    const bool i32_ok[] = {true,true,false,false,false,false,false,true,true,false,false,false,false,false,false,false,false};
    CHECK(yyjson_mut_arr_size(ROOT(doc)) == COUNT(u64_ok));
    for (size_t i = 0; i < COUNT(u64_ok); i++) {
        yyjson_mut_val *value = yyjson_mut_arr_get(ROOT(doc), i);
        uint64_t u64 = 123; uint32_t u32 = 123; int32_t i32 = 123;
        CHECK(nm_monitor_u64(value, &u64) == u64_ok[i]);
        CHECK(nm_monitor_u32(value, &u32) == u32_ok[i]);
        CHECK(nm_monitor_i32(value, &i32) == i32_ok[i]);
        CHECK(u64_ok[i] || u64 == 123);
        CHECK(u32_ok[i] || u32 == 123);
        CHECK(i32_ok[i] || i32 == 123);
    }
    uint64_t u64; uint32_t u32; int32_t i32;
    CHECK(!nm_monitor_u64(NULL, &u64) && !nm_monitor_u32(NULL, &u32) && !nm_monitor_i32(NULL, &i32));
    CHECK(!nm_monitor_u64(ROOT(doc), NULL) && !nm_monitor_u32(ROOT(doc), NULL) && !nm_monitor_i32(ROOT(doc), NULL));
    CHECK(nm_monitor_add_i32(INT32_MAX, 1) == INT32_MIN);
    CHECK(nm_monitor_add_i32(INT32_MIN, -1) == INT32_MAX);
    CHECK(nm_monitor_add_i32(INT32_MAX, INT32_MAX) == -2);
    return true;
}

static bool test_piid_u32_rollover(void)
{
    nm_monitor_core *core = configured_core();
    yyjson_mut_doc *oracle_doc = fixture("ping-info.json");
    yyjson_mut_val *oracle = NULL, *record; size_t fi, fn;
    yyjson_mut_arr_foreach(ROOT(oracle_doc), fi, fn, record)
        if (uint_is(GET(record, "DateSentInt"), UINT32_MAX)) oracle = record;
    CHECK(oracle != NULL);
    set_uint(core, nm_monitor_data(core), "PiIDKey", UINT32_MAX);
    const uint64_t ids[] = {UINT32_MAX, 0, 1};
    for (size_t i = 0; i < COUNT(ids); i++) {
        CHECK(nm_monitor_probe(core, host(core), true, UINT16_MAX, "ok", "alive", when, UINT32_MAX));
        yyjson_mut_val *ping = yyjson_mut_arr_get(queue(core, "PingInfos"), i);
        CHECK(uint_is(GET(ping, "ID"), ids[i]));
        CHECK(uint_is(GET(ping, "DateSentInt"), UINT32_MAX));
        CHECK(uint_is(GET(ping, "RoundTripTime"), UINT16_MAX));
        CHECK(integer_is(GET(ping, "MonitorPingInfoID"), 7));
        /* Keep DateSent/DateSentInt from actual STJ output, replace only values
         * selected by the probe call; whole-object equality checks field shape. */
        yyjson_mut_doc *expected_doc = own(yyjson_mut_doc_new(NULL));
        yyjson_mut_val *expected = yyjson_mut_val_mut_copy(expected_doc, oracle);
        yyjson_mut_doc_set_root(expected_doc, expected);
        set(expected_doc, expected, "ID", yyjson_mut_uint(expected_doc, ids[i]));
        set(expected_doc, expected, "MonitorPingInfoID", yyjson_mut_uint(expected_doc, 7));
        set(expected_doc, expected, "Status", yyjson_mut_str(expected_doc, "ok"));
        set(expected_doc, expected, "StatusID", yyjson_mut_uint(expected_doc, 0));
        set(expected_doc, expected, "RoundTripTimeInt", yyjson_mut_uint(expected_doc, 0));
        set(expected_doc, expected, "RoundTripTime", yyjson_mut_uint(expected_doc, UINT16_MAX));
        CHECK(yyjson_mut_equals(ping, expected));
    }
    CHECK(uint_is(GET(nm_monitor_data(core), "PiIDKey"), 2));
    CHECK(integer_is(GET(info(core), "PacketsRecieved"), 3));
    CHECK(integer_is(GET(info(core), "RoundTripTimeTotal"), 196605));
    nm_monitor_core *reopened = new_core();
    CHECK(nm_monitor_open(reopened, nm_monitor_root(core), NULL, NULL));
    CHECK(yyjson_mut_equals(nm_monitor_root(core), nm_monitor_root(reopened)));
    return true;
}

static bool test_counter_rollover_and_statistics(void)
{
    nm_monitor_core *core = configured_core();
    CHECK(nm_monitor_probe(core, host(core), true, 10, "ok", "up", when, 1));
    CHECK(nm_monitor_probe(core, host(core), false, 0, "timeout", "down", when, 2));
    CHECK(nm_monitor_probe(core, host(core), true, 20, "ok", "up", when, 3));
    CHECK(integer_is(GET(info(core), "PacketsSent"), 3));
    CHECK(integer_is(GET(info(core), "PacketsRecieved"), 2));
    CHECK(integer_is(GET(info(core), "PacketsLost"), 1));
    CHECK(integer_is(GET(info(core), "RoundTripTimeMinimum"), 10));
    CHECK(integer_is(GET(info(core), "RoundTripTimeMaximum"), 20));
    CHECK(yyjson_mut_get_num(GET(info(core), "RoundTripTimeAverage")) == 15.0);
    CHECK(yyjson_mut_get_num(GET(info(core), "PacketsLostPercentage")) == (double)(float)(100.0 / 3.0));
    set_int(core, info(core), "PacketsSent", INT32_MAX);
    set_int(core, info(core), "PacketsLost", INT32_MAX);
    set_int(core, GET(info(core), "MonitorStatus"), "DownCount", INT32_MAX);
    CHECK(nm_monitor_probe(core, host(core), false, 0, "timeout", "down", when, 4));
    CHECK(integer_is(GET(info(core), "PacketsSent"), INT32_MIN));
    CHECK(integer_is(GET(info(core), "PacketsLost"), INT32_MIN));
    CHECK(integer_is(GET(GET(info(core), "MonitorStatus"), "DownCount"), INT32_MIN));
    return true;
}

static bool test_metadata_and_disabled_preservation(void)
{
    nm_monitor_core *core = configured_core();
    CHECK(nm_monitor_probe(core, host(core), true, 23, "ok", "alive", when, 42));
    set_copy(core, info(core), "PredictStatus", ROOT(parse("{\"custom\":[1,null,\"keep\"]}")));
    set_copy(core, info(core), "ModelConfig", ROOT(parse("{\"Version\":9007199254740993}")));
    set_copy(core, nm_monitor_root(core), "Extension", ROOT(parse("{\"opaque\":true}")));
    set_copy(core, info(core), "FutureMetadata", ROOT(parse("{\"opaque\":[18446744073709551615,null]}")));
    yyjson_mut_val *before = saved_root(core);
    CHECK(update(core, "[{\"ID\":7,\"Address\":\"changed.test\",\"Enabled\":false,"
        "\"EndPointType\":\"sitehash\",\"Port\":443,\"Timeout\":0,\"SkipCycles\":2,"
        "\"UserID\":\"new-owner\",\"Username\":\"new-user\",\"Password\":\"new-test-only\","
        "\"Args\":\"new args\",\"AddUserEmail\":\"new@example.test\",\"IsEmailVerified\":false}]"));
    CHECK(yyjson_mut_is_false(GET(info(core), "Enabled")));
    CHECK(yyjson_mut_is_false(GET(host(core), "Enabled")));
    CHECK(yyjson_mut_equals_str(GET(info(core), "Address"), "changed.test"));
    CHECK(yyjson_mut_equals_str(GET(info(core), "Host"), "changed.test"));
    CHECK(yyjson_mut_equals_str(GET(info(core), "UserID"), "new-owner"));
    CHECK(yyjson_mut_equals_str(GET(info(core), "Username"), "new-user"));
    CHECK(yyjson_mut_equals_str(GET(info(core), "Password"), "new-test-only"));
    CHECK(yyjson_mut_equals_str(GET(info(core), "Args"), "new args"));
    CHECK(yyjson_mut_equals_str(GET(info(core), "AddUserEmail"), "new@example.test"));
    CHECK(integer_is(GET(info(core), "Timeout"), 1000));
    CHECK(integer_is(GET(info(core), "Port"), 443));
    CHECK(integer_is(GET(info(core), "SkipCycles"), 2));
    CHECK(yyjson_mut_is_false(GET(info(core), "IsEmailVerified")));
    yyjson_mut_val *old_info = yyjson_mut_arr_get_first(GET(GET(before, "ProcessorData"), "MonitorPingInfos"));
    const char *retained[] = {"PacketsSent", "PacketsRecieved", "RoundTripTimeTotal",
        "MonitorStatus", "PredictStatus", "ModelConfig", "DateStarted", "DateEnded", "FutureMetadata"};
    for (size_t i = 0; i < COUNT(retained); i++)
        CHECK(yyjson_mut_equals(GET(info(core), retained[i]), GET(old_info, retained[i])));
    CHECK(yyjson_mut_equals(queue(core, "PingInfos"), GET(GET(before, "ProcessorData"), "PingInfos")));
    CHECK(yyjson_mut_equals(GET(nm_monitor_root(core), "Extension"), GET(before, "Extension")));
    nm_monitor_core *reopened = new_core();
    CHECK(nm_monitor_open(reopened, nm_monitor_root(core), NULL, NULL));
    CHECK(yyjson_mut_equals(nm_monitor_root(reopened), nm_monitor_root(core)));
    CHECK(update(reopened, "[{\"ID\":7,\"Address\":\"changed.test\",\"Enabled\":true}]"));
    CHECK(integer_is(GET(info(reopened), "PacketsSent"), 1));
    return true;
}

static bool test_swap_delete_queues(void)
{
    nm_monitor_core *core = configured_core();
    CHECK(nm_monitor_probe(core, host(core), true, 10, "ok", "alive", when, 1));
    yyjson_mut_val *pending = GET(saved_root(core), "ProcessorData");
    CHECK(update(core, "[{\"ID\":7,\"Delete\":true}]"));
    CHECK(yyjson_mut_arr_size(nm_monitor_hosts(core)) == 0);
    CHECK(yyjson_mut_is_false(GET(info(core), "Enabled")));
    CHECK(yyjson_mut_arr_size(queue(core, "RemoveMonitorPingInfoIDs")) == 1);
    CHECK(integer_is(yyjson_mut_arr_get_first(queue(core, "RemoveMonitorPingInfoIDs")), 7));
    CHECK(yyjson_mut_equals(queue(core, "PingInfos"), GET(pending, "PingInfos")));
    CHECK(nm_monitor_ack(core, ROOT(parse("{\"RemoveMonitorPingInfoIDs\":[8]}"))));
    CHECK(yyjson_mut_arr_size(queue(core, "RemoveMonitorPingInfoIDs")) == 1);
    CHECK(nm_monitor_ack(core, ROOT(parse("{\"RemoveMonitorPingInfoIDs\":[7]}"))));
    CHECK(yyjson_mut_arr_size(queue(core, "RemoveMonitorPingInfoIDs")) == 0);
    CHECK(yyjson_mut_arr_size(queue(core, "PingInfos")) == 0);
    CHECK(yyjson_mut_arr_size(queue(core, "MonitorPingInfos")) == 0);
    CHECK(nm_monitor_ack(core, ROOT(parse("{\"RemovePingInfos\":[{\"ID\":1,\"MonitorPingInfoID\":7}]}"))));
    CHECK(yyjson_mut_arr_size(queue(core, "PingInfos")) == 0);

    nm_monitor_core *source = configured_core();
    CHECK(nm_monitor_probe(source, host(source), true, 33, "ok", "alive", when, 99));
    nm_monitor_core *target = empty_core();
    yyjson_mut_doc *updates = parse("[{\"ID\":7,\"Address\":\"example.test\",\"Enabled\":true,\"IsSwapping\":true}]");
    set(updates, yyjson_mut_arr_get_first(ROOT(updates)), "MonitorPingInfo",
        yyjson_mut_val_mut_copy(updates, info(source)));
    set(updates, GET(yyjson_mut_arr_get_first(ROOT(updates)), "MonitorPingInfo"),
        "ID", yyjson_mut_sint(updates, 12345));
    CHECK(nm_monitor_updates(target, ROOT(updates), "new-agent", 16, when));
    CHECK(integer_is(GET(info(target), "ID"), 12345));
    CHECK(nm_monitor_reconcile(target, "new-agent", when));
    CHECK(integer_is(GET(info(target), "ID"), 12345));
    CHECK(integer_is(GET(info(target), "PacketsSent"), 1));
    CHECK(integer_is(GET(info(target), "RoundTripTimeTotal"), 33));
    CHECK(yyjson_mut_equals_str(GET(info(target), "AppID"), "new-agent"));
    CHECK(yyjson_mut_arr_size(queue(target, "SwapMonitorPingInfos")) == 1);
    CHECK(integer_is(GET(yyjson_mut_arr_get_first(queue(target, "SwapMonitorPingInfos")), "ID"), 7));
    CHECK(nm_monitor_ack(target, ROOT(parse("{\"SwapMonitorPingInfos\":[{\"ID\":8,\"AppID\":\"new-agent\"}]}"))));
    CHECK(yyjson_mut_arr_size(queue(target, "SwapMonitorPingInfos")) == 1);
    CHECK(nm_monitor_ack(target, ROOT(parse("{\"SwapMonitorPingInfos\":[{\"ID\":7,\"AppID\":\"new-agent\"}]}"))));
    CHECK(yyjson_mut_arr_size(queue(target, "SwapMonitorPingInfos")) == 0);
    CHECK(update(target, "[{\"ID\":7,\"Address\":\"example.test\",\"Enabled\":true}]"));
    CHECK(integer_is(GET(info(target), "ID"), 7)); /* later Fill overwrites supplied ID */
    CHECK(update(source, "[{\"ID\":7,\"Delete\":true,\"IsSwapping\":true}]"));
    CHECK(yyjson_mut_arr_size(queue(source, "RemoveMonitorPingInfoIDs")) == 0);
    CHECK(yyjson_mut_arr_size(nm_monitor_hosts(source)) == 0);
    CHECK(yyjson_mut_arr_size(queue(source, "PingInfos")) == 1);
    return true;
}

static bool test_swap_ack_dotnet_id_comparer(void)
{
    nm_monitor_core *core = empty_core();
    yyjson_mut_doc *swaps = fixture("swap-monitor-ping-info.json");
    set_copy(core, nm_monitor_data(core), "SwapMonitorPingInfos", ROOT(swaps));
    yyjson_mut_doc *ack = parse("{\"SwapMonitorPingInfos\":[{\"ID\":2147483647,\"AppID\":\"different-agent\"}]}");
    CHECK(nm_monitor_ack(core, ROOT(ack)));
    /* The real SwapMonitorPingInfoComparer compares ID only, not AppID. */
    CHECK(yyjson_mut_arr_size(queue(core, "SwapMonitorPingInfos")) + 1 == yyjson_mut_arr_size(ROOT(swaps)));
    return true;
}

static bool test_alerts_reset_and_dirty_downcount(void)
{
    nm_monitor_core *core = configured_core();
    CHECK(nm_monitor_probe(core, host(core), false, 0, "timeout", "down", when, 1));
    set_copy(core, info(core), "SiteHash", ROOT(parse("\"old-hash\"")));
    yyjson_mut_val *ids = ROOT(parse("[7]"));
    CHECK(nm_monitor_alert(core, "processorAlertFlag", ids, app));
    CHECK(nm_monitor_alert(core, "processorAlertSent", ids, app));
    yyjson_mut_val *status = GET(info(core), "MonitorStatus");
    CHECK(yyjson_mut_is_true(GET(status, "AlertFlag")) && yyjson_mut_is_true(GET(status, "AlertSent")));
    yyjson_mut_val *before = saved_root(core);
    (void)nm_monitor_alert(core, "processorResetAlerts", ids, "wrong-agent");
    CHECK(yyjson_mut_equals(nm_monitor_root(core), before));
    CHECK(nm_monitor_alert(core, "processorResetAlerts", ids, app));
    status = GET(info(core), "MonitorStatus");
    CHECK(yyjson_mut_is_false(GET(status, "AlertFlag")) && yyjson_mut_is_false(GET(status, "AlertSent")));
    CHECK(integer_is(GET(status, "DownCount"), 0));
    CHECK(yyjson_mut_is_true(GET(info(core), "IsDirtyDownCount")));
    CHECK(yyjson_mut_is_null(GET(info(core), "SiteHash")));
    CHECK(nm_monitor_probe(core, host(core), false, 0, "timeout", "down", when, 2));
    status = GET(info(core), "MonitorStatus");
    CHECK(integer_is(GET(status, "DownCount"), 0));
    CHECK(yyjson_mut_is_false(GET(info(core), "IsDirtyDownCount")));
    CHECK(nm_monitor_probe(core, host(core), false, 0, "timeout", "down", when, 3));
    status = GET(info(core), "MonitorStatus");
    CHECK(integer_is(GET(status, "DownCount"), 1));
    CHECK(nm_monitor_probe(core, host(core), true, 4, "ok", "alive", when, 4));
    status = GET(info(core), "MonitorStatus");
    CHECK(integer_is(GET(status, "DownCount"), 0));
    CHECK(!nm_monitor_alert(core, "unknown-operation", ids, app));
    CHECK(!nm_monitor_alert(core, "processorAlertFlag", ROOT(parse("[\"7\"]")), app));
    return true;
}

static bool test_alerts_mixed_missing_and_malformed_ids(void)
{
    nm_monitor_core *live = configured_core();
    CHECK(nm_monitor_probe(live, host(live), false, 0, "timeout", "down", when, 1));
    set_copy(live, info(live), "SiteHash", ROOT(parse("\"old-hash\"")));
    yyjson_mut_val *original = saved_root(live);
    nm_monitor_core *candidate = clone_core(live);
    yyjson_mut_val *mixed = ROOT(parse("[999,7,1000]"));
    yyjson_mut_val *status = GET(info(candidate), "MonitorStatus");
    /* .NET reports missing IDs per item, but still changes every valid host.
     * The handler's per-item logs/response list are outside this core-only test. */
    CHECK(nm_monitor_alert(candidate, "processorAlertFlag", mixed, app));
    status = GET(info(candidate), "MonitorStatus");
    CHECK(yyjson_mut_is_true(GET(status, "AlertFlag")));
    CHECK(nm_monitor_alert(candidate, "processorAlertSent", mixed, app));
    status = GET(info(candidate), "MonitorStatus");
    CHECK(yyjson_mut_is_true(GET(status, "AlertSent")));
    CHECK(nm_monitor_alert(candidate, "processorResetAlerts", mixed, app));
    status = GET(info(candidate), "MonitorStatus");
    CHECK(yyjson_mut_is_false(GET(status, "AlertFlag")));
    CHECK(yyjson_mut_is_false(GET(status, "AlertSent")));
    CHECK(integer_is(GET(status, "DownCount"), 0));
    CHECK(yyjson_mut_is_true(GET(info(candidate), "IsDirtyDownCount")));
    CHECK(yyjson_mut_is_null(GET(info(candidate), "SiteHash")));
    CHECK(yyjson_mut_equals(nm_monitor_root(live), original));
    const char *operations[] = {"processorAlertFlag", "processorAlertSent", "processorResetAlerts"};
    const char *invalid[] = {"[7,\"999\"]", "[7,null]", "[7,true]", "[7,2147483648]", "[7,1.0]"};
    for (size_t op = 0; op < COUNT(operations); op++) {
        for (size_t i = 0; i < COUNT(invalid); i++) {
            nm_monitor_core *rejected = clone_core(live);
            CHECK(!nm_monitor_alert(rejected, operations[op], ROOT(parse(invalid[i])), app));
            /* List<int> deserialization fails before .NET invokes the handler. */
            CHECK(yyjson_mut_equals(nm_monitor_root(rejected), original));
            CHECK(yyjson_mut_equals(nm_monitor_root(live), original));
        }
    }
    return true;
}

static bool test_reset_and_total_reset(void)
{
    nm_monitor_core *core = configured_core();
    CHECK(nm_monitor_probe(core, host(core), true, 17, "ok", "alive", when, 1));
    CHECK(nm_monitor_alert(core, "processorAlertFlag", ROOT(parse("[7]")), app));
    set_copy(core, nm_monitor_data(core), "SwapMonitorPingInfos", ROOT(parse("[{\"ID\":7,\"AppID\":\"parity-agent\"}]")));
    CHECK(nm_monitor_init(core, ROOT(parse("{\"Reset\":true,\"PingParams\":{\"Timeout\":1234}}")), app, 16, when));
    CHECK(yyjson_mut_arr_size(nm_monitor_hosts(core)) == 1);
    CHECK(yyjson_mut_arr_size(queue(core, "PingInfos")) == 0);
    CHECK(uint_is(GET(nm_monitor_data(core), "PiIDKey"), 1));
    const char *zeros[] = {"PacketsSent", "PacketsRecieved", "PacketsLost", "PacketsLostPercentage",
        "RoundTripTimeAverage", "RoundTripTimeMaximum", "RoundTripTimeTotal"};
    for (size_t i = 0; i < COUNT(zeros); i++) CHECK(yyjson_mut_get_num(GET(info(core), zeros[i])) == 0);
    /* Init calls ZeroMonitorPingInfos before SetVars(new PingParams). */
    EXPECT_CASE(integer_is(GET(info(core), "RoundTripTimeMinimum"), 1000), "reset uses old PingParams.Timeout");
    CHECK(integer_is(GET(GET(nm_monitor_root(core), "PingParams"), "Timeout"), 1234));
    CHECK(yyjson_mut_is_true(GET(GET(info(core), "MonitorStatus"), "AlertFlag")));
    CHECK(yyjson_mut_arr_size(queue(core, "SwapMonitorPingInfos")) == 1);
    CHECK(nm_monitor_init(core, ROOT(parse("{\"TotalReset\":true}")), app, 16, when));
    CHECK(yyjson_mut_arr_size(nm_monitor_hosts(core)) == 0);
    const char *empty[] = {"MonitorPingInfos", "PingInfos", "RemoveMonitorPingInfoIDs"};
    for (size_t i = 0; i < COUNT(empty); i++) CHECK(yyjson_mut_arr_size(queue(core, empty[i])) == 0);
    CHECK(uint_is(GET(nm_monitor_data(core), "PiIDKey"), 1));
    return true;
}

static bool test_dotnet_fill_defaults(void)
{
    nm_monitor_core *core = configured_core();
    /* MonitorPingInfo's own initializer is 9999, independent of PingParams. */
    EXPECT_CASE(integer_is(GET(info(core), "RoundTripTimeMinimum"), 9999), "fresh RTT minimum");
    CHECK(update(core, "[{\"ID\":7,\"Address\":\"example.test\",\"Enabled\":true,"
        "\"Timeout\":-1,\"SkipCycles\":5}]"));
    EXPECT_CASE(integer_is(GET(info(core), "Timeout"), -1), "negative nonzero timeout is preserved");
    CHECK(update(core, "[{\"ID\":7,\"Address\":\"example.test\"}]"));
    /* JSON UpdateMonitorIP is a complete CLR object, not a PATCH document. */
    EXPECT_CASE(yyjson_mut_is_false(GET(info(core), "Enabled")), "omitted Enabled defaults false");
    EXPECT_CASE(yyjson_mut_is_null(GET(info(core), "SkipCycles")), "omitted nullable SkipCycles clears value");
    EXPECT_CASE(integer_is(GET(info(core), "Port"), 0), "omitted Port defaults zero");
    return true;
}

static bool test_invalid_host_numeric_fields(void)
{
    const struct { const char *key; const char *token; } invalid[] = {
        {"ID", "2147483648"}, {"ID", "\"7\""}, {"ID", "7.0"},
        {"Port", "-1"}, {"Port", "65536"}, {"Port", "null"}, {"Port", "\"443\""},
        {"Timeout", "2147483648"}, {"Timeout", "null"}, {"Timeout", "1.0"},
        {"SkipCycles", "2147483648"}, {"SkipCycles", "true"}, {"SkipCycles", "\"2\""}
    };
    nm_monitor_core *live = configured_core();
    yyjson_mut_val *original = saved_root(live);
    for (size_t i = 0; i < COUNT(invalid); i++) {
        nm_monitor_core *candidate = clone_core(live);
        yyjson_mut_doc *changes = parse("[{\"ID\":7,\"Address\":\"example.test\",\"Enabled\":true}]");
        set(changes, yyjson_mut_arr_get_first(ROOT(changes)), invalid[i].key,
            yyjson_mut_val_mut_copy(changes, ROOT(parse(invalid[i].token))));
        bool accepted = nm_monitor_updates(candidate, ROOT(changes), app, 16, when);
        char name[128];
        snprintf(name, sizeof(name), "%s=%s", invalid[i].key, invalid[i].token);
        EXPECT_CASE(!accepted, name);
        CHECK(yyjson_mut_equals(nm_monitor_root(live), original));
    }
    return true;
}

static bool test_total_reset_live_key_adaptation(void)
{
    nm_monitor_core *core = configured_core();
    set_uint(core, nm_monitor_data(core), "PiIDKey", 42);
    set_copy(core, nm_monitor_data(core), "SwapMonitorPingInfos",
        ROOT(fixture("swap-monitor-ping-info.json")));
    CHECK(nm_monitor_init(core, ROOT(parse("{\"TotalReset\":true,\"PingParams\":{\"Timeout\":1000}}")), app, 16, when));
    /* Approved adaptation: agree with reset persistent state immediately. */
    CHECK(uint_is(GET(nm_monitor_data(core), "PiIDKey"), 1));
    CHECK(yyjson_mut_arr_size(queue(core, "SwapMonitorPingInfos")) == 0);
    return true;
}

struct save_context {
    nm_monitor_core *live;
    yyjson_mut_val *original;
    yyjson_mut_val *expected;
    yyjson_mut_val *persisted;
    unsigned calls;
    bool succeed;
    bool observed_live_unchanged;
    bool observed_candidate;
};
static bool save_snapshot(void *opaque, yyjson_mut_val *snapshot)
{
    struct save_context *context = opaque;
    context->calls++;
    context->observed_live_unchanged = yyjson_mut_equals(nm_monitor_root(context->live), context->original);
    context->observed_candidate = yyjson_mut_equals(snapshot, context->expected);
    if (context->succeed) {
        yyjson_mut_doc *copy = own(yyjson_mut_doc_new(NULL));
        yyjson_mut_doc_set_root(copy, yyjson_mut_val_mut_copy(copy, snapshot));
        context->persisted = ROOT(copy);
    }
    return context->succeed;
}

static bool test_commit_failure_atomicity(void)
{
    nm_monitor_core *live = configured_core();
    set_copy(live, nm_monitor_data(live), "PingInfos", ROOT(fixture("ping-info.json")));
    nm_monitor_core *candidate = clone_core(live);
    yyjson_mut_doc *original_doc = live->doc;
    yyjson_mut_val *original = saved_root(live);
    CHECK(nm_monitor_ack(candidate, ROOT(parse(
        "{\"RemovePingInfos\":[{\"ID\":18446744073709551615,\"MonitorPingInfoID\":7}]}"))));
    CHECK(nm_monitor_user_event(candidate, ROOT(parse("{\"IsHostsAdded\":true}"))));
    yyjson_mut_doc *candidate_doc = candidate->doc;
    struct save_context context = {.live = live, .original = original,
        .expected = saved_root(candidate), .succeed = false};
    CHECK(!nm_monitor_commit(live, candidate, save_snapshot, &context));
    CHECK(context.calls == 1 && context.observed_candidate && context.observed_live_unchanged);
    CHECK(live->doc == original_doc && candidate->doc == candidate_doc);
    CHECK(yyjson_mut_equals(nm_monitor_root(live), original));
    CHECK(contains_id(queue(live, "PingInfos"), UINT64_MAX));
    CHECK(yyjson_mut_equals(nm_monitor_root(candidate), context.expected));
    CHECK(!nm_monitor_commit(live, candidate, NULL, NULL));
    CHECK(live->doc == original_doc && candidate->doc == candidate_doc);
    context.succeed = true;
    CHECK(nm_monitor_commit(live, candidate, save_snapshot, &context));
    CHECK(context.calls == 2 && context.observed_live_unchanged && context.observed_candidate);
    CHECK(candidate->doc == NULL && live->doc == candidate_doc);
    CHECK(!contains_id(queue(live, "PingInfos"), UINT64_MAX));
    CHECK(yyjson_mut_equals(nm_monitor_root(live), context.persisted));
    nm_monitor_core *reopened = new_core();
    CHECK(nm_monitor_open(reopened, context.persisted, NULL, NULL));
    CHECK(yyjson_mut_equals(nm_monitor_root(live), nm_monitor_root(reopened)));
    nm_monitor_core *invalid = clone_core(live);
    set_uint(invalid, nm_monitor_data(invalid), "PiIDKey", UINT64_C(4294967296));
    yyjson_mut_val *committed = saved_root(live);
    CHECK(!nm_monitor_commit(live, invalid, save_snapshot, &context));
    CHECK(context.calls == 2); /* validation must run before durable save */
    CHECK(yyjson_mut_equals(nm_monitor_root(live), committed));
    return true;
}

static bool test_failed_operations_do_not_mutate_live(void)
{
    nm_monitor_core *live = configured_core();
    yyjson_mut_val *original = saved_root(live);
    nm_monitor_core *candidate = clone_core(live);
    CHECK(!update(candidate, "[{\"ID\":7,\"Address\":\"partial-change\"},{\"ID\":2147483648}]"));
    CHECK(yyjson_mut_equals(nm_monitor_root(live), original));
    candidate = clone_core(live);
    CHECK(!nm_monitor_init(candidate, ROOT(parse("{\"TotalReset\":true,\"MonitorIPs\":42}")), app, 16, when));
    CHECK(yyjson_mut_equals(nm_monitor_root(live), original));
    candidate = clone_core(live);
    CHECK(!nm_monitor_updates(candidate, ROOT(parse("[{\"ID\":8,\"Address\":\"extra.test\"}]")), app, 1, when));
    CHECK(yyjson_mut_equals(nm_monitor_root(live), original));
    candidate = clone_core(live);
    CHECK(!nm_monitor_alert(candidate, "processorAlertFlag", ROOT(parse("[7,\"malformed\"]")), app));
    CHECK(yyjson_mut_equals(nm_monitor_root(live), original));
    candidate = clone_core(live);
    CHECK(!nm_monitor_user_event(candidate, ROOT(parse("{\"IsLoggedInWebsite\":true,\"IsHostsAdded\":1}"))));
    CHECK(yyjson_mut_equals(nm_monitor_root(live), original));
    /* Valid first ack followed by invalid second collection: discard whole candidate. */
    CHECK(nm_monitor_probe(live, host(live), true, 1, "ok", "alive", when, 1));
    original = saved_root(live);
    candidate = clone_core(live);
    CHECK(!nm_monitor_ack(candidate, ROOT(parse("{\"RemovePingInfos\":[{\"ID\":1}],\"RemoveMonitorPingInfoIDs\":[\"7\"]}"))));
    CHECK(yyjson_mut_equals(nm_monitor_root(live), original));
    return true;
}

static bool test_sequence_collision_preserves_pending(void)
{
    nm_monitor_core *live = configured_core();
    CHECK(nm_monitor_probe(live, host(live), true, 9, "ok", "alive", when, 1));
    set_uint(live, nm_monitor_data(live), "PiIDKey", 1);
    yyjson_mut_val *original = saved_root(live);
    nm_monitor_core *candidate = clone_core(live);
    CHECK(!nm_monitor_probe(candidate, host(candidate), true, 99, "ok", "new", when, 2));
    CHECK(yyjson_mut_equals(nm_monitor_root(live), original));
    CHECK(yyjson_mut_equals(queue(candidate, "PingInfos"), queue(live, "PingInfos")));
    return true;
}

static bool test_legacy_import_and_invalid_sequence(void)
{
    yyjson_mut_doc *data = parse("{\"PiIDKey\":4294967295,\"Extra\":{\"keep\":true}}");
    yyjson_mut_doc *pings = fixture("ping-info.json");
    set(data, ROOT(data), "PingInfos", yyjson_mut_val_mut_copy(data, ROOT(pings)));
    nm_monitor_core *core = new_core();
    CHECK(nm_monitor_open(core, NULL, ROOT(data), ROOT(parse("[]"))));
    CHECK(yyjson_mut_equals(queue(core, "PingInfos"), ROOT(pings)));
    CHECK(yyjson_mut_equals(GET(nm_monitor_data(core), "Extra"), GET(ROOT(data), "Extra")));
    const char *bad[] = {"-1", "4294967296", "1.0", "1e0", "\"1\"", "null", "true", "[]", "{}"};
    for (size_t i = 0; i < COUNT(bad); i++) {
        nm_monitor_core *candidate = clone_core(core);
        set_copy(candidate, nm_monitor_data(candidate), "PiIDKey", ROOT(parse(bad[i])));
        nm_monitor_core *loaded = new_core();
        CHECK(!nm_monitor_open(loaded, nm_monitor_root(candidate), NULL, NULL));
        CHECK(loaded->doc == NULL);
    }
    return true;
}

static bool test_retained_host_churn_bound(void)
{
    nm_monitor_core *live = configured_core();
    CHECK(nm_monitor_probe(live, host(live), true, 5, "ok", "alive", when, 1));
    yyjson_mut_val *add = ROOT(parse("[{\"ID\":7,\"Address\":\"example.test\",\"Enabled\":true}]"));
    yyjson_mut_val *del = ROOT(parse("[{\"ID\":7,\"Delete\":true}]"));
    yyjson_mut_val *pending = GET(GET(saved_root(live), "ProcessorData"), "PingInfos");
    /* Repeated same-ID churn during an outage must never grow metadata queues. */
    for (unsigned cycle = 0; cycle < 64; cycle++) {
        CHECK(nm_monitor_updates(live, add, app, 1, when));
        CHECK(nm_monitor_updates(live, del, app, 1, when));
        CHECK(nm_monitor_updates(live, del, app, 1, when));
        CHECK(yyjson_mut_arr_size(queue(live, "MonitorPingInfos")) == 1);
        CHECK(yyjson_mut_arr_size(queue(live, "RemoveMonitorPingInfoIDs")) == 1);
        CHECK(yyjson_mut_arr_size(queue(live, "SwapMonitorPingInfos")) == 0);
        CHECK(yyjson_mut_arr_size(nm_monitor_hosts(live)) == 0);
        CHECK(yyjson_mut_equals(queue(live, "PingInfos"), pending));
    }
    yyjson_mut_val *original = saved_root(live);
    nm_monitor_core *candidate = clone_core(live);
    yyjson_mut_val *new_host = ROOT(parse("[{\"ID\":8,\"Address\":\"new.test\",\"Enabled\":true}]"));
    CHECK(!nm_monitor_updates(candidate, new_host, app, 1, when));
    CHECK(yyjson_mut_equals(nm_monitor_root(live), original));
    candidate = clone_core(live);
    CHECK(nm_monitor_ack(candidate, ROOT(parse("{\"RemoveMonitorPingInfoIDs\":[7]}"))));
    CHECK(yyjson_mut_arr_size(queue(candidate, "PingInfos")) == 0);
    CHECK(yyjson_mut_arr_size(queue(candidate, "MonitorPingInfos")) == 0);
    CHECK(yyjson_mut_arr_size(queue(candidate, "RemoveMonitorPingInfoIDs")) == 0);
    struct save_context context = {.live = live, .original = original,
        .expected = saved_root(candidate), .succeed = false};
    CHECK(!nm_monitor_commit(live, candidate, save_snapshot, &context));
    CHECK(context.calls == 1 && context.observed_live_unchanged && context.observed_candidate);
    CHECK(yyjson_mut_equals(nm_monitor_root(live), original));
    context.succeed = true;
    CHECK(nm_monitor_commit(live, candidate, save_snapshot, &context));
    CHECK(context.calls == 2 && candidate->doc == NULL);
    CHECK(nm_monitor_updates(live, new_host, app, 1, when));
    CHECK(yyjson_mut_arr_size(queue(live, "MonitorPingInfos")) == 1);
    CHECK(integer_is(GET(info(live), "MonitorIPID"), 8));
    return true;
}

static bool test_pending_metadata_queue_bounds(void)
{
    /* No parent-integrity checks here: restoration is deliberately numeric-only.
     * An update must still refuse each over-budget metadata queue. */
    const char *keys[] = {"RemoveMonitorPingInfoIDs", "SwapMonitorPingInfos"};
    const char *values[] = {"[8,9]", "[{\"ID\":8,\"AppID\":\"a\"},{\"ID\":9,\"AppID\":\"a\"}]"};
    for (size_t i = 0; i < COUNT(keys); i++) {
        nm_monitor_core *live = configured_core();
        set_copy(live, nm_monitor_data(live), keys[i], ROOT(parse(values[i])));
        yyjson_mut_val *original = saved_root(live);
        nm_monitor_core *candidate = clone_core(live);
        CHECK(!nm_monitor_updates(candidate, ROOT(parse("[]")), app, 1, when));
        CHECK(yyjson_mut_equals(nm_monitor_root(live), original));
        candidate = clone_core(live);
        CHECK(nm_monitor_updates(candidate, ROOT(parse("[]")), app, 2, when));
        CHECK(yyjson_mut_arr_size(queue(candidate, keys[i])) == 2);
    }
    return true;
}

static bool test_dataset_delete_ack_ownership(void)
{
    nm_monitor_core *core = configured_core();
    CHECK(nm_monitor_probe(core, host(core), true, 7, "ok", "alive", when, 1));
    CHECK(update(core, "[{\"ID\":8,\"Address\":\"retired.test\",\"Enabled\":true}]"));
    CHECK(nm_monitor_probe(core, yyjson_mut_arr_get(nm_monitor_hosts(core), 1), false, 0,
        "timeout", "down", when, 2));
    CHECK(update(core, "[{\"ID\":8,\"Delete\":true}]"));
    yyjson_mut_val *before = saved_root(core);
    CHECK(nm_monitor_ack(core, ROOT(parse("{\"RemoveMonitorPingInfoIDs\":[999]}"))));
    CHECK(yyjson_mut_equals(nm_monitor_root(core), before));
    /* Even an application ACK must not delete data of a still-owned host. */
    CHECK(nm_monitor_ack(core, ROOT(parse("{\"RemoveMonitorPingInfoIDs\":[7]}"))));
    CHECK(yyjson_mut_equals(nm_monitor_root(core), before));
    CHECK(nm_monitor_ack(core, ROOT(parse("{\"RemoveMonitorPingInfoIDs\":[8]}"))));
    CHECK(yyjson_mut_arr_size(queue(core, "MonitorPingInfos")) == 1);
    CHECK(yyjson_mut_arr_size(queue(core, "PingInfos")) == 1);
    CHECK(yyjson_mut_arr_size(queue(core, "RemoveMonitorPingInfoIDs")) == 0);
    CHECK(nm_monitor_info(core, 8) == NULL);
    CHECK(yyjson_mut_equals(info(core), yyjson_mut_arr_get_first(GET(GET(before, "ProcessorData"), "MonitorPingInfos"))));
    CHECK(yyjson_mut_equals(yyjson_mut_arr_get_first(queue(core, "PingInfos")),
        yyjson_mut_arr_get_first(GET(GET(before, "ProcessorData"), "PingInfos"))));
    CHECK(nm_monitor_ack(core, ROOT(parse("{\"RemoveMonitorPingInfoIDs\":[8,8]}"))));
    CHECK(yyjson_mut_arr_size(queue(core, "PingInfos")) == 1);
    return true;
}

int main(int argc, char **argv)
{
    if (argc > 3) { fprintf(stderr, "Usage: %s [fixture-directory] [test-filter]\n", argv[0]); return 2; }
    if (argc > 1) fixture_dir = argv[1];
    const struct { const char *name; bool (*run)(void); } tests[] = {
        {"fixture_exact_ack", test_fixture_exact_ack},
        {"oracle_ping_numeric_validation", test_oracle_ping_numeric_validation},
        {"oracle_ack_numeric_validation", test_oracle_ack_numeric_validation},
        {"integer_helpers", test_integer_helpers},
        {"piid_u32_rollover", test_piid_u32_rollover},
        {"counter_rollover_and_statistics", test_counter_rollover_and_statistics},
        {"metadata_and_disabled_preservation", test_metadata_and_disabled_preservation},
        {"swap_delete_queues", test_swap_delete_queues},
        {"swap_ack_dotnet_id_comparer", test_swap_ack_dotnet_id_comparer},
        {"alerts_reset_and_dirty_downcount", test_alerts_reset_and_dirty_downcount},
        {"alerts_mixed_missing_and_malformed_ids", test_alerts_mixed_missing_and_malformed_ids},
        {"reset_and_total_reset", test_reset_and_total_reset},
        {"dotnet_fill_defaults", test_dotnet_fill_defaults},
        {"invalid_host_numeric_fields", test_invalid_host_numeric_fields},
        {"total_reset_live_key_adaptation", test_total_reset_live_key_adaptation},
        {"commit_failure_atomicity", test_commit_failure_atomicity},
        {"failed_operations_do_not_mutate_live", test_failed_operations_do_not_mutate_live},
        {"sequence_collision_preserves_pending", test_sequence_collision_preserves_pending},
        {"legacy_import_and_invalid_sequence", test_legacy_import_and_invalid_sequence},
        {"retained_host_churn_bound", test_retained_host_churn_bound},
        {"pending_metadata_queue_bounds", test_pending_metadata_queue_bounds},
        {"dataset_delete_ack_ownership", test_dataset_delete_ack_ownership}
    };
    unsigned ran = 0, failed = 0;
    for (size_t i = 0; i < COUNT(tests); i++) {
        if (argc == 3 && !strstr(tests[i].name, argv[2])) continue;
        unsigned before = expectation_failures;
        bool passed = tests[i].run();
        passed = passed && before == expectation_failures;
        printf("%s %s\n", passed ? "PASS" : "FAIL", tests[i].name);
        cleanup();
        ran++;
        if (!passed) failed++;
    }
    printf("%u tests, %u failed\n", ran, failed);
    return ran == 0 ? 2 : failed ? 1 : 0;
}
