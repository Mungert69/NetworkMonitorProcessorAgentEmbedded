#include "monitor_schedule.h"

#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Source-derived parity fixtures:
 * NetworkMonitorLib/Objects/Connection/FilterStrategy/
 *   ConfigurableEndpointFilterStrategy.cs:33-120,143-204
 *   FilterStrategyConfig.cs:72-86,118-172
 * NetworkMonitorLib/Objects/Connection/NetConnectCollection.cs:93-100
 * Daily tests inject hash results, not a substitute .NET string hash algorithm.
 */
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
static unsigned checks;

static yyjson_mut_doc *parse(const char *text)
{
    yyjson_doc *src = yyjson_read(text, strlen(text), 0);
    CHECK(src);
    yyjson_mut_doc *d = yyjson_doc_mut_copy(src, NULL);
    yyjson_doc_free(src);
    CHECK(d);
    return d;
}

struct fixture { yyjson_mut_doc *d; yyjson_mut_val *state, *config, *monitors; };
static struct fixture fixture(const char *strategies, const char *monitors)
{
    struct fixture f = {0};
    f.d = yyjson_mut_doc_new(NULL); CHECK(f.d);
    f.state = yyjson_mut_obj(f.d); CHECK(f.state);
    yyjson_mut_doc_set_root(f.d, f.state);
    yyjson_mut_doc *c = parse(strategies), *m = parse(monitors);
    f.config = yyjson_mut_val_mut_copy(f.d, yyjson_mut_doc_get_root(c));
    f.monitors = yyjson_mut_val_mut_copy(f.d, yyjson_mut_doc_get_root(m));
    yyjson_mut_doc_free(c); yyjson_mut_doc_free(m);
    CHECK(f.config && f.monitors);
    return f;
}
static void prepare(struct fixture *f)
{ CHECK(nm_monitor_schedule_prepare(f->d, f->state, f->config, f->monitors, 0)); }
static bool include_at(struct fixture *f, size_t index, int64_t utc, double random, int32_t hash)
{
    bool included = true;
    CHECK(nm_monitor_schedule_include(f->d, f->state, f->config,
        yyjson_mut_arr_get(f->monitors, index), utc, random, hash, &included));
    checks++;
    return included;
}
static bool include(struct fixture *f, size_t index)
{ return include_at(f, index, 0, 0.5, 0); }
static void set_int(struct fixture *f, yyjson_mut_val *obj, const char *key, int64_t n)
{ CHECK(yyjson_mut_obj_put(obj, yyjson_mut_strcpy(f->d, key), yyjson_mut_sint(f->d, n))); }
static yyjson_mut_val *counter(struct fixture *f, size_t i)
{ return yyjson_mut_arr_get(yyjson_mut_obj_get(f->state, "Counters"), i); }
static int64_t number(yyjson_mut_val *obj, const char *key)
{ return yyjson_mut_get_sint(yyjson_mut_obj_get(obj, key)); }
static void free_fixture(struct fixture *f) { yyjson_mut_doc_free(f->d); }

static void host_phases(void)
{
    struct fixture f = fixture("{\"FilterStrategies\":[{\"StrategyName\":\"smtp\",\"FireInterval\":{\"Every\":100}}]}",
        "[{\"MonitorIPID\":42,\"EndPointType\":\"smtp\",\"SkipCycles\":2,\"Enabled\":true},"
        "{\"MonitorIPID\":43,\"EndPointType\":\"smtp\",\"SkipCycles\":2,\"Enabled\":true},"
        "{\"MonitorIPID\":44,\"EndPointType\":\"smtp\",\"SkipCycles\":2,\"Enabled\":true}]");
    for (int cycle = 0; cycle < 6; cycle++) {
        prepare(&f);
        for (int host = 0; host < 3; host++) CHECK(include(&f, (size_t)host) == (host == cycle % 3));
    }
    /* Host overrides count towards TotalEndpoints but never advance counters. */
    CHECK(number(counter(&f, 0), "TotalEndpoints") == 3);
    CHECK(number(counter(&f, 0), "Counter") == 0);
    yyjson_mut_val *h = yyjson_mut_arr_get(f.monitors, 0);
    set_int(&f, h, "SkipCycles", 3);
    CHECK(!include(&f, 0)); CHECK(!include(&f, 0)); CHECK(include(&f, 0));
    set_int(&f, h, "SkipCycles", 1);
    CHECK(include(&f, 0)); CHECK(!include(&f, 0));
    set_int(&f, h, "SkipCycles", 0);
    CHECK(include(&f, 0)); CHECK(include(&f, 0));
    set_int(&f, h, "SkipCycles", -1); CHECK(include(&f, 0));
    /* <=0 does not discard the previous positive skip state. */
    set_int(&f, h, "SkipCycles", 1); CHECK(include(&f, 0));
    CHECK(yyjson_mut_obj_put(h, yyjson_mut_strcpy(f.d, "SkipCycles"), yyjson_mut_null(f.d)));
    CHECK(include(&f, 0)); /* null resumes the still-unadvanced SMTP counter. */
    CHECK(!include(&f, 0));
    set_int(&f, h, "SkipCycles", 1); CHECK(!include(&f, 0)); /* positive state retained through null */
    free_fixture(&f);

    f = fixture("{}", "[{\"MonitorIPID\":-1,\"SkipCycles\":2,\"Enabled\":true},"
        "{\"MonitorIPID\":-2147483648,\"SkipCycles\":2147483647,\"Enabled\":true}]");
    prepare(&f);
    CHECK(include(&f, 0)); /* uint(-1) % 3 == 0, not signed remainder. */
    CHECK(include(&f, 1)); /* uint(INT_MIN) % 2^31 == 0. */
    CHECK(!include(&f, 0)); CHECK(!include(&f, 1));
    free_fixture(&f);
}

static void counters_and_matching(void)
{
    struct fixture f = fixture("{\"FilterStrategies\":[{\"StrategyName\":\"http\",\"FireInterval\":{\"Every\":2}}]}",
        "[{\"EndPointType\":\"HTTPhtml\",\"Enabled\":true},{\"EndPointType\":\"https\",\"Enabled\":true},"
        "{\"EndPointType\":\"dns\",\"Enabled\":true}]");
    prepare(&f); CHECK(include(&f, 0)); CHECK(!include(&f, 1)); CHECK(include(&f, 2));
    prepare(&f); CHECK(!include(&f, 0)); CHECK(include(&f, 1));
    free_fixture(&f);

    f = fixture("{\"FilterStrategies\":[{\"StrategyName\":\"custom\",\"EndpointTypeContains\":[null,\" \",\"HTTP\"],"
        "\"FireInterval\":{\"Every\":3,\"Offset\":-1}}]}",
        "[{\"EndPointType\":\"http\",\"Enabled\":true}]");
    prepare(&f); CHECK(!include(&f, 0)); CHECK(include(&f, 0)); CHECK(!include(&f, 0));
    free_fixture(&f);

    f = fixture("{\"FilterStrategies\":[{\"StrategyName\":\"http\",\"EndpointTypeContains\":[\" \"],\"FireInterval\":{\"Every\":100}}]}",
        "[{\"EndPointType\":\"http\",\"Enabled\":true}]");
    prepare(&f); CHECK(include(&f, 0)); CHECK(include(&f, 0));
    CHECK(number(counter(&f, 0), "Counter") == 0); /* Nonempty blank pattern list does not fall back. */
    free_fixture(&f);

    f = fixture("{\"FilterStrategies\":[{\"StrategyName\":\"http\",\"FireInterval\":{\"Every\":2}}]}",
        "[{\"EndPointType\":\"http\",\"Enabled\":false},{\"EndPointType\":\"http\",\"Enabled\":true}]");
    prepare(&f); CHECK(!include(&f, 0)); CHECK(!include(&f, 1));
    CHECK(number(counter(&f, 0), "Offset") == 1);
    prepare(&f); CHECK(!include(&f, 0)); CHECK(include(&f, 1));
    free_fixture(&f);

    f = fixture("{\"FilterStrategies\":[{\"StrategyName\":\"http\",\"FireInterval\":{\"Every\":2,\"Offset\":1}},"
        "{\"StrategyName\":\"second\",\"EndpointTypeContains\":[\"http\"],\"FireInterval\":{\"Every\":3}}]}",
        "[{\"EndPointType\":\"http\",\"Enabled\":true}]");
    prepare(&f); CHECK(!include(&f, 0)); CHECK(number(counter(&f, 1), "Offset") == 0);
    CHECK(include(&f, 0)); CHECK(number(counter(&f, 1), "Offset") == 1);
    free_fixture(&f);
}

static void defaults_aliases_random(void)
{
    const char *configs[] = {"{}", "{\"FilterStrategies\":null}", "{\"FilterStrategies\":[]}",
        "{\"FilterStrategies\":[{\"StrategyName\":\"http\"}]}",
        "{\"FilterStrategies\":[{\"StrategyName\":\"http\",\"FireInterval\":null}]}",
        "{\"FilterStrategies\":[{\"StrategyName\":\"http\",\"FireInterval\":{\"Every\":0,\"Offset\":-3}}]}",
        "{\"FilterStrategies\":[{\"StrategyName\":\"http\",\"FireInterval\":{\"Mode\":\"unknown\"}}]}"};
    for (size_t i = 0; i < sizeof(configs) / sizeof(*configs); i++) {
        struct fixture f = fixture(configs[i], "[{\"EndPointType\":\"http\",\"Enabled\":true},{}]");
        prepare(&f); CHECK(include(&f, 0)); CHECK(include(&f, 0)); CHECK(!include(&f, 1)); free_fixture(&f);
    }
    const char *aliases[] = {
        "{\"FilterStrategies\":[{\"StrategyName\":\"http\",\"FilterSkip\":2,\"FireInterval\":{\"Every\":1}}]}",
        "{\"FilterStrategies\":[{\"StrategyName\":\"http\",\"FireInterval\":{\"Every\":1},\"FilterSkip\":2}]}"};
    for (size_t i = 0; i < 2; i++) {
        struct fixture f = fixture(aliases[i], "[{\"EndPointType\":\"http\",\"Enabled\":true}]");
        prepare(&f); CHECK(include(&f, 0)); CHECK(include(&f, 0) == (i == 0)); free_fixture(&f);
    }
    struct fixture f = fixture("{\"FilterStrategies\":[{\"StrategyName\":\"http\",\"FireInterval\":{\"Mode\":\" RANDOMIZED-COUNTER \"}}]}",
        "[{\"EndPointType\":\"http\",\"Enabled\":true}]");
    prepare(&f); CHECK(include_at(&f, 0, 0, 0.5, 0)); CHECK(!include_at(&f, 0, 0, 0.50001, 0)); free_fixture(&f);
    f = fixture("{\"FilterStrategies\":[{\"StrategyName\":\"http\",\"FireInterval\":{\"Mode\":\"randomized-counter\"},\"Randomization\":{\"Probability\":-2}}]}",
        "[{\"EndPointType\":\"http\",\"Enabled\":true}]");
    prepare(&f); CHECK(include_at(&f, 0, 0, 0, 0)); CHECK(!include_at(&f, 0, 0, 0.1, 0)); free_fixture(&f);
    f = fixture("{\"FilterStrategies\":[{\"StrategyName\":\"http\",\"EndpointTypeContains\":[],\"FireInterval\":{\"Mode\":\"randomized-counter\",\"Every\":-1},\"Randomization\":{\"Probability\":5}}]}",
        "[{\"EndPointType\":\"HTTP\",\"Enabled\":true}]");
    prepare(&f); CHECK(include_at(&f, 0, 0, 0.999999, 0)); CHECK(include_at(&f, 0, 0, 0.9, 0)); free_fixture(&f);
}

static void daily_and_persistence(void)
{
    struct fixture f = fixture("{\"FilterStrategies\":[{\"StrategyName\":\"http\",\"FireInterval\":{\"Mode\":\"daily-slot\"}}]}",
        "[{\"MonitorIPID\":7,\"EndPointType\":\"http\",\"Enabled\":true}]");
    prepare(&f);
    CHECK(!include_at(&f, 0, 3599, 0.5, -1));
    CHECK(include_at(&f, 0, 3600, 0.5, -1));
    CHECK(!include_at(&f, 0, 3601, 0.5, -1));
    CHECK(!include_at(&f, 0, 3600 - 86400, 0.5, -1)); /* Clock reversal. */
    char *snapshot = yyjson_mut_write(f.d, 0, NULL); CHECK(snapshot);
    yyjson_mut_doc *restored = parse(snapshot); free(snapshot);
    CHECK(!nm_monitor_schedule_prepare(restored, yyjson_mut_doc_get_root(restored), f.config, f.monitors, INT64_MAX));
    CHECK(nm_monitor_schedule_prepare(restored, yyjson_mut_doc_get_root(restored), f.config, f.monitors, 3600));
    bool run = true;
    CHECK(nm_monitor_schedule_include(restored, yyjson_mut_doc_get_root(restored), f.config,
        yyjson_mut_arr_get(f.monitors, 0), 3600, 0.5, 1, &run)); CHECK(!run);
    CHECK(nm_monitor_schedule_include(restored, yyjson_mut_doc_get_root(restored), f.config,
        yyjson_mut_arr_get(f.monitors, 0), 90000, 0.5, 1, &run)); CHECK(run);
    CHECK(!nm_monitor_schedule_include(f.d, f.state, f.config, yyjson_mut_arr_get(f.monitors, 0), 0, 0.5, INT32_MIN, &run));
    CHECK(!run);
    yyjson_mut_doc_free(restored); free_fixture(&f);

    /* Daily history belongs to a host, not to a particular matching strategy. */
    f = fixture("{\"FilterStrategies\":[{\"StrategyName\":\"a\",\"EndpointTypeContains\":[\"http\"],\"FireInterval\":{\"Mode\":\"daily-slot\",\"SlotsPerDay\":1}},"
        "{\"StrategyName\":\"b\",\"EndpointTypeContains\":[\"http\"],\"FireInterval\":{\"Mode\":\"daily-slot\",\"SlotsPerDay\":1}}]}",
        "[{\"MonitorIPID\":5,\"EndPointType\":\"http\",\"Enabled\":true}]");
    prepare(&f); CHECK(!include(&f, 0)); CHECK(yyjson_mut_obj_get(yyjson_mut_obj_get(f.state, "Daily"), "5"));
    free_fixture(&f);

    f = fixture("{\"FilterStrategies\":[{\"StrategyName\":\"http\",\"FireInterval\":{\"Mode\":\"daily-slot\",\"SlotsPerDay\":0}}]}",
        "[{\"MonitorIPID\":5,\"EndPointType\":\"http\",\"Enabled\":false}]");
    prepare(&f); CHECK(!include(&f, 0));
    yyjson_mut_val *h = yyjson_mut_arr_get(f.monitors, 0);
    CHECK(yyjson_mut_obj_put(h, yyjson_mut_strcpy(f.d, "Enabled"), yyjson_mut_true(f.d)));
    CHECK(!include(&f, 0)); /* Disabled evaluation consumed daily eligibility. */
    CHECK(include_at(&f, 0, 86400, 0.5, 0));
    free_fixture(&f);
}

static void state_reconciliation_and_overflow(void)
{
    struct fixture f = fixture("{\"FilterStrategies\":[{\"StrategyName\":\"http\",\"FireInterval\":{\"Every\":2147483647}}]}",
        "[{\"EndPointType\":\"http\",\"Enabled\":true}]");
    prepare(&f);
    yyjson_mut_val *c = counter(&f, 0);
    set_int(&f, c, "Counter", 2); set_int(&f, c, "TotalEndpoints", 3); set_int(&f, c, "Offset", 2147483646);
    CHECK(!include(&f, 0)); /* int32(2+2147483646) == -2147483648. */
    c = counter(&f, 0);
    CHECK(number(c, "Counter") == 0); CHECK(number(c, "Offset") == 0);
    set_int(&f, c, "Counter", 2); set_int(&f, c, "TotalEndpoints", 3);
    prepare(&f); c = counter(&f, 0); CHECK(number(c, "Counter") == 0); CHECK(number(c, "TotalEndpoints") == 1);
    free_fixture(&f);

    f = fixture("{}", "[{\"MonitorIPID\":43,\"SkipCycles\":2,\"Enabled\":true}]");
    prepare(&f); CHECK(!include(&f, 0));
    char *json = yyjson_mut_write(f.d, 0, NULL); CHECK(json);
    yyjson_mut_doc *saved = parse(json); free(json);
    CHECK(nm_monitor_schedule_prepare(saved, yyjson_mut_doc_get_root(saved), f.config, f.monitors, 0));
    bool run = false;
    CHECK(nm_monitor_schedule_include(saved, yyjson_mut_doc_get_root(saved), f.config,
        yyjson_mut_arr_get(f.monitors, 0), 0, 0.5, 0, &run)); CHECK(run);
    yyjson_mut_doc_free(saved);
    /* Strategy changes recreate all strategy-local state, like SetNetConnectConfig. */
    yyjson_mut_doc *changed = parse("{\"FilterStrategies\":[{\"StrategyName\":\"smtp\"}]}");
    CHECK(nm_monitor_schedule_prepare(f.d, f.state, yyjson_mut_doc_get_root(changed), f.monitors, 0));
    CHECK(yyjson_mut_obj_size(yyjson_mut_obj_get(f.state, "Hosts")) == 0);
    yyjson_mut_doc_free(changed); free_fixture(&f);
}

struct samples { const double *values; size_t count, used; };
static double next_sample(void *context)
{
    struct samples *s = context;
    CHECK(s->used < s->count);
    return s->values[s->used++];
}
static void independent_random_and_short_circuit(void)
{
    struct fixture f = fixture("{\"FilterStrategies\":["
        "{\"StrategyName\":\"a\",\"EndpointTypeContains\":[\"http\"],\"FireInterval\":{\"Mode\":\"randomized-counter\"}},"
        "{\"StrategyName\":\"b\",\"EndpointTypeContains\":[\"http\"],\"FireInterval\":{\"Mode\":\"randomized-counter\"}}]}",
        "[{\"EndPointType\":\"http\",\"Enabled\":true}]");
    prepare(&f);
    const double values[] = {0.25, 0.75, 0.75};
    struct samples s = {values, 3, 0}; bool run = true;
    CHECK(nm_monitor_schedule_include_with_random(f.d, f.state, f.config,
        yyjson_mut_arr_get(f.monitors, 0), 0, next_sample, &s, 0, &run));
    CHECK(!run && s.used == 2); /* First gate passes; distinct second draw rejects. */
    CHECK(nm_monitor_schedule_include_with_random(f.d, f.state, f.config,
        yyjson_mut_arr_get(f.monitors, 0), 0, next_sample, &s, 0, &run));
    CHECK(!run && s.used == 3); /* First gate rejects: no fourth RNG draw. */
    free_fixture(&f);

    f = fixture("{\"FilterStrategies\":[{\"StrategyName\":\"http\",\"FireInterval\":{\"Mode\":\"randomized-counter\",\"Every\":2,\"Offset\":1}}]}",
        "[{\"EndPointType\":\"http\",\"Enabled\":true}]");
    prepare(&f); s.used = 0;
    CHECK(nm_monitor_schedule_include_with_random(f.d, f.state, f.config,
        yyjson_mut_arr_get(f.monitors, 0), 0, next_sample, &s, 0, &run));
    CHECK(!run && s.used == 0); /* Counter exclusion consumes no RNG value. */
    CHECK(nm_monitor_schedule_include_with_random(f.d, f.state, f.config,
        yyjson_mut_arr_get(f.monitors, 0), 0, next_sample, &s, 0, &run));
    CHECK(run && s.used == 1); free_fixture(&f);

    f = fixture("{\"FilterStrategies\":["
        "{\"StrategyName\":\"http\",\"FireInterval\":{\"Every\":2,\"Offset\":1}},"
        "{\"StrategyName\":\"daily\",\"EndpointTypeContains\":[\"http\"],\"FireInterval\":{\"Mode\":\"daily-slot\"}}]}",
        "[{\"EndPointType\":\"http\",\"Enabled\":true}]");
    prepare(&f);
    CHECK(!include_at(&f, 0, 0, 0.5, INT32_MIN)); /* Daily never reached. */
    CHECK(!nm_monitor_schedule_include(f.d, f.state, f.config,
        yyjson_mut_arr_get(f.monitors, 0), 0, 0.5, INT32_MIN, &run)); /* Daily reached. */
    CHECK(!run); free_fixture(&f);
}

static void prepare_config_order_and_invalid_state(void)
{
    struct fixture f = fixture("{\"FilterStrategies\":[{\"StrategyName\":\"http\",\"FilterSkip\":2,\"FireInterval\":{\"Every\":1}}]}",
        "[{\"EndPointType\":\"http\",\"Enabled\":true}]");
    prepare(&f); CHECK(include(&f, 0)); CHECK(include(&f, 0));
    yyjson_mut_doc *new_config = parse("{\"FilterStrategies\":[{\"StrategyName\":\"http\",\"FireInterval\":{\"Every\":1},\"FilterSkip\":2}]}");
    yyjson_mut_val *cfg = yyjson_mut_doc_get_root(new_config);
    CHECK(nm_monitor_schedule_prepare(f.d, f.state, cfg, f.monitors, 0));
    bool run = false;
    CHECK(nm_monitor_schedule_include(f.d, f.state, cfg, yyjson_mut_arr_get(f.monitors, 0), 0, 0.5, 0, &run)); CHECK(run);
    CHECK(nm_monitor_schedule_include(f.d, f.state, cfg, yyjson_mut_arr_get(f.monitors, 0), 0, 0.5, 0, &run)); CHECK(!run);
    set_int(&f, counter(&f, 0), "Counter", -1);
    CHECK(!nm_monitor_schedule_prepare(f.d, f.state, cfg, f.monitors, 0));
    yyjson_mut_doc_free(new_config); free_fixture(&f);

    f = fixture("{}", "[{\"MonitorIPID\":7,\"SkipCycles\":1,\"Enabled\":true}]");
    prepare(&f); CHECK(!include(&f, 0));
    yyjson_mut_val *h = yyjson_mut_obj_get(yyjson_mut_obj_get(f.state, "Hosts"), "7");
    set_int(&f, h, "RemainingSkips", 2);
    CHECK(!nm_monitor_schedule_prepare(f.d, f.state, f.config, f.monitors, 0));
    free_fixture(&f);
}

static void malformed(void)
{
    const char *configs[] = {"null", "[]", "{\"FilterStrategies\":true}",
        "{\"FilterStrategies\":[null]}", "{\"FilterStrategies\":[{}]}",
        "{\"FilterStrategies\":[{\"StrategyName\":\" \"}]}",
        "{\"FilterStrategies\":[{\"StrategyName\":\"smtp\",\"FireInterval\":[]}]}",
        "{\"FilterStrategies\":[{\"StrategyName\":\"smtp\",\"FireInterval\":{\"Every\":2.0}}]}",
        "{\"FilterStrategies\":[{\"StrategyName\":\"smtp\",\"FilterSkip\":\"2\"}]}",
        "{\"FilterStrategies\":[{\"StrategyName\":\"smtp\",\"FireInterval\":{\"Offset\":2147483648}}]}",
        "{\"FilterStrategies\":[{\"StrategyName\":\"smtp\",\"Randomization\":{\"Probability\":null}}]}",
        "{\"FilterStrategies\":[{\"StrategyName\":\"smtp\",\"EndpointTypeContains\":[3]}]}",
        "{\"FilterStrategies\":[{\"StrategyName\":\"smtp\"},{\"StrategyName\":\"SMTP\"}]}",
        "{\"FilterStrategies\":[],\"FilterStrategies\":[]}",
        "{\"FilterStrategies\":[{\"StrategyName\":\"s\\u0000mtp\"}]}",
        "{\"FilterStrategies\":[{\"StrategyName\":\"\\u00e9\"}]}"};
    for (size_t i = 0; i < sizeof(configs) / sizeof(*configs); i++) {
        struct fixture f = fixture(configs[i], "[]");
        CHECK(!nm_monitor_schedule_prepare(f.d, f.state, f.config, f.monitors, 0));
        CHECK(yyjson_mut_obj_size(f.state) == 0); free_fixture(&f);
    }
    const char *monitors[] = {"[null]", "{}", "[{\"SkipCycles\":true}]", "[{\"SkipCycles\":2.0}]",
        "[{\"MonitorIPID\":4294967295}]", "[{\"MonitorIPID\":null}]", "[{\"Enabled\":1}]",
        "[{\"EndPointType\":[]}]", "[{\"SkipCycles\":1,\"SkipCycles\":2}]"};
    for (size_t i = 0; i < sizeof(monitors) / sizeof(*monitors); i++) {
        struct fixture f = fixture("{}", monitors[i]);
        CHECK(!nm_monitor_schedule_prepare(f.d, f.state, f.config, f.monitors, 0));
        CHECK(yyjson_mut_obj_size(f.state) == 0); free_fixture(&f);
    }
    struct fixture f = fixture("{}", "[{\"Enabled\":true}]");
    bool run = true;
    CHECK(!nm_monitor_schedule_include(f.d, f.state, f.config, yyjson_mut_arr_get(f.monitors, 0), 0, 0.5, 0, &run));
    prepare(&f);
    double invalid[] = {-0.1, 1.0, NAN, INFINITY};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(*invalid); i++) {
        CHECK(!nm_monitor_schedule_include(f.d, f.state, f.config, yyjson_mut_arr_get(f.monitors, 0), 0, invalid[i], 0, &run)); CHECK(!run);
    }
    set_int(&f, f.state, "Version", 2);
    CHECK(!nm_monitor_schedule_prepare(f.d, f.state, f.config, f.monitors, 0));
    free_fixture(&f);
}

int main(void)
{
    host_phases(); counters_and_matching(); defaults_aliases_random();
    daily_and_persistence(); state_reconciliation_and_overflow();
    independent_random_and_short_circuit(); prepare_config_order_and_invalid_state(); malformed();
    printf("monitor_schedule: %u inclusion fixtures plus validation/persistence checks passed\n", checks);
    return 0;
}
