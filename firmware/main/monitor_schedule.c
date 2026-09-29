#include "monitor_schedule.h"
#include "monitor_schedule_typed.h"
#include "nm_json.h"
#include <stdlib.h>

#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

int32_t nm_schedule_daily_hash(int32_t monitor_id)
{
    /* int32 decimal including sign and terminator needs at most 12 bytes. */
    char text[12];
    snprintf(text, sizeof(text), "%" PRId32, monitor_id);
    uint32_t hash = UINT32_C(2166136261);
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p)
        hash = (hash ^ *p) * UINT32_C(16777619);
    return (int32_t)(hash & INT32_MAX);
}

enum mode { COUNTER, RANDOM_COUNTER, DAILY, OTHER };
struct strategy {
    const char *name;
    yyjson_mut_val *patterns;
    enum mode mode;
    int32_t every, offset, slots;
    double probability;
};
struct host {
    int32_t id, skip;
    bool override, enabled;
    const char *endpoint;
};

static yyjson_mut_val *get(yyjson_mut_val *v, const char *key)
{
    return yyjson_mut_obj_get(v, key);
}

static bool put(yyjson_mut_doc *d, yyjson_mut_val *o, const char *k, yyjson_mut_val *v)
{
    return v && yyjson_mut_obj_put(o, yyjson_mut_strcpy(d, k), v);
}

static bool put_int(yyjson_mut_doc *d, yyjson_mut_val *o, const char *k, int64_t v)
{
    yyjson_mut_val *old = get(o, k);
    if (old)
        return yyjson_mut_set_sint(old, v);
    return put(d, o, k, yyjson_mut_sint(d, v));
}

static bool integer(yyjson_mut_val *v, int64_t lo, int64_t hi, int64_t *out)
{
    if (yyjson_mut_is_uint(v)) {
        uint64_t n = yyjson_mut_get_uint(v);
        if (n > (uint64_t)hi)
            return false;
        *out = (int64_t)n;
    } else if (yyjson_mut_is_sint(v))
        *out = yyjson_mut_get_sint(v);
    else
        return false;
    return *out >= lo && *out <= hi;
}

static bool int_field(yyjson_mut_val *o, const char *key, int32_t def, int32_t *out)
{
    yyjson_mut_val *v = get(o, key);
    int64_t n;
    if (!v) {
        *out = def;
        return true;
    }
    if (!integer(v, INT32_MIN, INT32_MAX, &n))
        return false;
    *out = (int32_t)n;
    return true;
}

static bool unique_object(yyjson_mut_val *o)
{
    if (!yyjson_mut_is_obj(o))
        return false;
    size_t i, n, j, m;
    yyjson_mut_val *k, *v, *k2, *v2;
    yyjson_mut_obj_foreach(o, i, n, k, v)
    {
        (void)v;
        yyjson_mut_obj_foreach(o, j, m, k2, v2)
        {
            (void)v2;
            if (j >= i)
                break;
            if (yyjson_mut_equals(k, k2))
                return false;
        }
    }
    return true;
}

static bool ascii_string(yyjson_mut_val *v)
{
    if (!yyjson_mut_is_str(v))
        return false;
    const unsigned char *s = (const unsigned char *)yyjson_mut_get_str(v);
    size_t len = yyjson_mut_get_len(v);
    for (size_t i = 0; i < len; i++)
        if (!s[i] || s[i] > 127)
            return false;
    return true;
}

static unsigned char lower(unsigned char c)
{
    return c >= 'A' && c <= 'Z' ? (unsigned char)(c + ('a' - 'A')) : c;
}
static bool space(unsigned char c)
{
    return c == ' ' || (c >= '\t' && c <= '\r');
}
static bool blank(const char *s)
{
    while (*s && space((unsigned char)*s))
        s++;
    return !*s;
}
static bool equal_ci(const char *a, const char *b)
{
    while (*a && *b && lower((unsigned char)*a) == lower((unsigned char)*b)) {
        a++;
        b++;
    }
    return !*a && !*b;
}
static bool contains_ci(const char *s, const char *pattern)
{
    size_t n = strlen(pattern);
    for (;;) {
        size_t i = 0;
        while (i < n && s[i] && lower((unsigned char)s[i]) == lower((unsigned char)pattern[i]))
            i++;
        if (i == n)
            return true;
        if (!*s++)
            return false;
    }
}

static bool read_interval(yyjson_mut_val *v, struct strategy *s)
{
    s->mode = COUNTER;
    s->every = 1;
    s->offset = 0;
    s->slots = 24;
    if (!v || yyjson_mut_is_null(v))
        return true;
    if (!unique_object(v) || !int_field(v, "Every", 1, &s->every) ||
        !int_field(v, "Offset", 0, &s->offset) || !int_field(v, "SlotsPerDay", 24, &s->slots))
        return false;
    yyjson_mut_val *mode = get(v, "Mode");
    if (mode && !yyjson_mut_is_null(mode)) {
        if (!ascii_string(mode))
            return false;
        const char *start = yyjson_mut_get_str(mode);
        while (space((unsigned char)*start))
            start++;
        size_t len = strlen(start);
        while (len && space((unsigned char)start[len - 1]))
            len--;
        if (len) {
            char text[32];
            if (len >= sizeof(text))
                s->mode = OTHER;
            else {
                memcpy(text, start, len);
                text[len] = 0;
                s->mode = equal_ci(text, "counter")              ? COUNTER
                          : equal_ci(text, "randomized-counter") ? RANDOM_COUNTER
                          : equal_ci(text, "daily-slot")         ? DAILY
                                                                 : OTHER;
            }
        }
    }
    return true;
}

static bool read_strategy(yyjson_mut_val *v, struct strategy *s)
{
    if (!unique_object(v))
        return false;
    yyjson_mut_val *name = get(v, "StrategyName");
    if (!ascii_string(name) || blank(yyjson_mut_get_str(name)))
        return false;
    s->name = yyjson_mut_get_str(name);
    s->patterns = get(v, "EndpointTypeContains");
    if (yyjson_mut_is_null(s->patterns))
        s->patterns = NULL;
    if (s->patterns) {
        if (!yyjson_mut_is_arr(s->patterns))
            return false;
        size_t i, n;
        yyjson_mut_val *p;
        yyjson_mut_arr_foreach(s->patterns, i, n,
                               p) if (!yyjson_mut_is_null(p) && !ascii_string(p)) return false;
    }
    read_interval(NULL, s);
    /* STJ invokes setters in JSON order: legacy aliases mutate FireInterval. */
    size_t i, n;
    yyjson_mut_val *k, *value;
    yyjson_mut_obj_foreach(v, i, n, k, value)
    {
        if (yyjson_mut_equals_str(k, "FireInterval")) {
            if (!read_interval(value, s))
                return false;
        } else if (yyjson_mut_equals_str(k, "FilterSkip")) {
            if (!int_field(v, "FilterSkip", 1, &s->every))
                return false;
        } else if (yyjson_mut_equals_str(k, "FilterStart")) {
            if (!int_field(v, "FilterStart", 0, &s->offset))
                return false;
        }
    }
    if (s->every <= 0)
        s->every = 1;
    s->offset %= s->every;
    if (s->offset < 0)
        s->offset += s->every;
    if (s->slots <= 0)
        s->slots = 24;
    s->probability = 0.5;
    yyjson_mut_val *r = get(v, "Randomization");
    if (r && !yyjson_mut_is_null(r)) {
        if (!unique_object(r))
            return false;
        yyjson_mut_val *p = get(r, "Probability");
        if (p) {
            if (!yyjson_mut_is_num(p) || !isfinite(yyjson_mut_get_num(p)))
                return false;
            s->probability = yyjson_mut_get_num(p);
            if (s->probability < 0)
                s->probability = 0;
            if (s->probability > 1)
                s->probability = 1;
        }
    }
    yyjson_mut_val *ts = get(v, "TimeSpanString");
    return !ts || yyjson_mut_is_null(ts) || yyjson_mut_is_str(ts);
}

static bool counter_mode(struct strategy *s)
{
    return s->mode == COUNTER || s->mode == RANDOM_COUNTER;
}

static bool strategies_valid(yyjson_mut_val *a)
{
    if (!a || yyjson_mut_is_null(a))
        return true;
    if (!yyjson_mut_is_arr(a))
        return false;
    size_t i, n, j, m;
    yyjson_mut_val *v, *other;
    yyjson_mut_arr_foreach(a, i, n, v)
    {
        struct strategy s;
        if (!read_strategy(v, &s))
            return false;
        if (!counter_mode(&s))
            continue;
        yyjson_mut_arr_foreach(a, j, m, other)
        {
            if (j >= i)
                break;
            struct strategy prev;
            if (!read_strategy(other, &prev))
                return false;
            if (counter_mode(&prev) && equal_ci(s.name, prev.name))
                return false;
        }
    }
    return true;
}

static bool read_config(yyjson_mut_val *config, yyjson_mut_val **strategies)
{
    if (!unique_object(config))
        return false;
    *strategies = get(config, "FilterStrategies");
    if (yyjson_mut_is_null(*strategies))
        *strategies = NULL;
    return strategies_valid(*strategies);
}

static bool valid_time(int64_t utc)
{
    return utc >= INT64_C(-62135596800) && utc <= INT64_C(253402300799);
}

static int64_t day_number(int64_t utc)
{
    int64_t day = utc / 86400;
    return utc % 86400 < 0 ? day - 1 : day;
}

static bool key_is_id(yyjson_mut_val *k)
{
    if (!ascii_string(k))
        return false;
    const char *s = yyjson_mut_get_str(k);
    bool neg = *s == '-';
    if (neg)
        s++;
    if (!*s || (*s == '0' && (neg || s[1])))
        return false;
    uint64_t n = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9')
            return false;
        n = n * 10 + (unsigned)(*s - '0');
        if (n > (neg ? UINT64_C(2147483648) : INT32_MAX))
            return false;
    }
    return true;
}

static bool state_valid(yyjson_mut_val *state)
{
    if (!unique_object(state))
        return false;
    if (!yyjson_mut_obj_size(state))
        return true;
    int64_t version;
    if (!integer(get(state, "Version"), 1, 1, &version))
        return false;
    yyjson_mut_val *config = get(state, "Strategies"), *counters = get(state, "Counters");
    yyjson_mut_val *hosts = get(state, "Hosts"), *daily = get(state, "Daily");
    if (!yyjson_mut_is_arr(config) || !strategies_valid(config) || !yyjson_mut_is_arr(counters) ||
        yyjson_mut_arr_size(config) != yyjson_mut_arr_size(counters) || !unique_object(hosts) ||
        !unique_object(daily))
        return false;
    size_t i, n;
    yyjson_mut_val *v;
    yyjson_mut_arr_foreach(counters, i, n, v)
    {
        struct strategy s;
        int64_t c, off, total;
        if (!read_strategy(yyjson_mut_arr_get(config, i), &s) || !unique_object(v) ||
            !integer(get(v, "TotalEndpoints"), 1, INT32_MAX, &total) ||
            !integer(get(v, "Counter"), 0, total - 1, &c) ||
            !integer(get(v, "Offset"), 0, s.every - 1, &off))
            return false;
    }
    yyjson_mut_val *k;
    yyjson_mut_obj_foreach(hosts, i, n, k, v)
    {
        int64_t skip, remaining;
        if (!key_is_id(k) || !unique_object(v) ||
            !integer(get(v, "SkipCycles"), 1, INT32_MAX, &skip) ||
            !integer(get(v, "RemainingSkips"), 0, skip, &remaining))
            return false;
    }
    yyjson_mut_obj_foreach(daily, i, n, k, v)
    {
        int64_t day;
        if (!key_is_id(k) || !integer(v, -719162, 2932896, &day))
            return false;
    }
    return true;
}

static bool same_config(yyjson_mut_val *state, yyjson_mut_val *a)
{
    yyjson_mut_val *old = get(state, "Strategies");
    if (!old || !(a ? yyjson_mut_equals(old, a) : yyjson_mut_arr_size(old) == 0))
        return false;
    /* Object equality ignores setter order; legacy interval aliases do not. */
    size_t i, n;
    yyjson_mut_val *v;
    yyjson_mut_arr_foreach(a, i, n, v)
    {
        struct strategy now, previous;
        if (!read_strategy(v, &now) || !read_strategy(yyjson_mut_arr_get(old, i), &previous) ||
            now.every != previous.every || now.offset != previous.offset ||
            now.mode != previous.mode || now.slots != previous.slots ||
            now.probability != previous.probability)
            return false;
    }
    return true;
}

/* Defined unchecked C# int addition, also used by typed evaluation. */
static int64_t add_i32(int64_t a, int64_t b)
{
    uint32_t sum = (uint32_t)a + (uint32_t)b;
    return sum <= INT32_MAX ? (int64_t)sum : (int64_t)sum - INT64_C(4294967296);
}
/* Typed scheduler. The parsing helpers above are used ONLY at config/storage
 * boundaries. Evaluation itself performs no JSON lookup, parse or cloning. */
static char *schedule_strdup(const char *text)
{
    size_t n = strlen(text) + 1;
    char *p = nm_bulk_malloc(n);
    if (p)
        memcpy(p, text, n);
    return p;
}
void nm_schedule_close(nm_schedule *s)
{
    if (!s)
        return;
    for (size_t i = 0; i < s->strategy_count; ++i) {
        free(s->strategies[i].name);
        if (s->strategies[i].patterns)
            for (size_t j = 0; j < s->strategies[i].pattern_count; ++j)
                free(s->strategies[i].patterns[j]);
        free(s->strategies[i].patterns);
    }
    free(s->strategies);
    free(s->hosts);
    free(s->encoded_strategies);
    memset(s, 0, sizeof(*s));
}
static bool typed_strategies(nm_schedule *s, yyjson_mut_val *array)
{
    size_t n = yyjson_mut_arr_size(array);
    /* Config is bounded separately from host count; no unbounded strategy jobs. */
    if (n > 128 || !strategies_valid(array))
        return false;
    if (n && !(s->strategies = nm_bulk_calloc(n, sizeof(*s->strategies))))
        return false;
    s->strategy_count = n;
    for (size_t i = 0; i < n; ++i) {
        struct strategy parsed;
        if (!read_strategy(yyjson_mut_arr_get(array, i), &parsed))
            return false;
        nm_strategy *d = &s->strategies[i];
        d->name = schedule_strdup(parsed.name);
        if (!d->name)
            return false;
        d->mode = parsed.mode;
        d->every = parsed.every;
        d->offset = parsed.offset;
        d->slots = parsed.slots;
        d->probability = parsed.probability;
        d->total = 1;
        d->current_offset = d->offset;
        d->pattern_count = yyjson_mut_arr_size(parsed.patterns);
        if (d->pattern_count > 128)
            return false;
        if (d->pattern_count &&
            !(d->patterns = nm_bulk_calloc(d->pattern_count, sizeof(*d->patterns))))
            return false;
        for (size_t j = 0; j < d->pattern_count; ++j) {
            const char *text = yyjson_mut_get_str(yyjson_mut_arr_get(parsed.patterns, j));
            if (text && !(d->patterns[j] = schedule_strdup(text)))
                return false;
        }
    }
    s->encoded_strategies = array ? nm_json_write(array, 0, NULL) : schedule_strdup("[]");
    return s->encoded_strategies != NULL;
}
static nm_host_schedule *typed_host(nm_schedule *s, int32_t id, bool create)
{
    for (size_t i = 0; i < s->host_count; ++i)
        if (s->hosts[i].id == id)
            return &s->hosts[i];
    if (!create || s->host_count >= s->host_limit || s->host_count >= SIZE_MAX / sizeof(*s->hosts))
        return NULL;
    void *p = nm_bulk_realloc(s->hosts, (s->host_count + 1) * sizeof(*s->hosts));
    if (!p)
        return NULL;
    s->hosts = p;
    nm_host_schedule *h = &s->hosts[s->host_count++];
    *h = (nm_host_schedule){.id = id};
    return h;
}
bool nm_schedule_open(nm_schedule *s, yyjson_mut_val *saved, size_t limit)
{
    memset(s, 0, sizeof(*s));
    s->host_limit = limit;
    if (!saved || !yyjson_mut_obj_size(saved))
        return !saved || yyjson_mut_is_obj(saved);
    if (!state_valid(saved) || !typed_strategies(s, get(saved, "Strategies")))
        goto fail;
    for (size_t i = 0; i < s->strategy_count; ++i) {
        yyjson_mut_val *c = yyjson_mut_arr_get(get(saved, "Counters"), i);
        int64_t n;
        if (!integer(get(c, "Counter"), 0, INT32_MAX, &n))
            goto fail;
        s->strategies[i].counter = (int32_t)n;
        if (!integer(get(c, "Offset"), 0, INT32_MAX, &n))
            goto fail;
        s->strategies[i].current_offset = (int32_t)n;
        if (!integer(get(c, "TotalEndpoints"), 1, INT32_MAX, &n))
            goto fail;
        s->strategies[i].total = (int32_t)n;
    }
    for (unsigned pass = 0; pass < 2; ++pass) {
        yyjson_mut_val *key, *v;
        size_t i, n;
        yyjson_mut_obj_foreach(get(saved, pass ? "Daily" : "Hosts"), i, n, key, v)
        {
            const char *text = yyjson_mut_get_str(key);
            char *end;
            long long id = strtoll(text, &end, 10);
            if (*end || id < INT32_MIN || id > INT32_MAX)
                goto fail;
            nm_host_schedule *h = typed_host(s, (int32_t)id, true);
            if (!h)
                goto fail;
            int64_t number;
            if (pass) {
                if (!integer(v, -719162, 2932896, &number))
                    goto fail;
                h->day = number;
                h->has_day = true;
            } else {
                if (!integer(get(v, "SkipCycles"), 1, INT32_MAX, &number))
                    goto fail;
                h->skip = (int32_t)number;
                if (!integer(get(v, "RemainingSkips"), 0, h->skip, &number))
                    goto fail;
                h->remaining = (int32_t)number;
                h->has_skip = true;
            }
        }
    }
    s->initialized = true;
    return true;
fail:
    nm_schedule_close(s);
    return false;
}
bool nm_schedule_clone(nm_schedule *out, const nm_schedule *s)
{
    memset(out, 0, sizeof(*out));
    out->host_limit = s->host_limit;
    out->initialized = s->initialized;
    if (s->encoded_strategies &&
        !(out->encoded_strategies = schedule_strdup(s->encoded_strategies)))
        goto fail;
    if (s->strategy_count &&
        !(out->strategies = nm_bulk_calloc(s->strategy_count, sizeof(*out->strategies))))
        goto fail;
    out->strategy_count = s->strategy_count;
    for (size_t i = 0; i < s->strategy_count; ++i) {
        const nm_strategy *a = &s->strategies[i];
        nm_strategy *b = &out->strategies[i];
        *b = *a;
        b->name = NULL;
        b->patterns = NULL;
        if (!(b->name = schedule_strdup(a->name)))
            goto fail;
        if (a->pattern_count &&
            !(b->patterns = nm_bulk_calloc(a->pattern_count, sizeof(*b->patterns))))
            goto fail;
        for (size_t j = 0; j < a->pattern_count; ++j)
            if (a->patterns[j] && !(b->patterns[j] = schedule_strdup(a->patterns[j])))
                goto fail;
    }
    if (s->host_count) {
        if (s->host_count > SIZE_MAX / sizeof(*s->hosts) ||
            !(out->hosts = nm_bulk_malloc(s->host_count * sizeof(*s->hosts))))
            goto fail;
        memcpy(out->hosts, s->hosts, s->host_count * sizeof(*s->hosts));
        out->host_count = s->host_count;
    }
    return true;
fail:
    nm_schedule_close(out);
    return false;
}
bool nm_schedule_configure(nm_schedule *s, yyjson_mut_val *config)
{
    yyjson_mut_val *a;
    if (!read_config(config, &a))
        return false;
    /* Compare once when binding config. Preserve counter state across reboot. */
    yyjson_mut_doc *saved = nm_json_new();
    if (!saved)
        return false;
    yyjson_mut_val *state = nm_schedule_encode(saved, s);
    bool same = state && same_config(state, a);
    yyjson_mut_doc_free(saved);
    if (same)
        return true;
    nm_schedule next = {.host_limit = s->host_limit};
    if (!typed_strategies(&next, a)) {
        nm_schedule_close(&next);
        return false;
    }
    next.initialized = true;
    next.changed = true;
    nm_schedule_close(s);
    *s = next;
    return true;
}
yyjson_mut_val *nm_schedule_encode(yyjson_mut_doc *doc, const nm_schedule *s)
{
    yyjson_mut_val *out = yyjson_mut_obj(doc);
    if (!out || !s->initialized)
        return out;
    yyjson_mut_doc *parsed = nm_json_read(s->encoded_strategies, strlen(s->encoded_strategies));
    yyjson_mut_val *a =
        parsed ? yyjson_mut_val_mut_copy(doc, yyjson_mut_doc_get_root(parsed)) : NULL;
    yyjson_mut_doc_free(parsed);
    yyjson_mut_val *c = yyjson_mut_arr(doc), *hosts = yyjson_mut_obj(doc),
                   *daily = yyjson_mut_obj(doc);
    if (!a || !c || !hosts || !daily || !put_int(doc, out, "Version", 1) ||
        !put(doc, out, "Strategies", a) || !put(doc, out, "Counters", c) ||
        !put(doc, out, "Hosts", hosts) || !put(doc, out, "Daily", daily))
        return NULL;
    for (size_t i = 0; i < s->strategy_count; ++i) {
        const nm_strategy *r = &s->strategies[i];
        yyjson_mut_val *v = yyjson_mut_obj(doc);
        if (!v || !put_int(doc, v, "Counter", r->counter) ||
            !put_int(doc, v, "Offset", r->current_offset) ||
            !put_int(doc, v, "TotalEndpoints", r->total) || !yyjson_mut_arr_append(c, v))
            return NULL;
    }
    for (size_t i = 0; i < s->host_count; ++i) {
        const nm_host_schedule *h = &s->hosts[i];
        char id[16];
        snprintf(id, sizeof(id), "%ld", (long)h->id);
        if (h->has_skip) {
            yyjson_mut_val *v = yyjson_mut_obj(doc);
            if (!v || !put_int(doc, v, "SkipCycles", h->skip) ||
                !put_int(doc, v, "RemainingSkips", h->remaining) || !put(doc, hosts, id, v))
                return NULL;
        }
        if (h->has_day && !put_int(doc, daily, id, h->day))
            return NULL;
    }
    return out;
}
static bool typed_matches(const nm_strategy *s, const nm_monitor_record *h)
{
    const char *name = h->EndPointType ? h->EndPointType : "";
    if (!s->pattern_count)
        return contains_ci(name, s->name);
    for (size_t i = 0; i < s->pattern_count; ++i)
        if (s->patterns[i] && !blank(s->patterns[i]) && contains_ci(name, s->patterns[i]))
            return true;
    return false;
}
bool nm_schedule_prepare(nm_schedule *s, const nm_records *infos, int64_t now)
{
    if (!s->initialized || !valid_time(now) || infos->count > INT32_MAX)
        return false;
    for (size_t i = 0; i < s->strategy_count; ++i) {
        nm_strategy *r = &s->strategies[i];
        if (r->mode != COUNTER && r->mode != RANDOM_COUNTER)
            continue;
        int32_t total = 0;
        for (size_t j = 0; j < infos->count; ++j)
            if (typed_matches(r, (nm_monitor_record *)infos->items[j]))
                ++total;
        if (!total)
            total = 1;
        if (r->total != total) {
            r->total = total;
            r->counter %= total;
            s->changed = true;
        }
    }
    /* Retired hosts have no live connector. Bound scheduler memory on churn. */
    for (size_t i = s->host_count; i > 0; --i) {
        bool found = false;
        for (size_t j = 0; j < infos->count; ++j)
            if (((nm_monitor_record *)infos->items[j])->MonitorIPID == s->hosts[i - 1].id) {
                found = true;
                break;
            }
        if (!found) {
            memmove(s->hosts + i - 1, s->hosts + i, (s->host_count - i) * sizeof(*s->hosts));
            --s->host_count;
            s->changed = true;
        }
    }
    return true;
}
/* SkipCycles overrides all strategy filters, including the zero/negative case. */
static bool include_skip(nm_schedule *s, const nm_monitor_record *host, bool enabled, bool *include)
{
    if (host->SkipCycles <= 0) {
        *include = enabled;
        return true;
    }
    nm_host_schedule *state = typed_host(s, host->MonitorIPID, true);
    if (!state)
        return false;
    if (!state->has_skip || state->skip != host->SkipCycles) {
        state->remaining =
            (int32_t)((uint32_t)host->MonitorIPID % ((uint32_t)host->SkipCycles + 1U));
        state->skip = host->SkipCycles;
        state->has_skip = true;
    }
    bool run = state->remaining == 0;
    state->remaining = run ? state->skip : state->remaining - 1;
    s->changed = true;
    *include = run && enabled;
    return true;
}

/* Advance even for disabled hosts; draw randomness only on an eligible cycle. */
static bool include_counter(nm_schedule *s, nm_strategy *strategy,
                            nm_monitor_schedule_random_fn random_next, void *context, bool *run)
{
    *run = add_i32(strategy->counter, strategy->current_offset) % strategy->every == 0;
    if (++strategy->counter >= strategy->total) {
        strategy->counter = 0;
        strategy->current_offset = (strategy->current_offset + 1) % strategy->every;
    }
    s->changed = true;
    if (*run && strategy->mode == RANDOM_COUNTER) {
        double sample = random_next(context);
        if (!isfinite(sample) || sample < 0 || sample >= 1)
            return false;
        *run = sample <= strategy->probability;
    }
    return true;
}

/* Daily history is per host, shared across strategies, as in the .NET scheduler. */
static bool include_daily(nm_schedule *s, const nm_strategy *strategy,
                          const nm_monitor_record *host, int64_t now, int32_t hash, bool *run)
{
    if (hash == INT32_MIN)
        return false;
    int64_t day = day_number(now);
    int64_t seconds = now - day * 86400;
    int64_t positive = hash < 0 ? -(int64_t)hash : hash;
    int32_t slot = (int32_t)(((double)seconds / 60.0) / (1440.0 / strategy->slots));
    *run = positive % strategy->slots == slot;
    if (*run) {
        nm_host_schedule *state = typed_host(s, host->MonitorIPID, true);
        if (!state)
            return false;
        *run = !state->has_day || state->day < day;
        if (*run) {
            state->day = day;
            state->has_day = true;
            s->changed = true;
        }
    }
    return true;
}

bool nm_schedule_include(nm_schedule *s, const nm_monitor_record *host, int64_t now,
                         nm_monitor_schedule_random_fn random_next, void *context, int32_t hash,
                         bool *include)
{
    if (!include)
        return false;
    *include = false;
    if (!s->initialized || !valid_time(now) || !random_next || !host)
        return false;
    bool enabled =
        host->Enabled && (!nm_record_has(&host->base, NM_M_IsEnabled) || host->IsEnabled);
    if (nm_record_has(&host->base, NM_M_SkipCycles) &&
        !nm_record_null(&host->base, NM_M_SkipCycles))
        return include_skip(s, host, enabled, include);
    for (size_t i = 0; i < s->strategy_count; ++i) {
        nm_strategy *strategy = &s->strategies[i];
        if (!typed_matches(strategy, host))
            continue;
        bool run = true;
        if (strategy->mode == COUNTER || strategy->mode == RANDOM_COUNTER) {
            if (!include_counter(s, strategy, random_next, context, &run))
                return false;
        } else if (strategy->mode == DAILY) {
            if (!include_daily(s, strategy, host, now, hash, &run))
                return false;
        }
        if (!run)
            return true;
    }
    *include = enabled;
    return true;
}

#ifdef NM_SCHEDULE_REFERENCE
#include "monitor_schedule_reference.inc"
#endif
