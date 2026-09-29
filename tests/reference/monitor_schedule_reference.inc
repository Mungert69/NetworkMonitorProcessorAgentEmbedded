/* Pre-refactor implementation: host regression target only. */
static bool read_host(yyjson_mut_val *v, struct host *h)
{
    if (!unique_object(v) || !int_field(v, "MonitorIPID", 0, &h->id)) return false;
    yyjson_mut_val *e = get(v, "EndPointType");
    h->endpoint = "";
    if (e && !yyjson_mut_is_null(e)) {
        if (!ascii_string(e)) return false;
        h->endpoint = yyjson_mut_get_str(e);
    }
    yyjson_mut_val *skip = get(v, "SkipCycles");
    h->override = skip && !yyjson_mut_is_null(skip);
    h->skip = 0;
    if (h->override && !int_field(v, "SkipCycles", 0, &h->skip)) return false;
    yyjson_mut_val *enabled = get(v, "Enabled"), *live = get(v, "IsEnabled");
    if ((enabled && !yyjson_mut_is_bool(enabled)) || (live && !yyjson_mut_is_bool(live))) return false;
    h->enabled = yyjson_mut_is_true(enabled) && (!live || yyjson_mut_is_true(live));
    return true;
}

static bool matches(struct strategy *s, struct host *h)
{
    if (!s->patterns || !yyjson_mut_arr_size(s->patterns)) return contains_ci(h->endpoint, s->name);
    size_t i, n; yyjson_mut_val *p;
    yyjson_mut_arr_foreach(s->patterns, i, n, p) {
        if (yyjson_mut_is_null(p)) continue;
        const char *text = yyjson_mut_get_str(p);
        if (!blank(text) && contains_ci(h->endpoint, text)) return true;
    }
    return false;
}


bool nm_monitor_schedule_prepare(yyjson_mut_doc *doc, yyjson_mut_val *state,
    yyjson_mut_val *config, yyjson_mut_val *monitors, int64_t utc_seconds)
{
    yyjson_mut_val *a;
    if (!doc || !valid_time(utc_seconds) || !read_config(config, &a) ||
        !state_valid(state) || !yyjson_mut_is_arr(monitors) || yyjson_mut_arr_size(monitors) > INT32_MAX) return false;
    size_t i, n; yyjson_mut_val *v;
    yyjson_mut_arr_foreach(monitors, i, n, v) { struct host h; if (!read_host(v, &h)) return false; }
    if (!same_config(state, a)) {
        yyjson_mut_val *copy = a ? yyjson_mut_val_mut_copy(doc, a) : yyjson_mut_arr(doc);
        yyjson_mut_val *counters = yyjson_mut_arr(doc), *hosts = yyjson_mut_obj(doc), *daily = yyjson_mut_obj(doc);
        if (!copy || !counters || !hosts || !daily) return false;
        yyjson_mut_arr_foreach(a, i, n, v) {
            struct strategy s;
            if (!read_strategy(v, &s)) return false;
            yyjson_mut_val *c = yyjson_mut_obj(doc);
            if (!c || !put_int(doc, c, "Counter", 0) || !put_int(doc, c, "Offset", s.offset) ||
                !put_int(doc, c, "TotalEndpoints", 1) || !yyjson_mut_arr_append(counters, c)) return false;
        }
        yyjson_mut_obj_clear(state);
        if (!put_int(doc, state, "Version", 1) || !put(doc, state, "Strategies", copy) ||
            !put(doc, state, "Counters", counters) || !put(doc, state, "Hosts", hosts) || !put(doc, state, "Daily", daily)) return false;
    }
    yyjson_mut_val *counters = get(state, "Counters");
    yyjson_mut_arr_foreach(a, i, n, v) {
        struct strategy s;
        if (!read_strategy(v, &s)) return false;
        if (!counter_mode(&s)) continue;
        int32_t total = 0;
        size_t j, m; yyjson_mut_val *mon;
        yyjson_mut_arr_foreach(monitors, j, m, mon) {
            struct host h;
            if (!read_host(mon, &h)) return false;
            if (matches(&s, &h)) total++;
        }
        if (!total) total = 1;
        yyjson_mut_val *c = yyjson_mut_arr_get(counters, i);
        int64_t counter;
        if (!integer(get(c, "Counter"), 0, INT32_MAX, &counter)) return false;
        if (!put_int(doc, c, "Counter", counter % total) || !put_int(doc, c, "TotalEndpoints", total)) return false;
    }
    return true;
}

bool nm_monitor_schedule_include_with_random(yyjson_mut_doc *doc, yyjson_mut_val *state,
    yyjson_mut_val *config, yyjson_mut_val *monitor, int64_t utc_seconds,
    nm_monitor_schedule_random_fn random_next, void *random_context,
    int32_t daily_hash, bool *include)
{
    yyjson_mut_val *a; struct host h;
    if (!include) return false;
    *include = false;
    if (!doc || !valid_time(utc_seconds) || !random_next ||
        !read_config(config, &a) || !state_valid(state) || !same_config(state, a) || !read_host(monitor, &h)) return false;
    char id[16]; (void)snprintf(id, sizeof(id), "%ld", (long)h.id);
    if (h.override) {
        if (h.skip <= 0) { *include = h.enabled; return true; }
        yyjson_mut_val *hosts = get(state, "Hosts"), *v = get(hosts, id);
        int64_t skip = 0, remaining = 0;
        if (v && (!integer(get(v, "SkipCycles"), 1, INT32_MAX, &skip) ||
            !integer(get(v, "RemainingSkips"), 0, skip, &remaining))) return false;
        if (!v || skip != h.skip) {
            remaining = (uint32_t)h.id % ((uint32_t)h.skip + UINT32_C(1));
            if (!v) {
                v = yyjson_mut_obj(doc);
                if (!v || !put(doc, hosts, id, v)) return false;
            }
            if (!put_int(doc, v, "SkipCycles", h.skip)) return false;
        }
        bool run = remaining == 0;
        if (!put_int(doc, v, "RemainingSkips", run ? h.skip : remaining - 1)) return false;
        *include = run && h.enabled;
        return true;
    }
    size_t i, n; yyjson_mut_val *v;
    yyjson_mut_arr_foreach(a, i, n, v) {
        struct strategy s;
        if (!read_strategy(v, &s)) return false;
        if (!matches(&s, &h)) continue;
        bool run = true;
        if (counter_mode(&s)) {
            yyjson_mut_val *c = yyjson_mut_arr_get(get(state, "Counters"), i);
            int64_t counter, off, total;
            if (!integer(get(c, "Counter"), 0, INT32_MAX, &counter) ||
                !integer(get(c, "Offset"), 0, INT32_MAX, &off) ||
                !integer(get(c, "TotalEndpoints"), 1, INT32_MAX, &total)) return false;
            run = add_i32(counter, off) % s.every == 0;
            counter++;
            if (counter >= total) { counter = 0; off = (off + 1) % s.every; }
            if (!put_int(doc, c, "Counter", counter) || !put_int(doc, c, "Offset", off)) return false;
            if (run && s.mode == RANDOM_COUNTER) {
                double sample = random_next(random_context);
                if (!isfinite(sample) || sample < 0 || sample >= 1) return false;
                run = sample <= s.probability;
            }
        } else if (s.mode == DAILY) {
            if (daily_hash == INT32_MIN) return false;
            int64_t day = day_number(utc_seconds), seconds = utc_seconds - day * 86400;
            int64_t hash = daily_hash < 0 ? -(int64_t)daily_hash : daily_hash;
            int32_t slot = (int32_t)(((double)seconds / 60.0) / (1440.0 / s.slots));
            run = hash % s.slots == slot;
            if (run) {
                yyjson_mut_val *daily = get(state, "Daily"), *last = get(daily, id);
                int64_t previous;
                if (last) {
                    if (!integer(last, -719162, 2932896, &previous)) return false;
                    run = previous < day;
                }
                if (run && !put_int(doc, daily, id, day)) return false;
            }
        }
        if (!run) return true; /* Later matching strategies do not advance. */
    }
    *include = h.enabled;
    return true;
}

static double constant_random(void *context)
{ return *(double *)context; }

bool nm_monitor_schedule_include(yyjson_mut_doc *doc, yyjson_mut_val *state,
    yyjson_mut_val *config, yyjson_mut_val *monitor, int64_t utc_seconds,
    double random_value, int32_t daily_hash, bool *include)
{
    if (include) *include = false;
    if (!isfinite(random_value) || random_value < 0 || random_value >= 1) return false;
    return nm_monitor_schedule_include_with_random(doc, state, config, monitor,
        utc_seconds, constant_random, &random_value, daily_hash, include);
}
