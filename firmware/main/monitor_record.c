#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "monitor_model.h"
#include "monitor_numbers.h"
#include "monitor_record_internal.h"
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
typedef enum {
    I32,
    NI32,
    U16,
    NU16,
    U32,
    U64,
    BOOL,
    NBOOL,
    FLOAT,
    NDOUBLE,
    JSON,
    STRING,
    STATUS
} field_type;
typedef struct {
    const char *name;
    size_t offset;
    field_type type;
} field;
#define NM_FIELD(t, n, k) {#n, offsetof(nm_monitor_record, n), k},
static const field monitor_fields[] = {NM_MONITOR_FIELDS(NM_FIELD)};
#undef NM_FIELD
#define NM_FIELD(t, n, k) {#n, offsetof(nm_status_record, n), k},
static const field status_fields[] = {NM_STATUS_FIELDS(NM_FIELD)};
#undef NM_FIELD
#define NM_FIELD(t, n, k) {#n, offsetof(nm_ping_record, n), k},
static const field ping_fields[] = {NM_PING_FIELDS(NM_FIELD)};
#undef NM_FIELD
#define NM_FIELD(t, n, k) {#n, offsetof(nm_swap_record, n), k},
static const field swap_fields[] = {NM_SWAP_FIELDS(NM_FIELD)};
#undef NM_FIELD
#define NM_FIELD(t, n, k) {#n, offsetof(nm_params_record, n), k},
static const field params_fields[] = {NM_PARAMS_FIELDS(NM_FIELD)};
#undef NM_FIELD
#define NM_FIELD(t, n, k) {#n, offsetof(nm_flow_record, n), k},
static const field flow_fields[] = {NM_FLOW_FIELDS(NM_FIELD)};
#undef NM_FIELD
typedef struct {
    const field *fields;
    size_t count, size;
} schema;
#define SCHEMA(name, type) {name##_fields, sizeof(name##_fields) / sizeof(field), sizeof(type)}
static const schema schemas[] = {
    SCHEMA(monitor, nm_monitor_record), SCHEMA(status, nm_status_record),
    SCHEMA(ping, nm_ping_record),       SCHEMA(swap, nm_swap_record),
    SCHEMA(params, nm_params_record),   SCHEMA(flow, nm_flow_record)};
_Static_assert(NM_M_FIELDS <= 64, "presence mask capacity");
struct nm_extension {
    size_t references;
    char json[];
};
nm_extension *nm_extension_from_json(const char *json, size_t length)
{
    if (!json || length > SIZE_MAX - sizeof(nm_extension) - 1)
        return NULL;
    nm_extension *e = nm_bulk_malloc(sizeof(*e) + length + 1);
    if (e) {
        e->references = 1;
        memcpy(e->json, json, length);
        e->json[length] = 0;
    }
    return e;
}
nm_extension *nm_extension_create(yyjson_mut_val *value)
{
    if (!value)
        return NULL;
    size_t length;
    char *json = nm_json_write(value, 0, &length);
    if (!json)
        return NULL;
    nm_extension *e =
        length <= SIZE_MAX - sizeof(*e) - 1 ? nm_bulk_malloc(sizeof(*e) + length + 1) : NULL;
    if (e) {
        e->references = 1;
        memcpy(e->json, json, length + 1);
    }
    free(json);
    return e;
}
nm_extension *nm_extension_retain(nm_extension *e)
{
    if (e) {
        if (e->references == SIZE_MAX)
            return NULL;
        ++e->references;
    }
    return e;
}
void nm_extension_release(nm_extension *e)
{
    if (e && --e->references == 0)
        free(e);
}
yyjson_mut_val *nm_extension_decode(yyjson_mut_doc *doc, const nm_extension *e)
{
    if (!e)
        return yyjson_mut_obj(doc);
    yyjson_mut_doc *read = nm_json_read(e->json, strlen(e->json));
    yyjson_mut_val *value =
        read ? yyjson_mut_val_mut_copy(doc, yyjson_mut_doc_get_root(read)) : NULL;
    yyjson_mut_doc_free(read);
    return value;
}
bool nm_record_has(const nm_record *r, unsigned f)
{
    return r && f < 64 && (r->present & (UINT64_C(1) << f));
}
bool nm_record_null(const nm_record *r, unsigned f)
{
    return r && f < 64 && (r->nulls & (UINT64_C(1) << f));
}
void nm_record_mark(nm_record *r, unsigned f, bool null)
{
    if (r && f < 64) {
        r->present |= UINT64_C(1) << f;
        r->nulls &= ~(UINT64_C(1) << f);
        if (null)
            r->nulls |= UINT64_C(1) << f;
    }
}
nm_record *nm_record_new(nm_record_kind kind)
{
    if ((unsigned)kind >= sizeof(schemas) / sizeof(schemas[0]))
        return NULL;
    nm_record *r = nm_bulk_calloc(1, schemas[kind].size);
    if (r) {
        r->references = 1;
        r->kind = kind;
    }
    return r;
}
nm_record *nm_record_retain(nm_record *r)
{
    if (r) {
        if (r->references == SIZE_MAX)
            return NULL;
        ++r->references;
    }
    return r;
}
void nm_record_release(nm_record *r)
{
    if (!r || --r->references)
        return;
    const schema *s = &schemas[r->kind];
    for (size_t i = 0; i < s->count; ++i) {
        void *p = (char *)r + s->fields[i].offset;
        if (s->fields[i].type == STRING)
            free(*(char **)p);
        if (s->fields[i].type == JSON)
            nm_extension_release(*(nm_extension **)p);
        if (s->fields[i].type == STATUS)
            nm_record_release((nm_record *)*(nm_status_record **)p);
    }
    nm_extension_release(r->extension);
    free(r);
}
nm_record *nm_record_copy(const nm_record *r)
{
    if (!r)
        return NULL;
    const schema *s = &schemas[r->kind];
    nm_record *copy = nm_record_new(r->kind);
    if (!copy)
        return NULL;
    copy->present = r->present;
    copy->nulls = r->nulls;
    copy->extension = nm_extension_retain(r->extension);
    if (r->extension && !copy->extension)
        goto fail;
    for (size_t i = 0; i < s->count; ++i) {
        const field *f = &s->fields[i];
        const void *src = (const char *)r + f->offset;
        void *dst = (char *)copy + f->offset;
        switch (f->type) {
        case STRING:
            if (*(char *const *)src && !(*(char **)dst = nm_bulk_strdup(*(char *const *)src)))
                goto fail;
            break;
        case JSON:
            if (*(nm_extension *const *)src &&
                !(*(nm_extension **)dst = nm_extension_retain(*(nm_extension *const *)src)))
                goto fail;
            break;
        case NDOUBLE:
            *(double *)dst = *(const double *)src;
            break;
        case STATUS:
            if (*(nm_status_record *const *)src &&
                !(*(nm_status_record **)dst = (nm_status_record *)nm_record_retain(
                      (nm_record *)*(nm_status_record *const *)src)))
                goto fail;
            break;
        case I32:
        case NI32:
            *(int32_t *)dst = *(const int32_t *)src;
            break;
        case U16:
        case NU16:
            *(uint16_t *)dst = *(const uint16_t *)src;
            break;
        case U32:
            *(uint32_t *)dst = *(const uint32_t *)src;
            break;
        case U64:
            *(uint64_t *)dst = *(const uint64_t *)src;
            break;
        case BOOL:
        case NBOOL:
            *(bool *)dst = *(const bool *)src;
            break;
        case FLOAT:
            *(float *)dst = *(const float *)src;
            break;
        }
    }
    return copy;
fail:
    nm_record_release(copy);
    return NULL;
}
bool nm_record_string(nm_record *r, unsigned index, const char *value)
{
    if (!r || r->references != 1 || index >= schemas[r->kind].count)
        return false;
    const field *f = &schemas[r->kind].fields[index];
    if (f->type != STRING)
        return false;
    char *copy = value ? nm_bulk_strdup(value) : NULL;
    if (value && !copy)
        return false;
    char **slot = (char **)((char *)r + f->offset);
    free(*slot);
    *slot = copy;
    nm_record_mark(r, index, !value);
    return true;
}
nm_record *nm_record_decode(nm_record_kind kind, yyjson_mut_val *value)
{
    if (!yyjson_mut_is_obj(value))
        return NULL;
    size_t a, n, b, m;
    yyjson_mut_val *key, *entry, *other, *unused;
    yyjson_mut_obj_foreach(value, a, n, key, entry)
    {
        (void)entry;
        yyjson_mut_obj_foreach(value, b, m, other, unused)
        {
            (void)unused;
            if (b >= a)
                break;
            if (yyjson_mut_equals(key, other))
                return NULL;
        }
    }
    nm_record *r = nm_record_new(kind);
    if (!r)
        return NULL;
    const schema *s = &schemas[kind];
    yyjson_mut_doc *rest = nm_json_clone(value);
    if (!rest)
        goto fail;
    for (size_t i = 0; i < s->count; ++i) {
        const field *f = &s->fields[i];
        yyjson_mut_val *v = GET(value, f->name);
        if (!v)
            continue;
        yyjson_mut_obj_remove_key(yyjson_mut_doc_get_root(rest), f->name);
        bool null = yyjson_mut_is_null(v);
        void *dst = (char *)r + f->offset;
        uint64_t u;
        nm_record_mark(r, (unsigned)i, null);
        if (null) {
            if (f->type != STRING && f->type != NI32 && f->type != NU16 && f->type != NBOOL &&
                f->type != NDOUBLE && f->type != JSON)
                goto fail_rest;
            continue;
        }
        switch (f->type) {
        case I32:
        case NI32:
            if (!nm_monitor_i32(v, dst))
                goto fail_rest;
            break;
        case U16:
        case NU16:
            if (!nm_monitor_u64(v, &u) || u > UINT16_MAX)
                goto fail_rest;
            *(uint16_t *)dst = (uint16_t)u;
            break;
        case U32:
            if (!nm_monitor_u32(v, dst))
                goto fail_rest;
            break;
        case U64:
            if (!nm_monitor_u64(v, dst))
                goto fail_rest;
            break;
        case BOOL:
        case NBOOL:
            if (!yyjson_mut_is_bool(v))
                goto fail_rest;
            *(bool *)dst = yyjson_mut_get_bool(v);
            break;
        case JSON:
            if (!yyjson_mut_is_obj(v) || !(*(nm_extension **)dst = nm_extension_create(v)))
                goto fail_rest;
            break;
        case NDOUBLE:
            if (!yyjson_mut_is_num(v) || !isfinite(yyjson_mut_get_num(v)))
                goto fail_rest;
            *(double *)dst = yyjson_mut_get_num(v);
            break;
        case FLOAT:
            if (!yyjson_mut_is_num(v) || !isfinite(yyjson_mut_get_num(v)))
                goto fail_rest;
            *(float *)dst = (float)yyjson_mut_get_num(v);
            if (!isfinite(*(float *)dst))
                goto fail_rest;
            break;
        case STRING:
            if (!yyjson_mut_is_str(v) || !nm_record_string(r, (unsigned)i, yyjson_mut_get_str(v)))
                goto fail_rest;
            break;
        case STATUS:
            *(nm_status_record **)dst = (nm_status_record *)nm_record_decode(NM_STATUS, v);
            if (!*(nm_status_record **)dst)
                goto fail_rest;
            break;
        }
    }
    if (yyjson_mut_obj_size(yyjson_mut_doc_get_root(rest))) {
        r->extension = nm_extension_create(yyjson_mut_doc_get_root(rest));
        if (!r->extension)
            goto fail_rest;
    }
    yyjson_mut_doc_free(rest);
    return r;
fail_rest:
    yyjson_mut_doc_free(rest);
fail:
    nm_record_release(r);
    return NULL;
}
yyjson_mut_val *nm_record_encode(yyjson_mut_doc *doc, const nm_record *r)
{
    if (!doc || !r)
        return NULL;
    yyjson_mut_val *obj = nm_extension_decode(doc, r->extension);
    if (!obj)
        return NULL;
    const schema *s = &schemas[r->kind];
    for (size_t i = 0; i < s->count; ++i) {
        if (!nm_record_has(r, (unsigned)i))
            continue;
        const field *f = &s->fields[i];
        const void *p = (const char *)r + f->offset;
        yyjson_mut_val *v = NULL;
        if (nm_record_null(r, (unsigned)i))
            v = yyjson_mut_null(doc);
        else
            switch (f->type) {
            case I32:
            case NI32:
                v = yyjson_mut_sint(doc, *(const int32_t *)p);
                break;
            case U16:
            case NU16:
                v = yyjson_mut_uint(doc, *(const uint16_t *)p);
                break;
            case U32:
                v = yyjson_mut_uint(doc, *(const uint32_t *)p);
                break;
            case U64:
                v = yyjson_mut_uint(doc, *(const uint64_t *)p);
                break;
            case BOOL:
            case NBOOL:
                v = yyjson_mut_bool(doc, *(const bool *)p);
                break;
            case JSON:
                v = *(nm_extension *const *)p ? nm_extension_decode(doc, *(nm_extension *const *)p)
                                              : yyjson_mut_null(doc);
                break;
            case NDOUBLE:
                v = yyjson_mut_real(doc, *(const double *)p);
                break;
            case FLOAT:
                v = yyjson_mut_real(doc, *(const float *)p);
                break;
            case STRING:
                v = *(char *const *)p ? yyjson_mut_strcpy(doc, *(char *const *)p)
                                      : yyjson_mut_null(doc);
                break;
            case STATUS:
                v = nm_record_encode(doc, (nm_record *)*(nm_status_record *const *)p);
                break;
            }
        if (!v || !yyjson_mut_obj_add_val(doc, obj, f->name, v))
            return NULL;
    }
    return obj;
}
bool nm_records_append(nm_records *a, nm_record *r)
{
    if (!a || !r || a->count >= a->limit)
        return false;
    if (a->count == a->capacity) {
        size_t cap = a->capacity ? a->capacity : 4;
        if (cap <= SIZE_MAX / 2 && a->capacity)
            cap *= 2;
        if (cap > a->limit)
            cap = a->limit;
        if (cap <= a->count || cap > SIZE_MAX / sizeof(*a->items))
            return false;
        void *p = nm_bulk_realloc(a->items, cap * sizeof(*a->items));
        if (!p)
            return false;
        a->items = p;
        a->capacity = cap;
    }
    a->items[a->count++] = r;
    return true;
}
void nm_records_remove(nm_records *a, size_t index)
{
    if (!a || index >= a->count)
        return;
    nm_record_release(a->items[index]);
    memmove(a->items + index, a->items + index + 1, (a->count - index - 1) * sizeof(*a->items));
    --a->count;
}
void nm_records_free(nm_records *a)
{
    if (a) {
        for (size_t i = 0; i < a->count; ++i)
            nm_record_release(a->items[i]);
        free(a->items);
        memset(a, 0, sizeof(*a));
    }
}
bool nm_records_clone(nm_records *out, const nm_records *a)
{
    *out = (nm_records){.limit = a->limit};
    for (size_t i = 0; i < a->count; ++i) {
        nm_record *r = nm_record_retain(a->items[i]);
        if (!r || !nm_records_append(out, r)) {
            nm_record_release(r);
            nm_records_free(out);
            return false;
        }
    }
    return true;
}
nm_record *nm_records_edit(nm_records *a, size_t index)
{
    if (!a || index >= a->count)
        return NULL;
    nm_record *r = a->items[index];
    if (r->references == 1)
        return r;
    nm_record *copy = nm_record_copy(r);
    if (!copy)
        return NULL;
    a->items[index] = copy;
    nm_record_release(r);
    return copy;
}
