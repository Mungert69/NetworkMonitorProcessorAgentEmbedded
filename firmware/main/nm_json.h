#ifndef NM_JSON_H
#define NM_JSON_H
#include "yyjson.h"
#include "nm_memory.h"
#include <string.h>

/* Allocator callbacks have static lifetime; documents may outlive their creator. */
static inline void *nm_json_allocate(void *context, size_t size)
{
    (void)context;
    return nm_bulk_malloc(size);
}
static inline void *nm_json_resize(void *context, void *pointer, size_t old_size, size_t size)
{
    (void)context;
    (void)old_size;
    return nm_bulk_realloc(pointer, size);
}
static inline void nm_json_release(void *context, void *pointer)
{
    (void)context;
    free(pointer);
}
static inline const yyjson_alc *nm_json_allocator(void)
{
    static const yyjson_alc allocator = {nm_json_allocate, nm_json_resize, nm_json_release, NULL};
    return &allocator;
}
static inline yyjson_mut_doc *nm_json_new(void)
{
    return yyjson_mut_doc_new(nm_json_allocator());
}
/* Owned, free()-compatible serialized output. */
static inline char *nm_json_write(const yyjson_mut_val *value, yyjson_write_flag flags,
                                  size_t *length)
{
    return yyjson_mut_val_write_opts(value, flags, nm_json_allocator(), length, NULL);
}

enum { NM_JSON_MAX_DEPTH = 64 };

/* A nesting bound only: yyjson remains responsible for all JSON grammar.
 * Run before its recursive immutable-to-mutable copy sees untrusted input. */
static inline bool nm_json_depth_ok(const char *text, size_t length)
{
    if (!text)
        return false;
    unsigned depth = 0;
    bool string = false, escaped = false;
    for (size_t i = 0; i < length; ++i) {
        char c = text[i];
        if (string) {
            if (escaped)
                escaped = false;
            else if (c == '\\')
                escaped = true;
            else if (c == '"')
                string = false;
        } else if (c == '"')
            string = true;
        else if (c == '[' || c == '{') {
            if (++depth > NM_JSON_MAX_DEPTH)
                return false;
        } else if (c == ']' || c == '}') {
            if (!depth)
                return false;
            --depth;
        }
    }
    return true;
}

/* Iterative traversal checks keys as well as values before CString consumers
 * can mistake an embedded NUL for the end of an authenticated/config string. */
static inline bool nm_json_strings_ok(yyjson_val *value)
{
    struct frame {
        bool object;
        union {
            yyjson_arr_iter array;
            yyjson_obj_iter object;
        } iter;
    } stack[NM_JSON_MAX_DEPTH];
    size_t depth = 0;
    for (;;) {
        if (yyjson_is_str(value) && yyjson_get_len(value) != strlen(yyjson_get_str(value)))
            return false;
        if (yyjson_is_arr(value) || yyjson_is_obj(value)) {
            if (depth == NM_JSON_MAX_DEPTH)
                return false;
            struct frame *frame = &stack[depth++];
            frame->object = yyjson_is_obj(value);
            if (frame->object)
                yyjson_obj_iter_init(value, &frame->iter.object);
            else
                yyjson_arr_iter_init(value, &frame->iter.array);
        }
        value = NULL;
        while (depth && !value) {
            struct frame *frame = &stack[depth - 1];
            if (frame->object) {
                yyjson_val *key = yyjson_obj_iter_next(&frame->iter.object);
                if (key) {
                    if (yyjson_get_len(key) != strlen(yyjson_get_str(key)))
                        return false;
                    value = yyjson_obj_iter_get_val(key);
                }
            } else
                value = yyjson_arr_iter_next(&frame->iter.array);
            if (!value)
                --depth;
        }
        if (!value)
            return true;
    }
}

/* Returned documents own all values and strings, independent of input bytes. */
static inline yyjson_mut_doc *nm_json_read(const char *text, size_t length)
{
    if (!nm_json_depth_ok(text, length))
        return NULL;
    yyjson_doc *parsed = yyjson_read_opts((char *)text, length, 0, nm_json_allocator(), NULL);
    if (!parsed)
        return NULL;
    if (!nm_json_strings_ok(yyjson_doc_get_root(parsed))) {
        yyjson_doc_free(parsed);
        return NULL;
    }
    yyjson_mut_doc *doc = yyjson_doc_mut_copy(parsed, nm_json_allocator());
    yyjson_doc_free(parsed);
    return doc;
}

static inline yyjson_mut_doc *nm_json_clone(yyjson_mut_val *value)
{
    yyjson_mut_doc *doc = nm_json_new();
    yyjson_mut_val *root = yyjson_mut_val_mut_copy(doc, value);
    if (!root) {
        yyjson_mut_doc_free(doc);
        return NULL;
    }
    yyjson_mut_doc_set_root(doc, root);
    return doc;
}

static inline bool nm_json_put(yyjson_mut_doc *doc, yyjson_mut_val *obj, const char *key,
                               yyjson_mut_val *value)
{
    return value && yyjson_mut_obj_put(obj, yyjson_mut_strcpy(doc, key), value);
}

static inline bool nm_json_put_str(yyjson_mut_doc *doc, yyjson_mut_val *obj, const char *key,
                                   const char *value)
{
    return nm_json_put(doc, obj, key, yyjson_mut_strcpy(doc, value));
}

#endif
