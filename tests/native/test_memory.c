#include "nm_json.h"
#include <assert.h>
#include <stdio.h>
static unsigned allocations;
static bool fail;
static bool allowed(uint32_t caps)
{
    assert(caps == (MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    ++allocations;
    return !fail;
}
void *heap_caps_malloc(size_t size, uint32_t caps)
{
    return allowed(caps) ? malloc(size) : NULL;
}
void *heap_caps_calloc(size_t n, size_t size, uint32_t caps)
{
    return allowed(caps) ? calloc(n, size) : NULL;
}
void *heap_caps_realloc(void *p, size_t size, uint32_t caps)
{
    return allowed(caps) ? realloc(p, size) : NULL;
}
int main(void)
{
    unsigned before = allocations;
    assert(!nm_bulk_calloc(SIZE_MAX, 2) && allocations == before);
    char *copy = nm_bulk_strdup("owned");
    assert(copy && !strcmp(copy, "owned"));
    fail = true;
    assert(!nm_bulk_realloc(copy, 128) && !strcmp(copy, "owned"));
    assert(!nm_json_new()); /* no hidden internal fallback */
    fail = false;
    free(copy);
    const char *input = "{\"ID\":18446744073709551615,\"Nullable\":null}";
    yyjson_mut_doc *doc = nm_json_read(input, strlen(input));
    assert(doc);
    yyjson_mut_doc *other = nm_json_clone(yyjson_mut_doc_get_root(doc));
    assert(other);
    yyjson_mut_doc_free(doc);
    assert(yyjson_mut_get_uint(yyjson_mut_obj_get(yyjson_mut_doc_get_root(other), "ID")) ==
           UINT64_MAX);
    size_t size = 0;
    char *encoded = nm_json_write(yyjson_mut_doc_get_root(other), 0, &size);
    assert(encoded && size == strlen(input) && !strcmp(input, encoded));
    free(encoded);
    fail = true;
    assert(!nm_json_write(yyjson_mut_doc_get_root(other), 0, NULL));
    fail = false;
    yyjson_mut_doc_free(other);
    puts("bulk PSRAM allocation: capability, failure, ownership and exact JSON tests passed");
}
