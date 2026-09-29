#ifndef NM_TEST_HEAP_CAPS_H
#define NM_TEST_HEAP_CAPS_H
#include <stddef.h>
#include <stdint.h>
#define MALLOC_CAP_SPIRAM (1U << 10)
#define MALLOC_CAP_8BIT (1U << 2)
void *heap_caps_malloc(size_t, uint32_t);
void *heap_caps_calloc(size_t, size_t, uint32_t);
void *heap_caps_realloc(void *, size_t, uint32_t);
#endif
