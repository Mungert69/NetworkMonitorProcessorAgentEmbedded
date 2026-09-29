#ifndef NM_POOL_TEST_CAPS_H
#define NM_POOL_TEST_CAPS_H
#include <stdlib.h>
#define MALLOC_CAP_INTERNAL 1u
#define MALLOC_CAP_8BIT 2u
#define MALLOC_CAP_SPIRAM 4u
void *heap_caps_malloc(size_t, unsigned);
void *heap_caps_calloc(size_t, size_t, unsigned);
void *heap_caps_realloc(void *, size_t, unsigned);
#endif
