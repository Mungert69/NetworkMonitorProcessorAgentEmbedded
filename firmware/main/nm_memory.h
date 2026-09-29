#ifndef NM_MEMORY_H
#define NM_MEMORY_H
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef ESP_PLATFORM
#include "esp_heap_caps.h"
#endif

/* Byte-addressable application data, including enrollment response buffers
 * and task-context-only probe state.
 * Not DMA, ISR data or RTOS control blocks. Probe stacks use the dedicated IDF
 * WithCaps API, not these wrappers. Returned storage is free()-compatible.
 * No fallback to scarce internal RAM when PSRAM is exhausted. Host tests keep
 * libc allocation, including the existing allocation-failure interposition. */
static inline void *nm_bulk_malloc(size_t bytes)
{
#ifdef ESP_PLATFORM
    return heap_caps_malloc(bytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
#else
    return malloc(bytes);
#endif
}
static inline void *nm_bulk_calloc(size_t count, size_t bytes)
{
    if (bytes && count > SIZE_MAX / bytes)
        return NULL;
#ifdef ESP_PLATFORM
    return heap_caps_calloc(count, bytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
#else
    return calloc(count, bytes);
#endif
}
/* On failure the original allocation is still owned by the caller. */
static inline void *nm_bulk_realloc(void *pointer, size_t bytes)
{
#ifdef ESP_PLATFORM
    return heap_caps_realloc(pointer, bytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
#else
    return realloc(pointer, bytes);
#endif
}
static inline char *nm_bulk_strdup(const char *text)
{
    size_t size = strlen(text) + 1;
    char *copy = nm_bulk_malloc(size);
    if (copy)
        memcpy(copy, text, size);
    return copy;
}
#endif
