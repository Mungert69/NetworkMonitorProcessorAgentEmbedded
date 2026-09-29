#include <stdint.h>
#include <stdio.h>
#include "esp_heap_caps.h"
#include "esp_psram.h"

void app_main(void)
{
    const size_t bytes = 7u * 1024u * 1024u;
    printf("PSRAM_PROBE_APP_MAIN size=%u free=%u\n",
           (unsigned)esp_psram_get_size(),
           (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    volatile uint32_t *buffer = heap_caps_malloc(bytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!buffer) {
        printf("PSRAM_PROBE_ALLOC_FAILED\n");
        return;
    }
    for (size_t i = 0; i < bytes / sizeof(*buffer); ++i) {
        buffer[i] = (uint32_t)i ^ ((uint32_t)i >> 16) ^ 0xa5a55a5au;
    }
    for (size_t i = 0; i < bytes / sizeof(*buffer); ++i) {
        uint32_t expected = (uint32_t)i ^ ((uint32_t)i >> 16) ^ 0xa5a55a5au;
        if (buffer[i] != expected) {
            printf("PSRAM_PROBE_MISMATCH index=%u\n", (unsigned)i);
            heap_caps_free((void *)buffer);
            return;
        }
    }
    heap_caps_free((void *)buffer);
    printf("PSRAM_PROBE_PASS checked_bytes=%u\n", (unsigned)bytes);
}
