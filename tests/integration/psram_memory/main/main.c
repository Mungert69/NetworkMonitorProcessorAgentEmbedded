/* Standalone, unsigned ROM/PSRAM copy diagnostic; no processor credentials.
 * Invoke memcpy through a volatile function pointer so the compiler cannot
 * eliminate zero-length calls or substitute inline copies. */
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <assert.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static atomic_uint finished;
static atomic_bool model_finished;
void run_model_test(void);
static void copy_test(void *argument)
{
    unsigned core = (unsigned)(uintptr_t)argument;
    unsigned char *source = heap_caps_malloc(256, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    unsigned char *dest = heap_caps_malloc(256, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    assert(source && dest);
    void *(*volatile copy)(void *, const void *, size_t) = memcpy;
    for (unsigned i = 0; i < 256; ++i)
        source[i] = (unsigned char)(i + 1);
    for (unsigned repeat = 0; repeat < 4 || (core == 1 && !atomic_load(&model_finished)); ++repeat) {
        for (unsigned length = 0; length < 65; ++length) {
            for (unsigned offset = 0; offset < 16; ++offset) {
                for (unsigned source_offset = 0; source_offset < 16; ++source_offset) {
                    memset(dest, 0xa5, 256);
                    assert(copy(dest + offset, source + source_offset, length) == dest + offset);
                    for (unsigned i = 0; i < 256; ++i)
                        assert(dest[i] == (i >= offset && i < offset + length
                                              ? source[source_offset + i - offset]
                                              : 0xa5));
                }
            }
        }
        assert(heap_caps_check_integrity_all(true));
        if (repeat < 4 || repeat % 100 == 0)
            printf("COPY core=%u pass=%u\n", core, repeat);
        vTaskDelay(1);
    }
    free(source);
    free(dest);
    atomic_fetch_add(&finished, 1);
    vTaskDelete(NULL);
}
void app_main(void)
{
    atomic_init(&finished, 0);
    atomic_init(&model_finished, false);
    assert(xTaskCreatePinnedToCore(copy_test, "copy0", 4096, (void *)0, 1, NULL, 0) == pdPASS);
    assert(xTaskCreatePinnedToCore(copy_test, "copy1", 4096, (void *)1, 1, NULL, 1) == pdPASS);
    while (atomic_load(&finished) < 1)
        vTaskDelay(1);
    run_model_test();
    atomic_store(&model_finished, true);
    while (atomic_load(&finished) < 2)
        vTaskDelay(1);
    puts("PSRAM_MEMORY_INTEGRATION_PASS");
}
