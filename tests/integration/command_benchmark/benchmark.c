/* Opt-in test build only. Runs the production verifier on the processor task
 * after a real 50-host monitoring cycle; never included in release builds. */
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "command_security.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "nm_esp.h"
#include "benchmark_fixtures.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static yyjson_mut_doc *ecdsa(const char *body)
{
    yyjson_mut_doc *doc = nm_json_read(body, strlen(body));
    yyjson_mut_doc *verified =
        nm_command_verify(yyjson_mut_doc_get_root(doc), "processorInit", benchmark_target,
                          (const unsigned char *)benchmark_public, sizeof(benchmark_public));
    yyjson_mut_doc_free(doc);
    return verified;
}

bool nm_command_benchmark_setup(nm_esp_state *state, const nm_esp_config *config)
{
    if (strcmp(config->routing_id, benchmark_target))
        return false;
    yyjson_mut_doc *doc = ecdsa(benchmark_ecdsa_50);
    bool ok = doc && nm_esp_state_init(state, config, yyjson_mut_doc_get_root(doc));
    yyjson_mut_doc_free(doc);
    printf("COMMAND_BENCHMARK_PROFILE hosts=50 workers=%u installed=%d\n",
           config->max_task_queue_size, ok);
    return ok;
}

static void measure(const char *algorithm, const char *body, unsigned hosts)
{
    const unsigned runs = 20;
    int64_t total = 0, shortest = INT64_MAX, longest = 0;
    unsigned completed = 0;
    unsigned before_internal = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    unsigned before_psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    heap_caps_monitor_local_minimum_free_size_start();
    for (unsigned i = 0; i < runs; ++i) {
        int64_t start = esp_timer_get_time();
        yyjson_mut_doc *doc = NULL;
        if (!strcmp(algorithm, "ES256"))
            doc = ecdsa(body);
#ifdef NM_COMMAND_MLDSA_BENCHMARK
        else
            doc = nm_command_verify_mldsa_event(
                body, strlen(body), "processorInit", benchmark_target,
                (const unsigned char *)benchmark_mldsa_public, sizeof(benchmark_mldsa_public));
#endif
        int64_t elapsed = esp_timer_get_time() - start;
        if (!doc) {
            printf("COMMAND_BENCHMARK_FAILED algorithm=%s\n", algorithm);
            break;
        }
        yyjson_mut_doc_free(doc);
        total += elapsed;
        ++completed;
        if (elapsed < shortest)
            shortest = elapsed;
        if (elapsed > longest)
            longest = elapsed;
        vTaskDelay(1);
    }
    unsigned minimum_internal = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
    unsigned minimum_psram = heap_caps_get_minimum_free_size(MALLOC_CAP_SPIRAM);
    heap_caps_monitor_local_minimum_free_size_stop();
    printf("COMMAND_BENCHMARK algorithm=%s hosts=%u runs=%u wire_bytes=%u mean_us=%" PRId64
           " min_us=%" PRId64 " max_us=%" PRId64 " internal_before=%u internal_min=%u "
           "psram_before=%u psram_min=%u psram_after=%u\n",
           algorithm, hosts, completed, (unsigned)strlen(body), completed ? total / completed : 0,
           shortest, longest, before_internal, minimum_internal, before_psram, minimum_psram,
           (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
}

void nm_command_benchmark_cycle(void)
{
    static unsigned cycles;
    if (++cycles > 2)
        return;
    measure("ES256", benchmark_ecdsa_0, 0);
    measure("ES256", benchmark_ecdsa_50, 50);
#ifdef NM_COMMAND_MLDSA_BENCHMARK
    measure("ML-DSA-65", benchmark_mldsa_0, 0);
    measure("ML-DSA-65", benchmark_mldsa_50, 50);
#endif
    printf("COMMAND_BENCHMARK_CYCLE_DONE cycle=%u\n", cycles);
}
