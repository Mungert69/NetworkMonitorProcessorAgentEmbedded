#ifndef NM_PROBE_POOL_H
#define NM_PROBE_POOL_H
#include "nm_esp.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Injected, bounded probe executor.
 *
 * The monitoring model stays owned by the processor task. An executor only
 * performs the blocking endpoint I/O, so it never touches the model. This keeps
 * the single-writer contract of monitor_model.h intact while allowing several
 * endpoints to be probed at once.
 *
 * submit() must copy everything it needs from `monitor` before returning,
 * because the caller may mutate or release the record afterwards. It returns
 * false when capacity/allocation/validation fails; the caller pauses dispatch.
 * poll() returns one finished probe, blocking up to timeout_ms (0 polls only).
 * in_flight() reports accepted probes not yet polled, including queued replies.
 * submit/poll/destroy belong to one owner task. Workers only perform I/O.
 * destroy() releases context; the executor struct itself is caller-owned. */
typedef struct {
    int32_t monitor_id;
    uint64_t generation;
    nm_esp_result result;
} nm_probe_reply;

struct nm_probe_executor {
    int capacity;
    bool (*submit)(void *context, int32_t monitor_id, uint64_t generation,
                   const nm_monitor_record *monitor);
    bool (*poll)(void *context, nm_probe_reply *reply, uint32_t timeout_ms);
    int (*in_flight)(const void *context);
    void (*destroy)(void *context);
    void *context;
};

/* Firmware FreeRTOS-backed executor. Returns NULL on failure.
 * PSRAM holds stacks, job/result bytes and owned application context. RTOS
 * control blocks remain internal. The owner reaps completed workers; no worker
 * allocates a cleanup task on exit. Workers must never write flash/NVS.
 * The caller owns the returned executor and must pass it to nm_esp_state_set_probe_executor or
 * call executor->destroy(executor->context), then free(executor). */
nm_probe_executor *nm_probe_pool_freertos_create(int workers);

/* Diagnostic: smallest remaining stack (high-water mark) across the executor's
 * worker tasks, in bytes, or 0 when `executor` is NULL or not a pool executor.
 * Read-only; used by the processor task's resource log. */
size_t nm_probe_pool_worker_stack_free(const nm_probe_executor *executor);

#endif
