#include "nm_probe_pool.h"
#include "nm_memory.h"
#include "esp_heap_caps.h"
#include "probe_config.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "freertos/idf_additions.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef CONFIG_LWIP_MAX_SOCKETS
/* Old generated sdkconfig files do not inherit new defaults automatically.
 * Reserve room for workers, late helper sessions and background connections. */
_Static_assert(CONFIG_LWIP_MAX_SOCKETS >= NM_PROBE_MAX_WORKERS + NM_ENDPOINT_MAX_OPERATIONS + 4,
               "Increase CONFIG_LWIP_MAX_SOCKETS: regenerate sdkconfig from current defaults");
#endif

static const char *TAG = "nm_probe_pool";

/* Match the processor task stack (CONFIG_ESP_MAIN_TASK_STACK_SIZE), which was
 * sized for one TLS/HTTP probe; each worker runs one endpoint at a time. */
#define NM_POOL_WORKER_STACK 16384
/* TLS public-key work can run for several seconds without an application-level
 * yield. These workers are pinned to CPU1; priority 1 starved IDLE1 and tripped
 * the task watchdog in the 150-host run. At idle priority the scheduler time
 * slices with IDLE1 while the processor/MQTT tasks keep higher priority. */
#define NM_POOL_WORKER_PRIORITY tskIDLE_PRIORITY
#define NM_PROBE_STOP_ID INT32_MIN
#define NM_PROBE_ADDRESS_MAX 1024

/* One queued probe. Strings are owned copies, so a worker is independent of the
 * processor task's model records. */
typedef struct {
    int32_t monitor_id;
    uint64_t generation;
    char *address;
    char *type;
    char *username;
    char *password;
    char *arguments;
    uint32_t port;
    int32_t timeout;
} probe_job;

typedef struct {
    int workers;
    TaskHandle_t *tasks;
    QueueHandle_t jobs;
    QueueHandle_t replies;
    StaticQueue_t *job_control, *reply_control;
    uint8_t *job_storage, *reply_storage;
    SemaphoreHandle_t exited;
    atomic_int in_flight;
} pool_context;

static void job_free(probe_job *job)
{
    free(job->address);
    free(job->type);
    free(job->username);
    free(job->password);
    free(job->arguments);
    job->address = job->type = job->username = job->password = job->arguments = NULL;
}

/* Build a stack record from owned job fields; include the host ID for
 * diagnostics without sharing reference-counted model data across tasks. */
static nm_esp_result execute(const probe_job *job)
{
    nm_monitor_record monitor = {0};
    monitor.MonitorIPID = job->monitor_id;
    monitor.Address = job->address;
    monitor.EndPointType = job->type;
    monitor.Username = job->username;
    monitor.Password = job->password;
    monitor.Args = job->arguments;
    monitor.Port = (uint16_t)job->port;
    monitor.Timeout = job->timeout;
    return nm_esp_endpoint_run(&monitor);
}

static void pool_worker(void *argument)
{
    pool_context *ctx = argument;
    probe_job job;
    for (;;) {
        if (xQueueReceive(ctx->jobs, &job, portMAX_DELAY) != pdTRUE)
            continue;
        if (job.monitor_id == NM_PROBE_STOP_ID) {
            job_free(&job);
            break;
        }
        nm_probe_reply reply = {
            .monitor_id = job.monitor_id, .generation = job.generation, .result = execute(&job)};
        job_free(&job);
        /* A reply slot is reserved for every accepted job, so this cannot block
         * forever; the reservation lasts until the owner polls the reply. */
        xQueueSend(ctx->replies, &reply, portMAX_DELAY);
    }
    xSemaphoreGive(ctx->exited);
    /* The owner deletes the completed task with no exit-time allocation. */
    for (;;)
        vTaskSuspend(NULL);
}

static bool pool_submit(void *context, int32_t monitor_id, uint64_t generation,
                        const nm_monitor_record *monitor)
{
    pool_context *ctx = context;
    if (!monitor || !monitor->EndPointType ||
        (!monitor->Address && strcmp(monitor->EndPointType, "blebroadcastlisten")) ||
        monitor_id < 0 || atomic_load(&ctx->in_flight) >= ctx->workers)
        return false;
    if ((monitor->Address && strlen(monitor->Address) > NM_PROBE_ADDRESS_MAX) ||
        (monitor->Username && strlen(monitor->Username) > NM_PROBE_ADDRESS_MAX) ||
        (monitor->Password && strlen(monitor->Password) > NM_PROBE_ADDRESS_MAX) ||
        (monitor->Args && strlen(monitor->Args) > NM_PROBE_ADDRESS_MAX))
        return false;
    probe_job job = {.monitor_id = monitor_id,
                     .generation = generation,
                     .port = monitor->Port,
                     .timeout = monitor->Timeout};
    job.address = nm_bulk_strdup(monitor->Address ? monitor->Address : "");
    job.type = nm_bulk_strdup(monitor->EndPointType);
    job.username = nm_bulk_strdup(monitor->Username ? monitor->Username : "");
    job.password = nm_bulk_strdup(monitor->Password ? monitor->Password : "");
    job.arguments = nm_bulk_strdup(monitor->Args ? monitor->Args : "");
    if (!job.address || !job.type || !job.username || !job.password || !job.arguments) {
        job_free(&job);
        return false;
    }
    atomic_fetch_add(&ctx->in_flight, 1);
    if (xQueueSend(ctx->jobs, &job, 0) != pdTRUE) {
        atomic_fetch_sub(&ctx->in_flight, 1);
        job_free(&job);
        return false;
    }
    return true;
}

static bool pool_poll(void *context, nm_probe_reply *reply, uint32_t timeout_ms)
{
    pool_context *ctx = context;
    TickType_t ticks = timeout_ms ? pdMS_TO_TICKS(timeout_ms) : 0;
    if (timeout_ms && !ticks)
        ticks = 1;
    if (xQueueReceive(ctx->replies, reply, ticks) != pdTRUE)
        return false;
    atomic_fetch_sub(&ctx->in_flight, 1);
    return true;
}

static int pool_in_flight(const void *context)
{
    return atomic_load(&((const pool_context *)context)->in_flight);
}

static void pool_destroy_context(pool_context *ctx)
{
    if (!ctx)
        return;
    if (ctx->tasks) {
        /* Drop any undrained replies so a worker blocked on a full reply queue
         * can reach its stop job and exit. */
        nm_probe_reply discarded;
        while (ctx->replies && xQueueReceive(ctx->replies, &discarded, 0) == pdTRUE)
            nm_esp_result_release(&discarded.result);
        probe_job stop = {.monitor_id = NM_PROBE_STOP_ID};
        for (int i = 0; i < ctx->workers; ++i)
            if (ctx->tasks[i])
                xQueueSend(ctx->jobs, &stop, portMAX_DELAY);
        for (int i = 0; i < ctx->workers; ++i)
            if (ctx->tasks[i])
                xSemaphoreTake(ctx->exited, portMAX_DELAY);
        for (int i = 0; i < ctx->workers; ++i)
            if (ctx->tasks[i])
                vTaskDeleteWithCaps(ctx->tasks[i]);
    }
    if (ctx->exited)
        vSemaphoreDelete(ctx->exited);
    if (ctx->jobs)
        vQueueDelete(ctx->jobs);
    if (ctx->replies)
        vQueueDelete(ctx->replies);
    free(ctx->job_control);
    free(ctx->reply_control);
    free(ctx->job_storage);
    free(ctx->reply_storage);
    free(ctx->tasks);
    free(ctx);
}

static void pool_destroy(void *context)
{
    pool_destroy_context(context);
}

size_t nm_probe_pool_worker_stack_free(const nm_probe_executor *executor)
{
    if (!executor || !executor->context || executor->submit != pool_submit)
        return 0;
    const pool_context *ctx = executor->context;
    size_t minimum = SIZE_MAX;
    for (int i = 0; i < ctx->workers; ++i) {
        if (!ctx->tasks || !ctx->tasks[i])
            continue;
        size_t free_bytes = (size_t)uxTaskGetStackHighWaterMark(ctx->tasks[i]);
        if (free_bytes < minimum)
            minimum = free_bytes;
    }
    return minimum == SIZE_MAX ? 0 : minimum;
}

nm_probe_executor *nm_probe_pool_freertos_create(int workers)
{
    if (workers <= 0 || workers > NM_PROBE_MAX_WORKERS)
        return NULL;
    pool_context *ctx = nm_bulk_calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;
    ctx->workers = workers;
    atomic_init(&ctx->in_flight, 0);
    /* RTOS list/control objects stay internal; application queue bytes do not. */
    ctx->job_control =
        heap_caps_calloc(1, sizeof(StaticQueue_t), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    ctx->reply_control =
        heap_caps_calloc(1, sizeof(StaticQueue_t), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    ctx->job_storage = nm_bulk_calloc((size_t)workers, sizeof(probe_job));
    ctx->reply_storage = nm_bulk_calloc((size_t)workers, sizeof(nm_probe_reply));
    if (ctx->job_control && ctx->job_storage)
        ctx->jobs = xQueueCreateStatic((UBaseType_t)workers, sizeof(probe_job), ctx->job_storage,
                                       ctx->job_control);
    if (ctx->reply_control && ctx->reply_storage)
        ctx->replies = xQueueCreateStatic((UBaseType_t)workers, sizeof(nm_probe_reply),
                                          ctx->reply_storage, ctx->reply_control);
    ctx->exited = xSemaphoreCreateCounting((UBaseType_t)workers, 0);
    ctx->tasks = nm_bulk_calloc((size_t)workers, sizeof(TaskHandle_t));
    if (!ctx->jobs || !ctx->replies || !ctx->exited || !ctx->tasks) {
        ESP_LOGE(TAG, "executor allocation failed");
        goto fail;
    }
    for (int i = 0; i < workers; ++i) {
        char name[20];
        snprintf(name, sizeof(name), "nm_probe%d", i);
        if (xTaskCreatePinnedToCoreWithCaps(pool_worker, name, NM_POOL_WORKER_STACK, ctx,
                                            NM_POOL_WORKER_PRIORITY, &ctx->tasks[i], 1,
                                            MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT) != pdPASS) {
            ESP_LOGE(TAG, "worker %d creation failed", i);
            goto fail;
        }
    }
    nm_probe_executor *executor = nm_bulk_calloc(1, sizeof(*executor));
    if (!executor)
        goto fail;
    executor->capacity = workers;
    executor->submit = pool_submit;
    executor->poll = pool_poll;
    executor->in_flight = pool_in_flight;
    executor->destroy = pool_destroy;
    executor->context = ctx;
    ESP_LOGI(TAG, "concurrent probe executor started with %d workers", workers);
    return executor;
fail:
    pool_destroy_context(ctx);
    return NULL;
}
