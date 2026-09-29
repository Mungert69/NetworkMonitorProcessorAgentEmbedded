/* Exercise the production reaper's startup and completion ownership. Network
 * lifetime/contention itself is covered by endpoint_execution and the emulator. */
#include "../../firmware/main/endpoint_dns_task.c"
#include <assert.h>
#include <setjmp.h>
#include <stdio.h>

static bool fail_queue, fail_reaper, fail_dns;
static unsigned queues, deleted, released, created;
static TaskHandle_t queued;
static int fake_queue, fake_task;
static jmp_buf suspended, drained;
QueueHandle_t xQueueCreate(unsigned count, unsigned size)
{
    assert(count == NM_ENDPOINT_MAX_OPERATIONS && size == sizeof(TaskHandle_t));
    if (fail_queue)
        return NULL;
    ++queues;
    return (QueueHandle_t)&fake_queue;
}
void vQueueDelete(QueueHandle_t q)
{
    assert(q == (QueueHandle_t)&fake_queue && queues == 1);
    --queues;
}
int xTaskCreate(void (*run)(void *), const char *name, unsigned bytes, void *arg, unsigned priority,
                TaskHandle_t *out)
{
    (void)name;
    assert(run == reap && bytes == 3072 && !arg && priority == 1 && !out);
    return !fail_reaper;
}
static void worker(void *arg)
{
    (void)arg;
}
int xTaskCreateWithCaps(void (*run)(void *), const char *name, unsigned bytes, void *arg,
                        unsigned priority, TaskHandle_t *out, unsigned caps)
{
    (void)name;
    assert(run == worker && bytes == 4096 && arg == &fake_task && priority == 1 && !out);
    assert(caps == (MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    if (fail_dns)
        return 0;
    ++created;
    return pdPASS;
}
TaskHandle_t xTaskGetCurrentTaskHandle(void)
{
    return (TaskHandle_t)&fake_task;
}
int xQueueSend(QueueHandle_t q, const void *item, TickType_t ticks)
{
    assert(q == completed && ticks == portMAX_DELAY && !queued);
    queued = *(const TaskHandle_t *)item;
    return pdTRUE;
}
int xQueueReceive(QueueHandle_t q, void *item, TickType_t ticks)
{
    assert(q == completed && ticks == portMAX_DELAY);
    if (!queued)
        longjmp(drained, 1);
    *(TaskHandle_t *)item = queued;
    queued = NULL;
    return pdTRUE;
}
void vTaskSuspend(void *task)
{
    assert(!task);
    longjmp(suspended, 1);
}
void vTaskDeleteWithCaps(TaskHandle_t task)
{
    assert(task == (TaskHandle_t)&fake_task && deleted < created);
    ++deleted;
}
void nm_endpoint_release_slot(void)
{
    /* The slot is unavailable until stack/TCB cleanup has completed. */
    assert(deleted == released + 1);
    ++released;
}
int main(void)
{
    assert(!nm_dns_task_start(worker, &fake_task));
    fail_queue = true;
    assert(!nm_dns_tasks_init() && !completed && !queues);
    fail_queue = false;
    fail_reaper = true;
    assert(!nm_dns_tasks_init() && !completed && !queues);
    fail_reaper = false;
    assert(nm_dns_tasks_init() && nm_dns_tasks_init() && queues == 1);
    fail_dns = true;
    assert(!nm_dns_task_start(worker, &fake_task) && !released);
    fail_dns = false;
    for (unsigned i = 0; i < 100; ++i) {
        assert(nm_dns_task_start(worker, &fake_task));
        if (!setjmp(suspended))
            nm_dns_task_finish();
        assert(queued && deleted == i && released == i);
        if (!setjmp(drained))
            reap(NULL);
        assert(!queued && deleted == i + 1 && released == i + 1);
    }
    vQueueDelete(completed);
    completed = NULL;
    puts("DNS PSRAM task reaper: startup, failures and post-deletion slot release passed");
}
