#include "endpoint_dns_task.h"
#include "endpoint_internal.h"
#include "probe_config.h"
#include "esp_heap_caps.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "freertos/idf_additions.h"

static QueueHandle_t completed;

static void reap(void *unused)
{
    (void)unused;
    for (;;) {
        TaskHandle_t task;
        if (xQueueReceive(completed, &task, portMAX_DELAY) == pdTRUE) {
            /* IDF suspends and waits until the other core stops using the stack.
             * Only then are stack/TCB freed and the lifetime slot returned. */
            vTaskDeleteWithCaps(task);
            nm_endpoint_release_slot();
        }
    }
}

bool nm_dns_tasks_init(void)
{
    if (completed)
        return true;
    completed = xQueueCreate(NM_ENDPOINT_MAX_OPERATIONS, sizeof(TaskHandle_t));
    if (!completed)
        return false;
    if (xTaskCreate(reap, "nm_dns_reaper", 3072, NULL, 1, NULL) != pdPASS) {
        vQueueDelete(completed);
        completed = NULL;
        return false;
    }
    return true;
}

bool nm_dns_task_start(void (*run)(void *), void *argument)
{
    return completed && xTaskCreateWithCaps(run, "nm_dns", 4096, argument, 1, NULL,
                                            MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT) == pdPASS;
}

void nm_dns_task_finish(void)
{
    TaskHandle_t self = xTaskGetCurrentTaskHandle();
    /* Queue capacity covers every possible outstanding helper. The operation
     * slot is retained until the reaper has actually deleted this task. */
    xQueueSend(completed, &self, portMAX_DELAY);
    for (;;)
        vTaskSuspend(NULL);
}
