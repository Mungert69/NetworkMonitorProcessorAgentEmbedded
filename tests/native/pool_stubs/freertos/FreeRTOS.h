#ifndef NM_POOL_TEST_RTOS_H
#define NM_POOL_TEST_RTOS_H
#include <stddef.h>
#include <stdint.h>
typedef unsigned UBaseType_t;
typedef uint32_t TickType_t;
typedef struct test_queue *QueueHandle_t;
typedef struct test_queue *SemaphoreHandle_t;
typedef struct test_task *TaskHandle_t;
typedef struct {
    char placeholder;
} StaticQueue_t;
#define pdTRUE 1
#define pdPASS 1
#define portMAX_DELAY UINT32_MAX
#define pdMS_TO_TICKS(ms) (ms)
#define tskIDLE_PRIORITY 0
QueueHandle_t xQueueCreate(unsigned, unsigned);
QueueHandle_t xQueueCreateStatic(unsigned, unsigned, uint8_t *, StaticQueue_t *);
int xQueueSend(QueueHandle_t, const void *, TickType_t);
int xQueueReceive(QueueHandle_t, void *, TickType_t);
void vQueueDelete(QueueHandle_t);
SemaphoreHandle_t xSemaphoreCreateCounting(unsigned, unsigned);
int xSemaphoreTake(SemaphoreHandle_t, TickType_t);
int xSemaphoreGive(SemaphoreHandle_t);
void vSemaphoreDelete(SemaphoreHandle_t);
int xTaskCreatePinnedToCore(void (*)(void *), const char *, unsigned, void *, unsigned,
                            TaskHandle_t *, int);
void vTaskDelete(void *);
void vTaskSuspend(void *);
int xTaskCreate(void (*)(void *), const char *, unsigned, void *, unsigned, TaskHandle_t *);
TaskHandle_t xTaskGetCurrentTaskHandle(void);
size_t uxTaskGetStackHighWaterMark(TaskHandle_t);
#endif
