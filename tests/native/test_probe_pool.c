/* Actual production pool with pthread-backed RTOS boundaries. No network.
 * Tests concurrent completion, input ownership, capacity, partial startup and
 * destruction with undrained jobs. This is not an ESP-IDF scheduler emulation. */
#include "../../firmware/main/nm_probe_pool.c"
#include <assert.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>

struct test_queue {
    pthread_mutex_t mutex;
    pthread_cond_t changed;
    unsigned capacity, size, count, head;
    unsigned char *data;
    bool external_storage;
};
struct test_task {
    pthread_t thread;
    void (*run)(void *);
    void *arg;
};
static struct test_task *created[8];
static unsigned created_count, fail_task_at;
static unsigned allocations, fail_allocation;
static bool allocate(unsigned caps)
{
    assert(caps == (MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT) ||
           caps == (MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    return ++allocations != fail_allocation;
}
void *heap_caps_malloc(size_t bytes, unsigned caps)
{
    assert(caps == (MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    return allocate(caps) ? malloc(bytes) : NULL;
}
void *heap_caps_calloc(size_t count, size_t bytes, unsigned caps)
{
    return allocate(caps) ? calloc(count, bytes) : NULL;
}
void *heap_caps_realloc(void *pointer, size_t bytes, unsigned caps)
{
    assert(caps == (MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    return allocate(caps) ? realloc(pointer, bytes) : NULL;
}
static atomic_uint active_queues;
static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ready = PTHREAD_COND_INITIALIZER;
static bool release_probes;
static unsigned started;

QueueHandle_t xQueueCreate(unsigned capacity, unsigned size)
{
    struct test_queue *q = calloc(1, sizeof(*q));
    assert(q);
    q->capacity = capacity;
    q->size = size;
    q->data = calloc(capacity, size);
    assert(q->data);
    assert(!pthread_mutex_init(&q->mutex, NULL));
    assert(!pthread_cond_init(&q->changed, NULL));
    atomic_fetch_add(&active_queues, 1);
    return q;
}
QueueHandle_t xQueueCreateStatic(unsigned capacity, unsigned size, uint8_t *storage,
                                 StaticQueue_t *control)
{
    assert(storage && control);
    QueueHandle_t q = xQueueCreate(capacity, size);
    free(q->data);
    q->data = storage;
    q->external_storage = true;
    return q;
}
static int transfer(QueueHandle_t q, void *data, TickType_t timeout, bool send)
{
    struct timespec until;
    clock_gettime(CLOCK_REALTIME, &until);
    until.tv_nsec += (long)(timeout % 1000) * 1000000;
    until.tv_sec += timeout / 1000 + until.tv_nsec / 1000000000;
    until.tv_nsec %= 1000000000;
    pthread_mutex_lock(&q->mutex);
    while (send ? q->count == q->capacity : q->count == 0) {
        if (!timeout) {
            pthread_mutex_unlock(&q->mutex);
            return 0;
        }
        int rc = timeout == portMAX_DELAY ? pthread_cond_wait(&q->changed, &q->mutex)
                                          : pthread_cond_timedwait(&q->changed, &q->mutex, &until);
        if (rc == ETIMEDOUT) {
            pthread_mutex_unlock(&q->mutex);
            return 0;
        }
        assert(!rc);
    }
    if (send) {
        memcpy(q->data + ((q->head + q->count) % q->capacity) * q->size, data, q->size);
        ++q->count;
    } else {
        memcpy(data, q->data + q->head * q->size, q->size);
        q->head = (q->head + 1) % q->capacity;
        --q->count;
    }
    pthread_cond_broadcast(&q->changed);
    pthread_mutex_unlock(&q->mutex);
    return pdTRUE;
}
int xQueueSend(QueueHandle_t q, const void *data, TickType_t wait)
{
    return transfer(q, (void *)data, wait, true);
}
int xQueueReceive(QueueHandle_t q, void *data, TickType_t wait)
{
    return transfer(q, data, wait, false);
}
void vQueueDelete(QueueHandle_t q)
{
    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->changed);
    if (!q->external_storage)
        free(q->data);
    free(q);
    atomic_fetch_sub(&active_queues, 1);
}
SemaphoreHandle_t xSemaphoreCreateCounting(unsigned max, unsigned initial)
{
    SemaphoreHandle_t q = xQueueCreate(max, 1);
    q->count = initial;
    return q;
}
int xSemaphoreTake(SemaphoreHandle_t q, TickType_t wait)
{
    char byte;
    return xQueueReceive(q, &byte, wait);
}
int xSemaphoreGive(SemaphoreHandle_t q)
{
    char byte = 0;
    return xQueueSend(q, &byte, portMAX_DELAY);
}
void vSemaphoreDelete(SemaphoreHandle_t q)
{
    vQueueDelete(q);
}
static void *thread_start(void *arg)
{
    struct test_task *t = arg;
    t->run(t->arg);
    return NULL;
}
int xTaskCreatePinnedToCoreWithCaps(void (*run)(void *), const char *name, unsigned stack,
                                    void *arg, unsigned priority, TaskHandle_t *out, int core,
                                    unsigned caps)
{
    assert(caps == (MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT) && stack == 16384);
    (void)name;
    (void)stack;
    assert(priority == tskIDLE_PRIORITY && core == 1);
    if (fail_task_at && created_count + 1 == fail_task_at)
        return 0;
    struct test_task *t = calloc(1, sizeof(*t));
    assert(t && created_count < 8);
    t->run = run;
    t->arg = arg;
    *out = t;
    created[created_count++] = t;
    assert(!pthread_create(&t->thread, NULL, thread_start, t));
    return pdPASS;
}
void vTaskSuspend(void *task)
{
    assert(!task);
    pthread_exit(NULL);
}
void vTaskDeleteWithCaps(TaskHandle_t task)
{
    assert(task);
    assert(!pthread_join(task->thread, NULL));
}
size_t uxTaskGetStackHighWaterMark(TaskHandle_t task)
{
    assert(task);
    return 4096;
}
nm_esp_result nm_esp_endpoint_run(const nm_monitor_record *m)
{
    pthread_mutex_lock(&gate);
    ++started;
    pthread_cond_broadcast(&ready);
    while (!release_probes)
        pthread_cond_wait(&ready, &gate);
    if (!strcmp(m->EndPointType, "blebroadcastlisten")) {
        assert(m->Address && !*m->Address);
    } else {
        assert(!strcmp(m->Address, "original.test") && !strcmp(m->EndPointType, "https"));
        assert(!strcmp(m->Username, "ble-user") && !strcmp(m->Password, "ble-key"));
        assert(!strcmp(m->Args, "--format victron --metric pv_power"));
    }
    pthread_mutex_unlock(&gate);
    return (nm_esp_result){.ok = true, .elapsed_ms = 1};
}
static void join_workers(void)
{
    for (unsigned i = 0; i < created_count; ++i) {
        free(created[i]);
    }
    created_count = 0;
    assert(!atomic_load(&active_queues));
}
int main(void)
{
    for (unsigned i = 1; i <= 7; ++i) {
        allocations = 0;
        fail_allocation = i;
        assert(!nm_probe_pool_freertos_create(8));
        join_workers();
    }
    fail_allocation = 0;
    fail_task_at = 2;
    assert(!nm_probe_pool_freertos_create(2));
    join_workers();
    fail_task_at = 8;
    assert(!nm_probe_pool_freertos_create(8));
    join_workers();
    fail_task_at = 0;
    assert(!nm_probe_pool_freertos_create(0));
    assert(!nm_probe_pool_freertos_create(9));
    for (unsigned iteration = 0; iteration < 100; ++iteration) {
        const unsigned limits[] = {1, 2, 4, 8};
        unsigned workers = limits[iteration % 4];
        release_probes = false;
        started = 0;
        nm_probe_executor *e = nm_probe_pool_freertos_create((int)workers);
        assert(e && e->capacity == (int)workers);
        char address[] = "original.test", type[] = "https", username[] = "ble-user";
        char password[] = "ble-key";
        char arguments[] = "--format victron --metric pv_power";
        nm_monitor_record m = {.Address = address,
                               .EndPointType = type,
                               .Username = username,
                               .Password = password,
                               .Args = arguments,
                               .Timeout = 100};
        for (unsigned offset = 1; offset <= 5; ++offset) {
            fail_allocation = allocations + offset;
            assert(!e->submit(e->context, 0, 42, &m));
            assert(!e->in_flight(e->context));
        }
        fail_allocation = 0;
        for (unsigned i = 0; i < workers; ++i)
            assert(e->submit(e->context, (int32_t)i, 42, &m));
        assert(!e->submit(e->context, 100, 42, &m));
        pthread_mutex_lock(&gate);
        while (started < workers)
            pthread_cond_wait(&ready, &gate);
        memset(address, 'x', sizeof(address) - 1);
        memset(type, 'x', sizeof(type) - 1);
        memset(username, 'x', sizeof(username) - 1);
        memset(password, 'x', sizeof(password) - 1);
        memset(arguments, 'x', sizeof(arguments) - 1);
        release_probes = true;
        pthread_cond_broadcast(&ready);
        pthread_mutex_unlock(&gate);
        if ((iteration / 4) % 2) {
            nm_probe_reply reply;
            for (unsigned i = 0; i < workers; ++i) {
                assert(e->poll(e->context, &reply, 5000) && reply.generation == 42 &&
                       reply.result.ok);
                assert(e->in_flight(e->context) == (int)(workers - i - 1));
            }
        }
        e->destroy(e->context);
        free(e);
        join_workers();
    }
    release_probes = true;
    nm_probe_executor *listen_executor = nm_probe_pool_freertos_create(1);
    assert(listen_executor);
    nm_monitor_record listen = {.EndPointType = "blebroadcastlisten", .Timeout = 100};
    assert(listen_executor->submit(listen_executor->context, 101, 43, &listen));
    nm_probe_reply listen_reply;
    assert(listen_executor->poll(listen_executor->context, &listen_reply, 5000));
    assert(listen_reply.monitor_id == 101 && listen_reply.result.ok);
    listen_executor->destroy(listen_executor->context);
    free(listen_executor);
    join_workers();
    puts("probe pool: 100 concurrent ownership/capacity/shutdown iterations passed");
}
