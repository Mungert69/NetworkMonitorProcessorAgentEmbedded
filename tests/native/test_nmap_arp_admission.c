/* Exercise the production FIFO with real competing threads, not a copy. */
#include "../../firmware/main/nmap_arp.c"
#include <assert.h>
#include <pthread.h>
#include <time.h>
#include <stdio.h>

int64_t esp_timer_get_time(void)
{
    struct timespec t;
    assert(clock_gettime(CLOCK_MONOTONIC, &t) == 0);
    return (int64_t)t.tv_sec * 1000000 + t.tv_nsec / 1000;
}
unsigned nm_endpoint_remaining(int64_t start, unsigned timeout)
{
    int64_t elapsed = (esp_timer_get_time() - start) / 1000;
    return elapsed < timeout ? timeout - (unsigned)elapsed : 0;
}
TickType_t nm_endpoint_wait_ticks(unsigned ms)
{
    return ms;
}
void vTaskDelay(TickType_t ms)
{
    struct timespec t = {.tv_sec = ms / 1000, .tv_nsec = (long)(ms % 1000) * 1000000};
    nanosleep(&t, NULL);
}
typedef struct {
    unsigned timeout;
    atomic_bool cancel;
    nm_nmap_arp_state result;
    unsigned order;
} job;
static unsigned completed;
static void *run(void *arg)
{
    job *j = arg;
    j->result = acquire_observer(esp_timer_get_time(), j->timeout, &j->cancel);
    if (j->result == NM_ARP_REPLY) {
        lock_admission();
        j->order = ++completed;
        owned = false;
        unlock_admission();
    }
    return NULL;
}
static void wait_count(unsigned expected)
{
    int64_t until = esp_timer_get_time() + 1000000;
    for (;;) {
        lock_admission();
        unsigned count = 0;
        for (arp_waiter *p = wait_head; p; p = p->next)
            ++count;
        unlock_admission();
        if (count == expected)
            return;
        assert(esp_timer_get_time() < until);
        vTaskDelay(1);
    }
}
int main(void)
{
    owned = true;
    job jobs[5] = {{.timeout = 2000},
                   {.timeout = 2000},
                   {.timeout = 2000},
                   {.timeout = 80},
                   {.timeout = 2000}};
    pthread_t threads[5];
    for (unsigned i = 0; i < 5; ++i) {
        assert(pthread_create(&threads[i], NULL, run, &jobs[i]) == 0);
        wait_count(i + 1);
    }
    /* Cancel a middle waiter and expire another without releasing the owner. */
    atomic_store(&jobs[1].cancel, true);
    assert(pthread_join(threads[1], NULL) == 0);
    assert(jobs[1].result == NM_ARP_CANCELLED);
    assert(pthread_join(threads[3], NULL) == 0);
    assert(jobs[3].result == NM_ARP_LOCAL_FAILURE);
    wait_count(3);
    lock_admission();
    owned = false;
    unlock_admission();
    for (unsigned i = 0; i < 5; ++i)
        if (i != 1 && i != 3)
            assert(pthread_join(threads[i], NULL) == 0);
    assert(jobs[0].order == 1 && jobs[2].order == 2 && jobs[4].order == 3);
    assert(!wait_head && !wait_tail && !owned);
    /* Expired/pre-cancelled calls leave no node behind and no ownership. */
    atomic_bool cancel = true;
    assert(acquire_observer(esp_timer_get_time(), 100, &cancel) == NM_ARP_CANCELLED);
    assert(acquire_observer(esp_timer_get_time() - 100000, 1, NULL) == NM_ARP_LOCAL_FAILURE);
    assert(acquire_observer(esp_timer_get_time(), 100, NULL) == NM_ARP_REPLY);
    assert(!wait_head && !wait_tail && owned);
    puts("NMAP_ARP_FIFO_PASS");
}
