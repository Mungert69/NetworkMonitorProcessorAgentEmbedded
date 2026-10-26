#ifndef NM_TEST_ESP_TIMER_H
#define NM_TEST_ESP_TIMER_H
#include <stdint.h>
#include <time.h>
static inline int64_t esp_timer_get_time(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (int64_t)now.tv_sec * 1000000 + now.tv_nsec / 1000;
}
#endif
