#ifndef NM_STATUS_LED_H
#define NM_STATUS_LED_H
#include <stdbool.h>

typedef enum {
    NM_LED_BOOT,
    NM_LED_WIFI,
    NM_LED_CLOCK,
    NM_LED_ENROLLMENT,
    NM_LED_STORAGE,
    NM_LED_RUNNING,
    NM_LED_ERROR
} nm_led_stage;

/* Startup-only initialization. Optional hardware failure never blocks monitoring.
 * Other calls borrow no pointers and may run concurrently in task context.
 * Producers only update internal atomic mailboxes; they never wait for RMT.
 * Probe events within one 40 ms display interval coalesce into one pulse. */
#ifdef ESP_PLATFORM
void nm_status_led_start(void);
void nm_status_led_stage(nm_led_stage stage);
void nm_status_led_wifi(bool connected);
void nm_status_led_mqtt(bool connected);
void nm_status_led_clock(bool synced);
void nm_status_led_correcting(bool paused);
void nm_status_led_probe(void);
/* Monitoring data accepted for publication, not a backend acknowledgement. */
void nm_status_led_sent(void);
#else
static inline void nm_status_led_start(void)
{
}
static inline void nm_status_led_stage(nm_led_stage stage)
{
    (void)stage;
}
static inline void nm_status_led_wifi(bool connected)
{
    (void)connected;
}
static inline void nm_status_led_mqtt(bool connected)
{
    (void)connected;
}
static inline void nm_status_led_clock(bool synced)
{
    (void)synced;
}
static inline void nm_status_led_correcting(bool paused)
{
    (void)paused;
}
static inline void nm_status_led_probe(void)
{
}
static inline void nm_status_led_sent(void)
{
}
#endif
#endif
