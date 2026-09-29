#include "nm_esp.h"
#include "serial_commands.h"
#include <stdio.h>
#include <stdatomic.h>
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static atomic_flag maintenance=ATOMIC_FLAG_INIT;
bool nm_esp_maintenance_begin(void) { return !atomic_flag_test_and_set(&maintenance); }
void nm_esp_maintenance_end(void) { atomic_flag_clear(&maintenance); }

/* Monitor-loop stop/start: the console task writes, the processor task's cycle
 * gate reads. RAM-only, so a reboot always resumes monitoring. */
static atomic_bool monitors_stopped = false;
void nm_esp_monitor_stop(void) { atomic_store(&monitors_stopped,true); }
void nm_esp_monitor_start(void) { atomic_store(&monitors_stopped,false); }
bool nm_esp_monitor_stopped(void) { return atomic_load(&monitors_stopped); }

static void serial_task(void *unused)
{
    (void)unused;
    nm_serial_parser parser={0};
    puts("Serial commands: help, stop, start, reregister, factory-reset (require confirmation), cancel");
    for (;;) {
        int c=getchar();
        if (c==EOF) { clearerr(stdin); vTaskDelay(pdMS_TO_TICKS(25)); continue; }
        nm_serial_action action=nm_serial_feed(&parser,(unsigned char)c,esp_timer_get_time());
        switch (action) {
        case NM_SERIAL_PROMPT:
            puts("Re-register clears saved login and monitoring data, including unsent results.");
            puts("Wi-Fi, device name, AppName, firmware and signing keys are kept.");
            puts("Type 'confirm reregister' within 30 seconds, or 'cancel'.");
            break;
        case NM_SERIAL_FACTORY_PROMPT:
            puts("Factory reset clears Wi-Fi, login, naming settings and monitoring data, including unsent results.");
            puts("Firmware, signing trust and OTA security metadata are kept.");
            puts("Type 'confirm factory-reset' within 30 seconds, or 'cancel'.");
            break;
        case NM_SERIAL_FACTORY_CONFIRM:
        case NM_SERIAL_CONFIRM:
            if (!nm_esp_maintenance_begin()) {
                puts("Reset refused: firmware update or maintenance in progress."); break;
            }
            if (nm_esp_ota_pending()) {
                puts("Reset refused: firmware health confirmation pending.");
                nm_esp_maintenance_end(); break;
            }
            if (!(action==NM_SERIAL_FACTORY_CONFIRM ? nm_esp_factory_reset_request() : nm_esp_reregister_request())) {
                puts("Reset request could not be saved; no restart.");
                nm_esp_maintenance_end(); break;
            }
            puts(action==NM_SERIAL_FACTORY_CONFIRM ?
                "Factory reset request saved. Restarting into serial Wi-Fi setup." :
                "Re-register request saved. Restarting into browser login.");
            fflush(stdout);
            vTaskDelay(pdMS_TO_TICKS(100));
            esp_restart();
            break;
        case NM_SERIAL_STOP:
            nm_esp_monitor_stop();
            puts("Monitoring stopped. Type 'start' to resume.");
            break;
        case NM_SERIAL_START:
            nm_esp_monitor_start();
            puts("Monitoring started.");
            break;
        case NM_SERIAL_CANCEL: puts("Reset cancelled."); break;
        case NM_SERIAL_HELP: puts("Commands: help, stop, start, reregister, factory-reset, confirm reregister, confirm factory-reset, cancel"); break;
        case NM_SERIAL_INVALID: puts("Unknown, overlong or expired command. Type 'help'."); break;
        default: break;
        }
    }
}

bool nm_esp_serial_start(void)
{
    return xTaskCreate(serial_task,"nm_serial",4096,NULL,3,NULL)==pdPASS;
}
