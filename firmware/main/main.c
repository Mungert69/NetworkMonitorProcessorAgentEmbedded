#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "esp_flash.h"
#include "esp_heap_caps.h"
#include "esp_chip_info.h"
#include "esp_psram.h"
#include "esp_system.h"
#include "nm_esp.h"
#include "ble_scanner.h"

void app_main(void)
{
    nm_esp_ota_start_health_watchdog();
    esp_chip_info_t chip;
    uint32_t flash_bytes = 0;
    esp_chip_info(&chip);

    if (esp_flash_get_size(NULL, &flash_bytes) != ESP_OK) {
        puts("ESP32_S3_FLASH_CHECK_FAILED");
        return;
    }

    size_t psram_bytes = esp_psram_get_size();
    size_t psram_heap_bytes = heap_caps_get_total_size(MALLOC_CAP_SPIRAM);
    printf("ESP32-S3 cores=%d flash=%" PRIu32 " psram=%zu psram_heap=%zu\n",
           chip.cores, flash_bytes, psram_bytes, psram_heap_bytes);

    if (chip.model != CHIP_ESP32S3 || flash_bytes != 16U * 1024U * 1024U ||
        psram_bytes != 8U * 1024U * 1024U || psram_heap_bytes == 0) {
        puts("ESP32_S3_RESOURCE_CHECK_FAILED");
        return;
    }

    puts("ESP32_S3_EMULATOR_READY");
    nm_esp_config config;
    if (!nm_esp_config_load(&config)) {
        (void)nm_esp_serial_start();
        puts("ESP32_S3_CONFIG_INVALID");
        return;
    }
    bool setting_up=config.wifi_setup;
    if (setting_up && !nm_esp_serial_wifi_setup(&config)) {
        puts("ESP32_S3_WIFI_SETUP_FAILED");
        esp_restart();
    }
    if (!nm_esp_serial_start()) {
        puts("ESP32_S3_SERIAL_FAILED");
        return;
    }
    if (!nm_esp_wifi_connect(&config)) {
        puts("ESP32_S3_WIFI_FAILED");
        if (setting_up) {
            puts("Wi-Fi connection failed; restarting serial Wi-Fi setup.");
            esp_restart();
        }
        return;
    }
    if (setting_up && !nm_esp_wifi_setup_complete(&config)) {
        puts("ESP32_S3_WIFI_SETUP_SAVE_FAILED");
        esp_restart();
    }
    if (!nm_ble_scanner_start()) {
        puts("BLE scanner unavailable; continuing processor startup.");
    }
    if (config.auth_device && !nm_esp_enroll(&config)) {
        puts("ESP32_S3_ENROLLMENT_FAILED");
        return;
    }
    nm_esp_processor_run(&config);
}
