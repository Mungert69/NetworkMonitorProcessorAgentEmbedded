#include "sd_card.h"
#include "monitor_numbers.h"
#include "driver/sdspi_host.h"
#include "driver/spi_common.h"
#include "esp_log.h"
#include "esp_vfs_fat.h"
#include "psa/crypto.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static char directory[112];
static bool mounted;

static bool pin(yyjson_mut_val *settings, const char *name, int fallback, int *out)
{
    yyjson_mut_val *value = yyjson_mut_obj_get(settings, name);
    int32_t parsed = fallback;
    if (value && (!nm_monitor_i32(value, &parsed) || parsed < 0 || parsed > 48))
        return false;
    *out = parsed;
    return true;
}

const char *nm_sd_card_mount(yyjson_mut_val *settings, const char *identity)
{
    if (mounted)
        return directory;
    int sck, mosi, miso, cs;
    if (!identity || !pin(settings, "SdSckGpio", 12, &sck) ||
        !pin(settings, "SdMosiGpio", 11, &mosi) || !pin(settings, "SdMisoGpio", 13, &miso) ||
        !pin(settings, "SdCsGpio", 10, &cs) || sck == mosi || sck == miso || sck == cs ||
        mosi == miso || mosi == cs || miso == cs)
        return NULL;
    uint8_t digest[32];
    size_t length = 0;
    if (psa_hash_compute(PSA_ALG_SHA_256, (const uint8_t *)identity, strlen(identity), digest,
                         sizeof(digest), &length) != PSA_SUCCESS ||
        length != sizeof(digest))
        return NULL;
    const char prefix[] = "/sdcard/networkmonitor/";
    memcpy(directory, prefix, sizeof(prefix) - 1);
    for (size_t i = 0; i < sizeof(digest); ++i)
        snprintf(directory + sizeof(prefix) - 1 + i * 2, 3, "%02x", digest[i]);

    spi_bus_config_t bus = {.mosi_io_num = mosi,
                            .miso_io_num = miso,
                            .sclk_io_num = sck,
                            .quadwp_io_num = -1,
                            .quadhd_io_num = -1,
                            .max_transfer_sz = 32768};
    if (spi_bus_initialize(SPI2_HOST, &bus, SPI_DMA_CH_AUTO) != ESP_OK)
        return NULL;
    sdmmc_host_t host = SDSPI_HOST_DEFAULT();
    host.max_freq_khz = 10000;
    host.command_timeout_ms = 1000;
    sdspi_device_config_t slot = SDSPI_DEVICE_CONFIG_DEFAULT();
    slot.host_id = SPI2_HOST;
    slot.gpio_cs = cs;
    esp_vfs_fat_sdmmc_mount_config_t config = {
        .format_if_mount_failed = false, .max_files = 4, .allocation_unit_size = 32768};
    sdmmc_card_t *card = NULL;
    esp_err_t error = esp_vfs_fat_sdspi_mount("/sdcard", &host, &slot, &config, &card);
    if (error != ESP_OK) {
        spi_bus_free(SPI2_HOST);
        ESP_LOGI("nm_sd", "SD unavailable; using NVS ping storage");
        return NULL;
    }
    if ((mkdir("/sdcard/networkmonitor", 0700) && errno != EEXIST) ||
        (mkdir(directory, 0700) && errno != EEXIST)) {
        esp_vfs_fat_sdcard_unmount("/sdcard", card);
        spi_bus_free(SPI2_HOST);
        return NULL;
    }
    mounted = true;
    ESP_LOGI("nm_sd", "SD mounted for pending ping storage");
    return directory;
}

bool nm_sd_card_space(uint64_t *free_bytes)
{
    uint64_t total = 0;
    return mounted && free_bytes && esp_vfs_fat_info("/sdcard", &total, free_bytes) == ESP_OK;
}
