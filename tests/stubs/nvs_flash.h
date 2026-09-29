#ifndef NM_TEST_NVS_FLASH_H
#define NM_TEST_NVS_FLASH_H
#include "nvs.h"
typedef struct {
    size_t used_entries;
    size_t free_entries;
    size_t available_entries;
    size_t total_entries;
    size_t namespace_count;
} nvs_stats_t;
esp_err_t nvs_flash_init_partition(const char *partition);
esp_err_t nvs_get_stats(const char *partition, nvs_stats_t *stats);
#endif
