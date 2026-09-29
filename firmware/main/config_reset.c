#include "config_internal.h"
#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "reregister_config.h"

static const char *TAG = "nm_config_reset";
static bool request_reset(uint8_t mode)
{
    if (nvs_flash_init_partition("nmconfig") != ESP_OK)
        return false;
    nvs_handle_t handle;
    if (nvs_open_from_partition("nmconfig", "processor", NVS_READWRITE, &handle) != ESP_OK)
        return false;
    bool ok = nvs_set_u8(handle, "reregister", mode) == ESP_OK && nvs_commit(handle) == ESP_OK;
    nvs_close(handle);
    return ok;
}
bool nm_esp_reregister_request(void)
{
    return request_reset(1);
}
bool nm_esp_factory_reset_request(void)
{
    return request_reset(2);
}

bool nm_config_apply_reset(nm_esp_config *config)
{
    nvs_handle_t handle;
    if (nvs_open_from_partition("nmconfig", "processor", NVS_READWRITE, &handle) != ESP_OK)
        return false;
    uint8_t requested = 0;
    esp_err_t error = nvs_get_u8(handle, "reregister", &requested);
    bool ok = error == ESP_ERR_NVS_NOT_FOUND || (error == ESP_OK && requested == 0);
    if (error == ESP_OK && (requested == 1 || requested == 2)) {
        bool prepared = true;
        if (requested == 2) {
            yyjson_mut_doc *fresh = nm_factory_config(config->root);
            prepared = fresh != NULL;
            if (prepared) {
                yyjson_mut_doc_free(config->doc);
                config->doc = fresh;
                config->root = yyjson_mut_doc_get_root(fresh);
            }
            /* This partition contains ESP-IDF Wi-Fi settings/calibration only;
             * application config, monitor state and OTA metadata are separate. */
            if (prepared)
                prepared = nvs_flash_erase_partition("nvs") == ESP_OK;
        } else
            prepared = nm_reregister_config(config->doc, config->root);
        /* Leave the marker set until EVERY step succeeds. Interrupted resets
         * repeat safely on next boot, before networking or monitoring starts. */
        ok = prepared && nm_esp_storage_reset_monitoring() && nm_esp_config_save(config) &&
             nvs_erase_key(handle, "reregister") == ESP_OK && nvs_commit(handle) == ESP_OK;
        if (ok) {
            if (requested == 2)
                ESP_LOGI(TAG, "Factory reset applied: waiting for serial Wi-Fi setup");
            else
                ESP_LOGI(TAG,
                         "Re-register applied: login and monitoring state cleared; Wi-Fi retained");
        }
    }
    nvs_close(handle);
    return ok;
}
