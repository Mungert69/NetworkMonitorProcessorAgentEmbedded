#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "processor_internal.h"
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *TAG = "nm_processor";
typedef struct {
    processor *agent;
    char url[1025];
    char version[32];
    char sha256[65];
    char request_id[37];
} ota_job;

static void ota_task(void *argument)
{
    ota_job *job = argument;
    processor *agent = job->agent;
    nm_processor_publish_ready(agent, false);
    bool updated =
        nm_esp_ota_install(agent->config, job->url, job->version, job->sha256, job->request_id);
    if (!updated)
        nm_processor_publish_ready(agent, true);
    agent->updating = false;
    nm_esp_maintenance_end();
    free(job);
    vTaskDelete(NULL);
}

bool nm_processor_start_update(processor *agent, yyjson_mut_val *data)
{
    bool accepted = false;
    const char *url = string_field(data, "UpdateUrl");
    const char *version = string_field(data, "Version");
    const char *sha256 = string_field(data, "Sha256");
    const char *request_id = string_field(data, "RequestId");
    const char *app_id = string_field(data, "AppID");
    yyjson_mut_val *expires = yyjson_mut_obj_get(data, "ExpiresAtUnixSeconds");
    if (!agent->updating && app_id && !strcmp(app_id, agent->config->app_id) &&
        !nm_esp_clock_sync())
        return false;
    time_t now = time(NULL);
    uint64_t expiry = yyjson_mut_get_uint(expires);
    ESP_LOGI(TAG, "OTA validation updating=%d app_matches=%d clock=%lld expiry=%" PRIu64,
             agent->updating, app_id && !strcmp(app_id, agent->config->app_id), (long long)now,
             expiry);
    if (agent->updating) {
        ESP_LOGW(TAG, "OTA rejected: another update is running");
    } else if (!app_id || strcmp(app_id, agent->config->app_id)) {
        ESP_LOGW(TAG, "OTA rejected: AppID does not match this device");
    } else if (now <= 1700000000 || !yyjson_mut_is_uint(expires) || expiry > INT64_MAX ||
               expiry <= (uint64_t)now || expiry - (uint64_t)now > 300) {
        ESP_LOGW(TAG, "OTA rejected: clock or expiration outside allowed window");
    } else if (!nm_esp_ota_can_install(url, version, sha256, request_id)) {
        ESP_LOGW(TAG, "OTA rejected: image version, URL, digest, request ID or saved state policy");
    } else {
        ota_job *job = calloc(1, sizeof(*job));
        if (job && nm_esp_maintenance_begin()) {
            job->agent = agent;
            memcpy(job->url, url, strlen(url) + 1);
            memcpy(job->version, version, strlen(version) + 1);
            memcpy(job->sha256, sha256, 65);
            memcpy(job->request_id, request_id, 37);
            agent->updating = true;
            accepted = xTaskCreate(ota_task, "nm_ota", 16384, job, 5, NULL) == pdPASS;
            if (!accepted) {
                agent->updating = false;
                free(job);
                nm_esp_maintenance_end();
            }
        } else
            free(job);
    }
    return accepted;
}
