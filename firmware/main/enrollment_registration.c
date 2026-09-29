#include "command_security.h"
#include "enrollment_internal.h"
#include "enrollment_policy.h"
#include "esp_crt_bundle.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "nm_capabilities.h"
#include "nm_command_limits.h"
#include "nm_memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *TAG = "nm_enrollment";
extern const unsigned char public_start[] asm("_binary_command_signing_public_pem_start");
extern const unsigned char public_end[] asm("_binary_command_signing_public_pem_end");

typedef struct {
    QueueHandle_t messages;
    char topic[160];
    int subscription;
} enrollment;
typedef struct {
    bool subscribed;
    char *body;
} enrollment_message;
static void mqtt_event(void *context, esp_event_base_t base, int32_t id, void *raw)
{
    (void)base;
    enrollment *state = context;
    esp_mqtt_event_handle_t event = raw;
    enrollment_message message = {0};
    if (id == MQTT_EVENT_CONNECTED) {
        state->subscription = esp_mqtt_client_subscribe(event->client, state->topic, 1);
    } else if (id == MQTT_EVENT_SUBSCRIBED && event->msg_id == state->subscription) {
        message.subscribed = true;
        xQueueSend(state->messages, &message, 0);
    } else if (id == MQTT_EVENT_DATA && event->current_data_offset == 0 &&
               event->data_len == event->total_data_len && event->data_len > 0 &&
               event->data_len <= NM_ESP_MAX_ENROLLMENT_COMMAND &&
               event->topic_len == (int)strlen(state->topic) &&
               !memcmp(event->topic, state->topic, event->topic_len) &&
               !memchr(event->data, 0, event->data_len)) {
        message.body = nm_bulk_malloc((size_t)event->data_len + 1);
        if (!message.body)
            return;
        memcpy(message.body, event->data, event->data_len);
        message.body[event->data_len] = 0;
        if (xQueueSend(state->messages, &message, 0) != pdTRUE)
            free(message.body);
    }
}
bool nm_enrollment_register(nm_esp_config *config)
{
    enrollment state = {.messages = xQueueCreate(4, sizeof(enrollment_message)),
                        .subscription = -1};
    snprintf(state.topic, sizeof(state.topic), "%s/processorAuthKey", config->routing_id);
    esp_mqtt_client_config_t options = {
        .broker.address.uri = config->broker_uri,
        .broker.verification.crt_bundle_attach = esp_crt_bundle_attach,
        .credentials.username = config->mqtt_username,
        .credentials.client_id = config->routing_id,
        .credentials.authentication.password = config->mqtt_password,
        .buffer.size = NM_ESP_MAX_ENROLLMENT_COMMAND + 1024,
        .session.keepalive = 120};
    esp_mqtt_client_handle_t client = state.messages ? esp_mqtt_client_init(&options) : NULL;
    bool ok = false;
    if (!client ||
        esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqtt_event, &state) != ESP_OK ||
        esp_mqtt_client_start(client) != ESP_OK)
        goto done;
    ESP_LOGI(TAG, "Registering through authenticated MQTT; waiting for signed processorAuthKey");
    int64_t deadline = esp_timer_get_time() + 60000000;
    while (esp_timer_get_time() < deadline && !ok) {
        enrollment_message message = {0};
        if (xQueueReceive(state.messages, &message, pdMS_TO_TICKS(1000)) != pdTRUE)
            continue;
        if (message.subscribed) {
            yyjson_mut_doc *doc = nm_json_new();
            yyjson_mut_val *event = yyjson_mut_obj(doc), *data = yyjson_mut_obj(doc);
            char identifier[40], timestamp[32];
            snprintf(identifier, sizeof(identifier), "%08lx-%08lx-%08lx-%08lx",
                     (unsigned long)esp_random(), (unsigned long)esp_random(),
                     (unsigned long)esp_random(), (unsigned long)esp_random());
            time_t now = time(NULL);
            struct tm utc;
            gmtime_r(&now, &utc);
            strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &utc);
            bool built = event && data && nm_capabilities_add(doc, data, config->root) &&
                         nm_json_put_str(doc, data, "AppID", config->app_id) &&
                         nm_json_put_str(doc, data, "Owner", config->mqtt_username) &&
                         nm_json_put_str(doc, data, "Location",
                                         nm_enrollment_string(config->root, "MonitorLocation")) &&
                         nm_json_put_str(doc, data, "RabbitHost",
                                         nm_enrollment_string(config->root, "RabbitHost")) &&
                         yyjson_mut_obj_add_uint(doc, data, "MaxLoad", config->max_monitors) &&
                         yyjson_mut_obj_add_bool(doc, data, "IsQuantumCapable", false) &&
                         yyjson_mut_obj_add_uint(doc, data, "RabbitTopologyVersion", 2) &&
                         nm_json_put_str(doc, event, "type", "ProcessorObj") &&
                         nm_json_put_str(doc, event, "source", config->source) &&
                         nm_json_put_str(doc, event, "specversion", "") &&
                         nm_json_put_str(doc, event, "datacontenttype", "") &&
                         nm_json_put_str(doc, event, "id", identifier) &&
                         nm_json_put_str(doc, event, "time", timestamp);
            built = built && yyjson_mut_obj_add_val(doc, event, "data", data);
            char *body = built ? nm_json_write(event, 0, NULL) : NULL;
            char topic[200];
            snprintf(topic, sizeof(topic), "processor/register/%s/%s", config->mqtt_username,
                     config->routing_id);
            if (body)
                esp_mqtt_client_publish(client, topic, body, 0, 1, 0);
            free(body);
            yyjson_mut_doc_free(doc);
        }
        if (message.body) {
            yyjson_mut_doc *event_doc = nm_json_read(message.body, strlen(message.body));
            yyjson_mut_val *event = yyjson_mut_doc_get_root(event_doc);
            yyjson_mut_doc *init_doc = nm_command_verify(
                yyjson_mut_obj_get(event, "data"), "processorAuthKey", config->routing_id,
                public_start, (size_t)(public_end - public_start));
            yyjson_mut_val *init = yyjson_mut_doc_get_root(init_doc);
            const char *app = nm_enrollment_string(init, "AppID"),
                       *key = nm_enrollment_string(init, "AuthKey");
            yyjson_mut_val *monitors = yyjson_mut_obj_get(init, "MonitorIPs");
            if (app && !strcmp(app, config->app_id) && key && *key && strlen(key) <= 4096 &&
                nm_enrollment_monitors(monitors, config->max_monitors)) {
                ok = nm_json_put_str(config->doc, config->root, "auth_key", key) &&
                     nm_esp_config_bind(config, config->root) && nm_esp_storage_init();
                nm_esp_state *monitoring = ok ? nm_esp_state_new(config) : NULL;
                ok = monitoring && nm_esp_state_init(monitoring, config, init);
                nm_esp_state_free(monitoring);
            }
            if (!ok)
                ESP_LOGW(TAG, "Registration reply rejected or could not be stored");
            yyjson_mut_doc_free(init_doc);
            yyjson_mut_doc_free(event_doc);
            free(message.body);
        }
    }
done:
    if (client) {
        esp_mqtt_client_stop(client);
        esp_mqtt_client_destroy(client);
    }
    if (state.messages) {
        enrollment_message message;
        while (xQueueReceive(state.messages, &message, 0) == pdTRUE)
            free(message.body);
        vQueueDelete(state.messages);
    }
    return ok;
}
