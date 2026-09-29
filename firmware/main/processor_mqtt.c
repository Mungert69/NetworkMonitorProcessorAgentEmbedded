#include "esp_log.h"
#include "processor_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *TAG = "nm_processor";
static const char *operations[] = {
    "processorInit",           "processorConnect",          "processorQueueDic",
    "processorWakeUp",         "removePingInfos",           "processorAlertFlag",
    "processorAlertSent",      "processorResetAlerts",      "processorUserEvent",
    "processorFirmwareUpdate", "processorFirmwareHealthAck"};

void nm_processor_mqtt_event(void *arg, esp_event_base_t base, int32_t id, void *event_data)
{
    (void)base;
    processor *agent = arg;
    esp_mqtt_event_handle_t event = event_data;
    switch ((esp_mqtt_event_id_t)id) {
    case MQTT_EVENT_CONNECTED:
        agent->connected = true;
        agent->firmware_status_sent = false;
        agent->subscriptions = 0;
        ESP_LOGI(TAG, "MQTT connected; subscribing to commands");
        for (size_t i = 0; i < sizeof(operations) / sizeof(operations[0]); ++i) {
            char topic[160];
            int count =
                snprintf(topic, sizeof(topic), "%s/%s", agent->config->routing_id, operations[i]);
            if (count < 0 || (size_t)count >= sizeof(topic) ||
                esp_mqtt_client_subscribe(agent->client, topic, 1) < 0)
                ESP_LOGE(TAG, "MQTT subscribe failed operation=%s", operations[i]);
        }
        break;
    case MQTT_EVENT_SUBSCRIBED:
        if (++agent->subscriptions == sizeof(operations) / sizeof(operations[0])) {
            ESP_LOGI(TAG, "MQTT command subscriptions active");
            nm_processor_publish_ready(agent, true);
            nm_processor_publish_firmware_status(agent);
            puts("ESP32_S3_MQTT_READY");
        }
        break;
    case MQTT_EVENT_DISCONNECTED:
        agent->connected = false;
        agent->subscriptions = 0;
        ESP_LOGW(TAG, "MQTT disconnected");
        break;
    case MQTT_EVENT_DATA:
        if (event->current_data_offset != 0 || event->data_len != event->total_data_len ||
            event->data_len < 0 || event->data_len > NM_ESP_MAX_COMMAND || event->topic_len <= 0 ||
            event->topic_len >= 160 || memchr(event->data, 0, (size_t)event->data_len)) {
            ESP_LOGW(TAG, "MQTT fragmented/oversized message rejected");
            break;
        }
        command incoming = {0};
        memcpy(incoming.topic, event->topic, (size_t)event->topic_len);
        incoming.body = nm_bulk_malloc((size_t)event->data_len + 1);
        if (!incoming.body)
            break;
        memcpy(incoming.body, event->data, (size_t)event->data_len);
        incoming.body[event->data_len] = 0;
        if (xQueueSend(agent->queue, &incoming, 0) != pdTRUE) {
            ESP_LOGW(TAG, "MQTT command queue full");
            free(incoming.body);
        }
        break;
    case MQTT_EVENT_ERROR:
        ESP_LOGE(TAG, "MQTT transport error");
        break;
    default:
        break;
    }
}
