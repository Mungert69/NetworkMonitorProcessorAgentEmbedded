#include "command_security.h"
#include "esp_log.h"
#include "processor_internal.h"
#include <string.h>

static const char *TAG = "nm_processor";
extern const unsigned char
    command_public_key_start[] asm("_binary_command_signing_public_pem_start");
extern const unsigned char command_public_key_end[] asm("_binary_command_signing_public_pem_end");
static bool key_matches(const processor *agent, yyjson_mut_val *data)
{
    const char *key = string_field(data, "AuthKey");
    size_t expected = strlen(agent->config->auth_key);
    if (!key || strlen(key) != expected)
        return false;
    unsigned difference = 0;
    for (size_t i = 0; i < expected; ++i)
        difference |= (unsigned char)key[i] ^ (unsigned char)agent->config->auth_key[i];
    return difference == 0;
}

void nm_processor_dispatch(processor *agent, const command *message)
{
    size_t prefix = strlen(agent->config->routing_id);
    if (strncmp(message->topic, agent->config->routing_id, prefix) || message->topic[prefix] != '/')
        return;
    const char *operation = message->topic + prefix + 1;
    yyjson_mut_doc *event_doc = nm_json_read(message->body, strlen(message->body));
    yyjson_mut_val *event = yyjson_mut_doc_get_root(event_doc);
    yyjson_mut_val *data = yyjson_mut_obj_get(event, "data");
    yyjson_mut_doc *verified = NULL;
    bool accepted = false;
    if (!data)
        goto done;
    if (nm_command_requires_signature(operation)) {
        verified =
            nm_command_verify(data, operation, agent->config->routing_id, command_public_key_start,
                              (size_t)(command_public_key_end - command_public_key_start));
        if (!verified) {
            ESP_LOGW(TAG, "command %s rejected: missing or invalid ECDSA signature", operation);
            goto done;
        }
        data = yyjson_mut_doc_get_root(verified);
    }
    if (!strcmp(operation, "processorWakeUp")) {
        accepted = nm_processor_publish_ready(agent, true);
    } else if (!strcmp(operation, "processorConnect") && yyjson_mut_is_obj(data)) {
        yyjson_mut_val *interval = yyjson_mut_obj_get(data, "NextRunInterval");
        if (!interval)
            accepted = true;
        else if (yyjson_mut_is_uint(interval) && yyjson_mut_get_uint(interval) <= 86400000) {
            unsigned milliseconds = (unsigned)yyjson_mut_get_uint(interval);
            if (milliseconds)
                agent->poll_seconds = (milliseconds + 999) / 1000;
            accepted = true;
        }
    } else if (yyjson_mut_is_obj(data) && key_matches(agent, data) &&
               !strcmp(operation, "processorInit")) {
        accepted = nm_esp_state_init(agent->state, agent->config, data);
        if (accepted)
            accepted = nm_processor_publish_ready(agent, true);
    } else if (yyjson_mut_is_obj(data) && key_matches(agent, data) &&
               !strcmp(operation, "processorQueueDic")) {
        accepted = nm_esp_state_updates(agent->state, agent->config,
                                        yyjson_mut_obj_get(data, "MonitorIPs"));
    } else if (yyjson_mut_is_arr(data) && (!strcmp(operation, "processorAlertFlag") ||
                                           !strcmp(operation, "processorAlertSent") ||
                                           !strcmp(operation, "processorResetAlerts"))) {
        accepted = nm_esp_state_alert(agent->state, agent->config, agent->client, operation, data);
    } else if (yyjson_mut_is_obj(data) && !strcmp(operation, "processorUserEvent")) {
        accepted = nm_esp_state_user_event(agent->state, data);
    } else if (yyjson_mut_is_obj(data) && !strcmp(operation, "removePingInfos")) {
        accepted = nm_esp_state_ack(agent->state, data);
    } else if (yyjson_mut_is_obj(data) && key_matches(agent, data) &&
               !strcmp(operation, "processorFirmwareHealthAck")) {
        accepted = nm_esp_ota_confirm_from_backend(data);
        if (accepted) {
            nm_processor_publish_firmware_status(agent);
            nm_processor_publish_ready(agent, true);
        }
    } else if (yyjson_mut_is_obj(data) && key_matches(agent, data) &&
               !strcmp(operation, "processorFirmwareUpdate")) {
        accepted = nm_processor_start_update(agent, data);
    }
done:
    ESP_LOGI(TAG, "command %s %s", operation, accepted ? "accepted" : "rejected");
    yyjson_mut_doc_free(event_doc);
    yyjson_mut_doc_free(verified);
}
