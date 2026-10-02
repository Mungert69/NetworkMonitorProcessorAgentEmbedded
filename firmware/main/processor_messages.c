#include "message_publish.h"
#include "processor_internal.h"

bool nm_processor_publish_ready(processor *agent, bool ready)
{
    yyjson_mut_doc *doc = nm_json_new();
    yyjson_mut_val *data = yyjson_mut_obj(doc);
    if (!data) {
        yyjson_mut_doc_free(doc);
        return false;
    }
    bool built =
        yyjson_mut_obj_add_strcpy(doc, data, "AppID", agent->config->app_id) &&
        yyjson_mut_obj_add_strcpy(doc, data, "PType", "ESP32-S3") &&
        yyjson_mut_obj_add_strcpy(doc, data, "AuthKey", agent->config->auth_key) &&
        yyjson_mut_obj_add_bool(doc, data, "IsProcessorReady", ready) &&
        yyjson_mut_obj_add_uint(doc, data, "RabbitTopologyVersion", 2) &&
        yyjson_mut_obj_add_bool(doc, data, "IsQuantumCapable", agent->config->is_quantum_capable);
    bool ok = built && agent->connected &&
              nm_esp_publish_event(agent->config, agent->client, "processor/out/ready", data,
                                   NM_MESSAGE_JSON, "CProcessorReadyObj");
    yyjson_mut_doc_free(doc);
    return ok;
}

bool nm_processor_publish_firmware_status(processor *agent)
{
    if (!agent->connected)
        return false;
    yyjson_mut_doc *doc = nm_json_new();
    yyjson_mut_val *data = yyjson_mut_obj(doc);
    if (!data) {
        yyjson_mut_doc_free(doc);
        return false;
    }
    if (!yyjson_mut_obj_add_strcpy(doc, data, "AppID", agent->config->app_id) ||
        !yyjson_mut_obj_add_strcpy(doc, data, "AuthKey", agent->config->auth_key) ||
        !nm_esp_ota_add_status_fields(doc, data)) {
        yyjson_mut_doc_free(doc);
        return false;
    }
    bool ok = nm_esp_publish_event(agent->config, agent->client, "processor/out/firmware-status",
                                   data, NM_MESSAGE_JSON, "CProcessorFirmwareStatusObj");
    yyjson_mut_doc_free(doc);
    if (ok && !nm_esp_ota_pending())
        agent->firmware_status_sent = true;
    return ok;
}
