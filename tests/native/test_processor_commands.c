/* Real command dispatcher with recording adapters. Crypto itself is tested by
 * test-command-signatures.sh; this checks ordering, routing and delegation. */
#include "processor_internal.h"
#include "command_security.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

__asm__(".pushsection .rodata\n"
        ".global _binary_command_signing_public_pem_start\n"
        "_binary_command_signing_public_pem_start: .byte 1,2,3,4\n"
        ".global _binary_command_signing_public_pem_end\n"
        "_binary_command_signing_public_pem_end:\n.popsection\n");

static unsigned calls, ready, health, verified;
static bool valid_signature = true, operation_ok = true;
static char last_operation[64];
bool nm_command_requires_signature(const char *operation)
{
    return !strcmp(operation, "processorInit") || !strcmp(operation, "processorQueueDic") ||
           !strcmp(operation, "processorFirmwareUpdate") ||
           !strcmp(operation, "processorFirmwareHealthAck");
}
yyjson_mut_doc *nm_command_verify(yyjson_mut_val *data, const char *operation, const char *target,
                                  const unsigned char *key, size_t size)
{
    assert(nm_command_requires_signature(operation));
    assert(!strcmp(target, "owned-route") && key && size == 4);
    ++verified;
    return valid_signature ? nm_json_clone(data) : NULL;
}
bool nm_processor_publish_ready(processor *agent, bool value)
{
    assert(agent && value);
    ++ready;
    return true;
}
bool nm_processor_publish_firmware_status(processor *agent)
{
    assert(agent);
    ++health;
    return true;
}
static bool called(const char *operation, yyjson_mut_val *data)
{
    assert(data && strlen(operation) < sizeof(last_operation));
    ++calls;
    memcpy(last_operation, operation, strlen(operation) + 1);
    return operation_ok;
}
bool nm_esp_state_init(nm_esp_state *s, const nm_esp_config *c, yyjson_mut_val *data)
{
    (void)s;
    assert(c);
    return called("init", data);
}
bool nm_esp_state_updates(nm_esp_state *s, const nm_esp_config *c, yyjson_mut_val *data)
{
    (void)s;
    assert(c && yyjson_mut_is_arr(data));
    return called("updates", data);
}
bool nm_esp_state_alert(nm_esp_state *s, const nm_esp_config *c, esp_mqtt_client_handle_t client,
                        const char *op, yyjson_mut_val *data)
{
    (void)s;
    (void)client;
    assert(c);
    return called(op, data);
}
bool nm_esp_state_user_event(nm_esp_state *s, yyjson_mut_val *data)
{
    (void)s;
    return called("user", data);
}
bool nm_esp_state_ack(nm_esp_state *s, yyjson_mut_val *data)
{
    (void)s;
    return called("ack", data);
}
bool nm_esp_ota_confirm_from_backend(yyjson_mut_val *data)
{
    return called("health", data);
}
bool nm_processor_start_update(processor *agent, yyjson_mut_val *data)
{
    assert(agent);
    return called("update", data);
}
static void send(processor *agent, const char *route, const char *op, const char *body)
{
    command message = {0};
    int length = snprintf(message.topic, sizeof(message.topic), "%s/%s", route, op);
    assert(length > 0 && (size_t)length < sizeof(message.topic));
    message.body = (char *)body;
    nm_processor_dispatch(agent, &message);
}
int main(void)
{
    nm_esp_config config = {.auth_key = "test-key", .routing_id = "owned-route"};
    processor agent = {.config = &config, .poll_seconds = 60};
    const char *object = "{\"data\":{\"AuthKey\":\"test-key\",\"MonitorIPs\":[]}}";
    const char *protected_ops[] = {"processorInit", "processorQueueDic", "processorFirmwareUpdate",
                                   "processorFirmwareHealthAck"};
    for (size_t i = 0; i < 4; ++i) {
        unsigned before = calls, checks = verified;
        send(&agent, "other-route", protected_ops[i], object);
        assert(calls == before && verified == checks);
        valid_signature = false;
        send(&agent, "owned-route", protected_ops[i], object);
        assert(calls == before && verified == checks + 1);
        valid_signature = true;
        send(&agent, "owned-route", protected_ops[i], "{\"data\":{\"AuthKey\":\"wrong\"}}");
        assert(calls == before);
        send(&agent, "owned-route", protected_ops[i], object);
        assert(calls == before + 1);
    }
    assert(ready == 2 && health == 1);
    operation_ok = false;
    send(&agent, "owned-route", "processorInit", object);
    send(&agent, "owned-route", "processorFirmwareHealthAck", object);
    assert(ready == 2 && health == 1);
    operation_ok = true;
    const char *alerts[] = {"processorAlertFlag", "processorAlertSent", "processorResetAlerts"};
    for (size_t i = 0; i < 3; ++i) {
        send(&agent, "owned-route", alerts[i], "{\"data\":[1,2]}");
        assert(!strcmp(last_operation, alerts[i]));
    }
    send(&agent, "owned-route", "removePingInfos", "{\"data\":{}}");
    assert(!strcmp(last_operation, "ack"));
    send(&agent, "owned-route", "processorUserEvent", "{\"data\":{}}");
    assert(!strcmp(last_operation, "user"));
    send(&agent, "owned-route", "processorWakeUp", "{\"data\":{}}");
    assert(ready == 3);
    send(&agent, "owned-route", "processorConnect", "{\"data\":{\"NextRunInterval\":1001}}");
    assert(agent.poll_seconds == 2);
    const char *bad_intervals[] = {"0", "-1", "86400001", "\"1000\"", "null"};
    for (size_t i = 0; i < 5; ++i) {
        char body[128];
        snprintf(body, sizeof(body), "{\"data\":{\"NextRunInterval\":%s}}", bad_intervals[i]);
        send(&agent, "owned-route", "processorConnect", body);
        assert(agent.poll_seconds == 2);
    }
    unsigned before = calls;
    send(&agent, "owned-route", "unknown", object);
    send(&agent, "owned-route", "processorInit", "{}");
    send(&agent, "owned-route", "removePingInfos", "{broken");
    send(&agent, "owned-route", "processorAlertFlag", "{\"data\":{}}");
    assert(calls == before);
    puts("Command dispatcher: all 11 operations, signature gating, AuthKey, routing and malformed "
         "input passed");
    return 0;
}
