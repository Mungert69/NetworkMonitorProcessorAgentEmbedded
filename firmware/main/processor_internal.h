#ifndef NM_PROCESSOR_INTERNAL_H
#define NM_PROCESSOR_INTERNAL_H
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "nm_esp.h"
#include <stdatomic.h>
/* The processor task owns state and command bodies after dequeue.
 * MQTT callback owns bodies until successful enqueue. OTA copies command fields
 * into its own job. Cross-task flags are atomic; subscriptions is callback-only. */
typedef struct {
    char topic[160];
    char *body;
} command;

/* Broker sends host additions as individual commands. Allow a full 50-host
 * burst plus control/ack messages while the processor task is probing. Each
 * slot stores only a topic and an owned body pointer, not a command body. */
enum { NM_ESP_COMMAND_QUEUE_CAPACITY = 64 };

typedef struct {
    const nm_esp_config *config;
    esp_mqtt_client_handle_t client;
    QueueHandle_t queue;
    nm_esp_state *state;
    atomic_bool connected;
    atomic_bool updating;
    atomic_bool firmware_status_sent;
    atomic_uint mqtt_queue_high_water;
    atomic_uint mqtt_queue_drops;
    atomic_uint mqtt_allocation_failures;
    unsigned subscriptions;
    unsigned poll_seconds;
    TickType_t last_resource_tick;
} processor;

static inline const char *string_field(yyjson_mut_val *object, const char *name)
{
    yyjson_mut_val *value = yyjson_mut_obj_get(object, name);
    return yyjson_mut_is_str(value) ? yyjson_mut_get_str(value) : NULL;
}

bool nm_processor_publish_ready(processor *agent, bool ready);
bool nm_processor_publish_firmware_status(processor *agent);
void nm_processor_dispatch(processor *agent, const command *message);
void nm_processor_mqtt_event(void *arg, esp_event_base_t base, int32_t id, void *event_data);
bool nm_processor_start_update(processor *agent, yyjson_mut_val *data);
#endif
