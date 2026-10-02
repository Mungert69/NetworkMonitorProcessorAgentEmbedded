#include "esp_crt_bundle.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nm_probe_pool.h"
#include "processor_internal.h"
#include "processor_mqtt_buffer.h"
#include <stdlib.h>
#include <string.h>

static const char *TAG = "nm_processor";
#ifdef NM_COMMAND_BENCHMARK
bool nm_command_benchmark_setup(nm_esp_state *state, const nm_esp_config *config);
void nm_command_benchmark_cycle(void);
#endif
/* Called at safe probe/publication checkpoints; dispatch never starts another cycle. */
static bool yield_commands(void *context)
{
    processor *agent = context;
    TickType_t now = xTaskGetTickCount();
    if ((TickType_t)(now - agent->last_resource_tick) >= pdMS_TO_TICKS(10000)) {
        ESP_LOGI(TAG,
                 "resources phase=active internal_free=%u internal_min=%u "
                 "psram_free=%u psram_min=%u mqtt_queue=%u mqtt_queue_peak=%u "
                 "mqtt_queue_drops=%u mqtt_alloc_failures=%u",
                 (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
                 (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL),
                 (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),
                 (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_SPIRAM),
                 (unsigned)uxQueueMessagesWaiting(agent->queue),
                 atomic_load(&agent->mqtt_queue_high_water), atomic_load(&agent->mqtt_queue_drops),
                 atomic_load(&agent->mqtt_allocation_failures));
        agent->last_resource_tick = now;
    }
    command incoming;
    while (!agent->updating && xQueueReceive(agent->queue, &incoming, 0) == pdTRUE) {
        nm_processor_dispatch(agent, &incoming);
        free(incoming.body);
    }
    nm_processor_cmd_poll(agent);
    return agent->connected && !agent->updating;
}

void nm_esp_processor_run(const nm_esp_config *config)
{
    processor *agent = calloc(1, sizeof(*agent));
    if (!agent)
        return;
    atomic_init(&agent->connected, false);
    atomic_init(&agent->updating, false);
    atomic_init(&agent->firmware_status_sent, false);
    atomic_init(&agent->mqtt_queue_high_water, 0);
    atomic_init(&agent->mqtt_queue_drops, 0);
    atomic_init(&agent->mqtt_allocation_failures, 0);
    agent->config = config;
    agent->poll_seconds = config->poll_seconds;
    if (!nm_esp_storage_init()) {
        ESP_LOGE(TAG, "state storage unavailable; processor cannot run safely");
        goto fail;
    }
    agent->state = nm_esp_state_new(config);
    agent->queue = xQueueCreate(NM_ESP_COMMAND_QUEUE_CAPACITY, sizeof(command));
    if (!agent->state || !agent->queue) {
        ESP_LOGE(TAG, "processor allocation failed");
        goto fail;
    }
#ifdef NM_COMMAND_BENCHMARK
    if (!nm_command_benchmark_setup(agent->state, config))
        goto fail;
#endif
    nm_esp_state_set_yield(agent->state, yield_commands, agent);
    if (!nm_esp_endpoint_configure_limit(config->max_outstanding_endpoint_operations)) {
        ESP_LOGE(TAG, "cannot configure outstanding endpoint operation limit");
        goto fail;
    }
    ESP_LOGI(TAG, "shared DNS/ICMP outstanding operation limit=%u",
             config->max_outstanding_endpoint_operations);
    /* Optional: probe several endpoints concurrently. Single writer preserved:
     * workers only perform endpoint I/O, the processor task owns the model. */
    nm_probe_executor *probes = nm_probe_pool_freertos_create((int)config->max_task_queue_size);
    if (probes)
        nm_esp_state_set_probe_executor(agent->state, probes);
    else
        ESP_LOGW(TAG, "requested %u probe workers unavailable; probing sequentially",
                 config->max_task_queue_size);
    ESP_LOGI(TAG, "probe concurrency requested=%u effective=%d", config->max_task_queue_size,
             probes ? probes->capacity : 1);
    bool tls = strncmp(config->broker_uri, "mqtts://", 8) == 0;
    if (!tls && strncmp(config->broker_uri, "mqtt://", 7) != 0) {
        ESP_LOGE(TAG, "broker URI must use MQTT or MQTTS");
        goto fail;
    }
    int out_size =
        nm_mqtt_out_size(config->routing_id, config->mqtt_username, config->mqtt_password);
    if (!out_size) {
        ESP_LOGE(TAG, "MQTT CONNECT credentials exceed supported length");
        goto fail;
    }
    esp_mqtt_client_config_t mqtt = {
        .broker.address.uri = config->broker_uri,
        .credentials.username = config->mqtt_username,
        .credentials.client_id = config->routing_id,
        .credentials.authentication.password = config->mqtt_password,
        .session.keepalive = 120,
        .network.reconnect_timeout_ms = 2000,
        .buffer.size = NM_ESP_MAX_COMMAND + 1024,
        /* ESP-MQTT allocates separate receive/output buffers. Large incoming
         * signed inits need the receive buffer; publications are streamed. */
        .buffer.out_size = out_size,
    };
    ESP_LOGI(TAG, "MQTT input buffer=%d output buffer=%d", mqtt.buffer.size, out_size);
    if (tls)
        mqtt.broker.verification.crt_bundle_attach = esp_crt_bundle_attach;
    agent->client = esp_mqtt_client_init(&mqtt);
    if (!agent->client ||
        esp_mqtt_client_register_event(agent->client, ESP_EVENT_ANY_ID, nm_processor_mqtt_event,
                                       agent) != ESP_OK ||
        esp_mqtt_client_start(agent->client) != ESP_OK) {
        ESP_LOGE(TAG, "MQTT startup failed");
        goto fail;
    }
    ESP_LOGI(TAG,
             "processor started routing_id=%s max_monitors=%u pending_limit=%u command_queue=%u",
             config->routing_id, config->max_monitors, config->max_pending_ping_infos,
             (unsigned)NM_ESP_COMMAND_QUEUE_CAPACITY);
    TickType_t next_poll = xTaskGetTickCount() + pdMS_TO_TICKS(agent->poll_seconds * 1000);
    TickType_t next_health = xTaskGetTickCount() + pdMS_TO_TICKS(10000);
    for (;;) {
        command incoming;
        if (xQueueReceive(agent->queue, &incoming, pdMS_TO_TICKS(1000)) == pdTRUE) {
            nm_processor_dispatch(agent, &incoming);
            free(incoming.body);
            TickType_t current = xTaskGetTickCount();
            TickType_t interval = pdMS_TO_TICKS(agent->poll_seconds * 1000);
            if ((int32_t)(next_poll - current) > (int32_t)interval)
                next_poll = current + interval;
        }
        nm_processor_cmd_poll(agent);
        TickType_t now = xTaskGetTickCount();
        bool pending = nm_esp_ota_pending();
        if ((pending || !agent->firmware_status_sent) && agent->connected && !agent->updating &&
            (int32_t)(now - next_health) >= 0) {
            nm_processor_publish_firmware_status(agent);
            next_health = now + pdMS_TO_TICKS(10000);
        }
        if (agent->connected && !agent->updating && !pending && !nm_esp_monitor_stopped() &&
            (int32_t)(now - next_poll) >= 0) {
            nm_processor_publish_ready(agent, false);
            bool cycle_ok = nm_esp_state_cycle(agent->state, config, agent->client);
            if (!cycle_ok)
                ESP_LOGW(TAG, "monitor cycle failed or paused");
#ifdef NM_COMMAND_BENCHMARK
            if (cycle_ok)
                nm_command_benchmark_cycle();
#endif
            /* Per-cycle resource probe: heap headroom and the tightest task
             * stack high-water marks, so a concurrent-probe build can be
             * validated against real device RAM. All values are bytes. */
            ESP_LOGI(TAG,
                     "resources internal_free=%u internal_min=%u largest_internal=%u "
                     "psram_free=%u psram_min=%u proc_stack_min=%u worker_stack_min=%u "
                     "mqtt_queue=%u mqtt_queue_peak=%u mqtt_queue_drops=%u "
                     "mqtt_alloc_failures=%u",
                     (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
                     (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL),
                     (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL),
                     (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),
                     (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_SPIRAM),
                     (unsigned)uxTaskGetStackHighWaterMark(NULL),
                     (unsigned)nm_probe_pool_worker_stack_free(probes),
                     (unsigned)uxQueueMessagesWaiting(agent->queue),
                     atomic_load(&agent->mqtt_queue_high_water),
                     atomic_load(&agent->mqtt_queue_drops),
                     atomic_load(&agent->mqtt_allocation_failures));
            if (!agent->updating)
                nm_processor_publish_ready(agent, true);
            next_poll = xTaskGetTickCount() + pdMS_TO_TICKS(agent->poll_seconds * 1000);
        }
    }
fail:
    if (agent->client) {
        esp_mqtt_client_stop(agent->client);
        esp_mqtt_client_destroy(agent->client);
    }
    if (agent->queue) {
        command pending_command;
        while (xQueueReceive(agent->queue, &pending_command, 0) == pdTRUE)
            free(pending_command.body);
        vQueueDelete(agent->queue);
    }
    nm_esp_state_free(agent->state);
    free(agent);
}
