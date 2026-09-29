#ifndef NM_ESP_H
#define NM_ESP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "nm_json.h"
#include "monitor_model.h"
#include "mqtt_client.h"
#include "nm_command_limits.h"

enum { NM_ESP_MAX_PUBLICATION = 131072, NM_ESP_MAX_MONITORS = 150 };

typedef struct {
    yyjson_mut_doc *doc; /* Owns root and all borrowed configuration strings. */
    yyjson_mut_val *root;
    const char *wifi_ssid;
    const char *wifi_password;
    const char *broker_uri;
    const char *mqtt_username;
    const char *mqtt_password;
    const char *app_id;
    const char *auth_key;
    const char *source;
    const char *ota_ca_pem;
    unsigned max_monitors;
    unsigned max_pending_ping_infos;
    unsigned max_task_queue_size;
    unsigned max_outstanding_endpoint_operations;
    unsigned poll_seconds;
    bool is_quantum_capable;
    bool auth_device;
    bool wifi_setup;
    char routing_id[110];
} nm_esp_config;

/* Only observations may change host statistics. Local resource failures are
 * inconclusive and retried on a later cycle, never converted into packet loss. */
typedef enum { NM_PROBE_OBSERVATION, NM_PROBE_LOCAL_FAILURE } nm_probe_disposition;
typedef struct {
    bool ok;
    nm_probe_disposition disposition;
    unsigned elapsed_ms;
    char status[64];
    char message[256];
    /* Optional PSRAM-owned long diagnostic, transferred through the probe
     * executor and released with nm_esp_result_release(). */
    char *detail_message;
} nm_esp_result;
static inline void nm_esp_result_release(nm_esp_result *result)
{
    if (!result) return;
    free(result->detail_message);
    result->detail_message = NULL;
}

typedef struct nm_esp_state nm_esp_state;
/* Optional injected probe executor; see nm_probe_pool.h. */
typedef struct nm_probe_executor nm_probe_executor;

bool nm_esp_config_load(nm_esp_config *config);
bool nm_esp_serial_start(void);
bool nm_esp_reregister_request(void);
bool nm_esp_factory_reset_request(void);
bool nm_esp_serial_wifi_setup(nm_esp_config *config);
bool nm_esp_wifi_setup_complete(nm_esp_config *config);
bool nm_esp_maintenance_begin(void);
void nm_esp_maintenance_end(void);
/* Serial-console stop/start of the monitoring loop. The console task sets the
 * flag; the processor task stops starting cycles while it is set. The broker
 * link, command handling and firmware-status heartbeat keep running, so a
 * stopped device stays reachable and 'start' always works. RAM-only. */
void nm_esp_monitor_stop(void);
void nm_esp_monitor_start(void);
bool nm_esp_monitor_stopped(void);
bool nm_esp_storage_reset_monitoring(void);
/* Caller sets config->doc before binding its borrowed root. */
bool nm_esp_config_bind(nm_esp_config *config, yyjson_mut_val *root);
bool nm_esp_config_save(const nm_esp_config *config);
bool nm_esp_enroll(nm_esp_config *config);
bool nm_esp_wifi_connect(const nm_esp_config *config);
bool nm_esp_clock_sync(void);
bool nm_esp_ota_can_install(const char *url, const char *version, const char *sha256,
                            const char *request_id);
bool nm_esp_ota_install(const nm_esp_config *config, const char *url, const char *version,
                        const char *sha256, const char *request_id);
void nm_esp_ota_start_health_watchdog(void);
bool nm_esp_ota_pending(void);
bool nm_esp_ota_add_status_fields(yyjson_mut_doc *doc, yyjson_mut_val *data);
bool nm_esp_ota_confirm_from_backend(yyjson_mut_val *data);
void nm_esp_processor_run(const nm_esp_config *config);
bool nm_esp_endpoint_supported(const char *type);
/* Startup only, before probe tasks start. Never resets outstanding operation accounting. */
bool nm_esp_endpoint_configure_limit(unsigned limit);
nm_esp_result nm_esp_endpoint_run(const nm_monitor_record *monitor);
nm_esp_state *nm_esp_state_new(const nm_esp_config *config);
void nm_esp_state_free(nm_esp_state *state);
void nm_esp_state_set_yield(nm_esp_state *state, bool (*yield)(void *), void *context);
/* Takes ownership of executor (and its context); frees any previously set one.
 * When set, monitoring runs probes through it concurrently; when NULL, the
 * cycle probes monitors sequentially on the processor task. */
void nm_esp_state_set_probe_executor(nm_esp_state *state, nm_probe_executor *executor);
size_t nm_esp_state_monitor_count(const nm_esp_state *state);
bool nm_esp_state_init(nm_esp_state *state, const nm_esp_config *config, yyjson_mut_val *data);
bool nm_esp_state_updates(nm_esp_state *state, const nm_esp_config *config,
                          yyjson_mut_val *updates);
bool nm_esp_state_alert(nm_esp_state *state, const nm_esp_config *config,
                        esp_mqtt_client_handle_t client, const char *operation,
                        yyjson_mut_val *ids);
bool nm_esp_state_user_event(nm_esp_state *state, yyjson_mut_val *data);
/* Snapshot current RAM state. Runtime calls once after cycle jobs drain, never
 * per probe/command. Failure leaves live state intact for the next cycle. */
bool nm_esp_state_save(const nm_esp_state *state);
bool nm_esp_state_cycle(nm_esp_state *state, const nm_esp_config *config,
                        esp_mqtt_client_handle_t client);
bool nm_esp_state_ack(nm_esp_state *state, yyjson_mut_val *response);
bool nm_esp_storage_init(void);
yyjson_mut_doc *nm_esp_storage_load(const char *key);
bool nm_esp_storage_has_key(const char *key);
bool nm_esp_storage_save(const char *key, yyjson_mut_val *value);

#endif
