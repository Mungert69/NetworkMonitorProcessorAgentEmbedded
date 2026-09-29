#ifndef NM_MONITOR_CORE_H
#define NM_MONITOR_CORE_H
#include <stdbool.h>
#include <stdint.h>
#include "yyjson.h"
#include "monitor_numbers.h"

/* Pre-refactor host regression reference. Not part of the ESP-IDF build.
 * Documents own their values. No integer is routed through a double. */
typedef struct { yyjson_mut_doc *doc; } nm_monitor_core;
typedef bool (*nm_monitor_save)(void *context, yyjson_mut_val *snapshot);
bool nm_monitor_u64(yyjson_mut_val *value, uint64_t *out);
bool nm_monitor_i32(yyjson_mut_val *value, int32_t *out);
bool nm_monitor_u32(yyjson_mut_val *value, uint32_t *out);
bool nm_monitor_open(nm_monitor_core *core, yyjson_mut_val *snapshot,
                     yyjson_mut_val *legacy_data, yyjson_mut_val *legacy_monitors);
void nm_monitor_close(nm_monitor_core *core);
yyjson_mut_val *nm_monitor_root(const nm_monitor_core *core);
yyjson_mut_val *nm_monitor_data(const nm_monitor_core *core);
yyjson_mut_val *nm_monitor_hosts(const nm_monitor_core *core);
yyjson_mut_val *nm_monitor_info(const nm_monitor_core *core, int32_t id);
bool nm_monitor_reconcile(nm_monitor_core *core, const char *app_id, const char *timestamp);
bool nm_monitor_clone(nm_monitor_core *out, const nm_monitor_core *source);
bool nm_monitor_commit(nm_monitor_core *current, nm_monitor_core *candidate,
                       nm_monitor_save save, void *context);
bool nm_monitor_ack(nm_monitor_core *candidate, yyjson_mut_val *response);
bool nm_monitor_init(nm_monitor_core *candidate, yyjson_mut_val *request,
                     const char *app_id, unsigned max_hosts, const char *timestamp);
bool nm_monitor_updates(nm_monitor_core *candidate, yyjson_mut_val *updates,
                        const char *app_id, unsigned max_hosts, const char *timestamp);
bool nm_monitor_alert(nm_monitor_core *candidate, const char *operation,
                      yyjson_mut_val *ids, const char *app_id);
bool nm_monitor_user_event(nm_monitor_core *candidate, yyjson_mut_val *event);
bool nm_monitor_probe(nm_monitor_core *candidate, yyjson_mut_val *host,
                      bool up, uint16_t rtt, const char *status, const char *message,
                      const char *timestamp, uint32_t date_sent);
/* Signed .NET counters are unchecked int32 arithmetic, not C signed overflow. */
int32_t nm_monitor_add_i32(int32_t left, int32_t right);
#endif
