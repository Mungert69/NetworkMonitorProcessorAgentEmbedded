#ifndef NM_MONITOR_BATCH_H
#define NM_MONITOR_BATCH_H
#include "nm_esp.h"

/* Borrowed config/model. Returns an owned empty .NET monitoring payload for the
 * data batcher and status-alert codec. No storage access or model mutations. */
yyjson_mut_doc *nm_monitor_batch_payload(const nm_esp_config *config, const nm_model *model);
/* Synchronous bounded publication of a borrowed immutable/COW model view.
 * Combines monitor chunks according to exact encoded wire size, independently
 * of backing-store block/segment sizes. proceed/context are borrowed, may be
 * NULL, and are never retained. Publish acceptance does not acknowledge samples. */
bool nm_monitor_batch_send(const nm_esp_config *config, esp_mqtt_client_handle_t client,
                           const nm_model *model, bool (*proceed)(void *), void *context);
#endif
