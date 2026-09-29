#ifndef NM_MESSAGE_PUBLISH_H
#define NM_MESSAGE_PUBLISH_H
#include "nm_esp.h"

typedef enum {
    NM_MESSAGE_JSON,
    NM_MESSAGE_BROTLI_BASE64,
    NM_MESSAGE_BROTLI_TUPLE
} nm_message_encoding;

/* Borrows the input payload; serializes and releases all temporary storage
 * before returning. Publish acceptance is NOT a removePingInfos acknowledgement. */
bool nm_esp_publish_event(const nm_esp_config *config, esp_mqtt_client_handle_t client,
                          const char *topic, yyjson_mut_val *payload, nm_message_encoding encoding,
                          const char *type);
/* Returns the exact encoded wire length, or 0 if encoding/allocation fails.
 * The result is independent of the broker's publish acceptance. */
size_t nm_esp_event_wire_size(const nm_esp_config *config, yyjson_mut_val *payload,
                              nm_message_encoding encoding, const char *type);
#endif
