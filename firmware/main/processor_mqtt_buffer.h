#ifndef NM_PROCESSOR_MQTT_BUFFER_H
#define NM_PROCESSOR_MQTT_BUFFER_H

#include "nm_command_limits.h"
#include <stdint.h>
#include <string.h>

/* MQTT 3.1.1 CONNECT is built in one output buffer. Allow room for its fixed
 * and variable headers plus the three length-prefixed credential fields.
 * The 20 KiB floor makes ESP-IDF's malloc prefer PSRAM with this project's
 * 16 KiB CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL threshold. Zero means invalid. */
enum {
    NM_MQTT_OUT_MIN = 20 * 1024,
    NM_MQTT_OUT_MAX = NM_ESP_MAX_COMMAND + 1024,
    NM_MQTT_CONNECT_OVERHEAD = 64,
};

static inline int nm_mqtt_out_size(const char *client_id, const char *username,
                                   const char *password)
{
    const char *fields[] = {client_id, username, password};
    size_t required = NM_MQTT_CONNECT_OVERHEAD;
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
        if (!fields[i]) return 0;
        size_t length = strlen(fields[i]);
        if (length > UINT16_MAX || length > NM_MQTT_OUT_MAX - required)
            return 0;
        required += length;
    }
    return (int)(required < NM_MQTT_OUT_MIN ? NM_MQTT_OUT_MIN : required);
}

#endif
