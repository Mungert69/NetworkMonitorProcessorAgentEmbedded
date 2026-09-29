#ifndef NM_COMMAND_LIMITS_H
#define NM_COMMAND_LIMITS_H

/* Keep the signed limit in sync with EcdsaProcessorCommandSigner. The MQTT
 * limit includes base64 expansion, signature, and the CloudEvent envelope. */
enum {
    NM_ESP_MAX_SIGNED_PAYLOAD = 256 * 1024,
    NM_ESP_MAX_COMMAND = 384 * 1024,
    NM_ESP_MAX_ENROLLMENT_COMMAND = 64 * 1024
};

#endif
