#ifndef NM_BLE_DECODER_H
#define NM_BLE_DECODER_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/* Immutable registry entries are borrowed for the life of the process. Payload,
 * key and address are borrowed only during the call. Output is caller-owned;
 * failed decode returns only an error, never partially authenticated readings. */
typedef struct nm_ble_decoder nm_ble_decoder;
typedef struct {
    const uint8_t *bytes;
    size_t length;
} nm_ble_bytes;
typedef struct {
    const char *requested; /* Borrowed only during decode. */
    unsigned matches;
    bool available;
    double value;
} nm_ble_metric_selection;
typedef struct {
    char *text;
    size_t capacity, used;
    bool failed;
    nm_ble_metric_selection *selection; /* Optional synchronous numeric sink. */
} nm_ble_output;
struct nm_ble_decoder {
    const char *format;
    int manufacturer_id;
    uint16_t service_uuid;
    bool requires_key;
    const char *(*key_error)(size_t length);
    bool (*accepts)(nm_ble_bytes payload, bool has_key, uint8_t key_first);
    bool (*decode)(nm_ble_bytes payload, const char *address, const uint8_t *key, size_t key_length,
                   nm_ble_output *output);
};
const nm_ble_decoder *nm_ble_decoder_find(const char *format);
const char *nm_ble_decoder_key_error(const nm_ble_decoder *decoder, size_t length);
bool nm_ble_decoder_select(const nm_ble_decoder *decoder, nm_ble_bytes input,
                           const char *payload_type, nm_ble_bytes *selected);
bool nm_ble_decoder_decode(const nm_ble_decoder *decoder, nm_ble_bytes input,
                           const char *payload_type, const char *address, const uint8_t *key,
                           size_t key_length, char *output, size_t capacity);
bool nm_ble_decoder_decode_metric(const nm_ble_decoder *decoder, nm_ble_bytes input,
                                  const char *payload_type, const char *address, const uint8_t *key,
                                  size_t key_length, char *output, size_t capacity,
                                  nm_ble_metric_selection *selection);
void nm_ble_output_reading(nm_ble_output *output, const char *label, unsigned occurrence,
                           double value, bool available);
void nm_ble_output_append(nm_ble_output *output, const char *format, ...);
#endif
