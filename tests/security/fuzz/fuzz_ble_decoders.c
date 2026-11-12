#include "ble_decoder.h"
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2 || size > 255)
        return 0;
    static const char *formats[] = {"victron", "ruuvi", "bthome"};
    const nm_ble_decoder *decoder = nm_ble_decoder_find(formats[data[0] % 3]);
    if (!decoder)
        return 0;
    const uint8_t *key = size >= 17 ? data + size - 16 : NULL;
    size_t key_length = key ? 16 : 0;
    char output[4096];
    nm_ble_metric_selection selection = {.requested = "temperature"};
    (void)nm_ble_decoder_decode_metric(decoder, (nm_ble_bytes){data + 1, size - 1},
                                       data[0] & 0x80 ? "manufacturer" : "raw_input",
                                       "AA:BB:CC:DD:EE:FF", key, key_length, output,
                                       sizeof(output), &selection);
    return 0;
}
