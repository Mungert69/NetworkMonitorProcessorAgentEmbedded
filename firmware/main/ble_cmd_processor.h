#ifndef NM_BLE_CMD_PROCESSOR_H
#define NM_BLE_CMD_PROCESSOR_H
#include "ble_scanner.h"
#include "cmd_result.h"
typedef struct {
    bool listen, injected;
    char address[NM_BLE_ADDRESS_TEXT_SIZE], format[16], payload[16], metric[64];
    uint8_t key[32], uuid[16], raw[NM_BLE_ADVERTISEMENT_MAX];
    size_t key_length, uuid_length, raw_length;
    int company;
    unsigned nonce_length, tag_length, timeout_ms;
    bool nonce_at_end;
} nm_ble_command;
/* Caller-owned value request. No pointers into argument text retained. */
bool nm_ble_cmd_parse(const char *arguments, bool listen, nm_ble_command *request,
                      const char **error);
const char *nm_ble_cmd_help(bool listen);
/* Acquires/releases an immutable shared snapshot; never owns the radio or model.
 * Returns owned output; cancellation is borrowed for this synchronous call. */
nm_cmd_result nm_ble_cmd_run(const nm_ble_command *request, const atomic_bool *cancellation);
#endif
