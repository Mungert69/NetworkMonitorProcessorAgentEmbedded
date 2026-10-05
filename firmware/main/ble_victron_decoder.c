#include "ble_decoder_internal.h"
static bool record(nm_ble_bytes p, nm_ble_bytes *r)
{
    size_t offset = p.length && p.bytes[0] == 0x10 ? 4 : 0;
    if (p.length < offset + 5 || p.length - offset - 4 > 16)
        return false;
    *r = (nm_ble_bytes){p.bytes + offset, p.length - offset};
    return true;
}
static bool accepts(nm_ble_bytes p, bool has_key, uint8_t first)
{
    nm_ble_bytes r;
    return record(p, &r) && nm_ble_victron_record_supported(r.bytes[0]) &&
           (!has_key || r.bytes[3] == first);
}
static bool decode(nm_ble_bytes p, const char *address, const uint8_t *key, size_t n,
                   nm_ble_output *o)
{
    nm_ble_bytes r;
    if (!record(p, &r)) {
        nm_ble_output_append(o, "Invalid Victron instant-readout record");
        return false;
    }
    if (n != 16) {
        nm_ble_output_append(o, "Victron AES-128 key is missing: set monitor Password to the "
                                "16-byte key (32 hex digits)");
        return false;
    }
    if (r.bytes[3] != key[0]) {
        nm_ble_output_append(o, "Victron key-check mismatch");
        return false;
    }
    uint8_t nonce[16] = {r.bytes[1], r.bytes[2]}, stream[16], plain[16];
    if (!nm_ble_aes_block(key, n, nonce, stream)) {
        nm_ble_output_append(o, "Victron AES operation failed");
        return false;
    }
    for (size_t i = 0; i < r.length - 4; i++)
        plain[i] = r.bytes[i + 4] ^ stream[i];
    (void)address;
    if (!nm_ble_victron_record_supported(r.bytes[0])) {
        nm_ble_output_append(o, "Victron plaintext: ");
        for (size_t i = 0; i < r.length - 4; i++)
            nm_ble_output_append(o, "%02X", plain[i]);
        return !o->failed;
    }
    return nm_ble_victron_record_decode(r.bytes[0], (nm_ble_bytes){plain, r.length - 4}, o);
}
const nm_ble_decoder nm_ble_victron_decoder = {"victron", 0x02e1, 0, true, nm_ble_aes128_key_error,
                                               accepts,   decode};
