#include "ble_decoder_internal.h"
#include <stdio.h>
#include <string.h>
static bool accepts(nm_ble_bytes p, bool has_key, uint8_t first)
{
    (void)has_key;
    (void)first;
    return p.length >= 24 && p.bytes[0] == 5;
}
static unsigned be(const uint8_t *p)
{
    return ((unsigned)p[0] << 8) | p[1];
}
static void value(nm_ble_output *o, const char *label, double v, const char *unit, bool na)
{
    nm_ble_output_reading(o, label, 1, v, !na);
    if (na)
        nm_ble_output_append(o, "%s: NA\n", label);
    else {
        char number[64];
        snprintf(number, sizeof(number), "%.4f", v);
        size_t n = strlen(number);
        while (n && number[n - 1] == '0')
            number[--n] = 0;
        if (n && number[n - 1] == '.')
            number[--n] = 0;
        nm_ble_output_append(o, "%s: %s%s%s\n", label, number, *unit ? " " : "", unit);
    }
}
static bool decode(nm_ble_bytes p, const char *address, const uint8_t *key, size_t n,
                   nm_ble_output *o)
{
    (void)key;
    (void)n;
    if (!accepts(p, false, 0)) {
        nm_ble_output_append(o, "Ruuvi decoder requires a 24-byte RAWv2 (format 5) payload");
        return false;
    }
    nm_ble_output_append(o, "BLE address: %s\nBLE device: RuuviTag (RAWv2)\n", address);
    const char *labels[] = {"Temperature",    "Humidity",       "Pressure",
                            "Acceleration X", "Acceleration Y", "Acceleration Z"};
    const char *units[] = {"°C", "%", "Pa", "g", "g", "g"};
    const double scales[] = {.005, .0025, 1, .001, .001, .001};
    for (unsigned i = 0; i < 6; i++) {
        unsigned raw = be(p.bytes + 1 + 2 * i);
        bool sign = i == 0 || i >= 3;
        int v = sign && raw >= 32768 ? (int)raw - 65536 : (int)raw;
        value(o, labels[i], v * scales[i] + (i == 2 ? 50000 : 0), units[i],
              raw == (sign ? 32768 : 65535));
    }
    unsigned power = be(p.bytes + 13), battery = power >> 5, tx = power & 31;
    value(o, "Battery voltage", (battery + 1600) / 1000.0, "V", battery == 2047);
    value(o, "TX power", (int)tx * 2 - 40, "dBm", tx == 31);
    value(o, "Movement counter", p.bytes[15], "", p.bytes[15] == 255);
    value(o, "Measurement sequence", be(p.bytes + 16), "", be(p.bytes + 16) == 65535);
    bool na = true;
    for (unsigned i = 18; i < 24; i++)
        if (p.bytes[i] != 255)
            na = false;
    if (na)
        nm_ble_output_append(o, "Device MAC: NA\n");
    else
        nm_ble_output_append(o, "Device MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", p.bytes[18],
                             p.bytes[19], p.bytes[20], p.bytes[21], p.bytes[22], p.bytes[23]);
    return !o->failed;
}
const nm_ble_decoder nm_ble_ruuvi_decoder = {"ruuvi", 0x0499, 0, false, nm_ble_no_key_error,
                                             accepts, decode};
