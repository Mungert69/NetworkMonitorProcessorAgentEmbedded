#include "ble_decoder_internal.h"
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
typedef struct {
    uint8_t id, width;
    const char *label;
    bool sign, binary;
    double scale;
    const char *unit;
} object;
static const object objects[] = {
    {0x00, 1, "Packet id", false, false, 1, ""},
    {0x01, 1, "Battery", false, false, 1, "%"},
    {0x02, 2, "Temperature", true, false, 0.01, "°C"},
    {0x03, 2, "Humidity", false, false, 0.01, "%"},
    {0x04, 3, "Pressure", false, false, 0.01, "hPa"},
    {0x05, 3, "Illuminance", false, false, 0.01, "lx"},
    {0x06, 2, "Mass", false, false, 0.01, "kg"},
    {0x07, 2, "Mass", false, false, 0.01, "lb"},
    {0x08, 2, "Dewpoint", true, false, 0.01, "°C"},
    {0x09, 1, "Count", false, false, 1, ""},
    {0x0a, 3, "Energy", false, false, 0.001, "kWh"},
    {0x0b, 3, "Power", false, false, 0.01, "W"},
    {0x0c, 2, "Voltage", false, false, 0.001, "V"},
    {0x0d, 2, "PM2.5", false, false, 1, "µg/m³"},
    {0x0e, 2, "PM10", false, false, 1, "µg/m³"},
    {0x12, 2, "CO2", false, false, 1, "ppm"},
    {0x13, 2, "TVOC", false, false, 1, "µg/m³"},
    {0x14, 2, "Moisture", false, false, 0.01, "%"},
    {0x2e, 1, "Humidity", false, false, 1, "%"},
    {0x2f, 1, "Moisture", false, false, 1, "%"},
    {0x3d, 2, "Count", false, false, 1, ""},
    {0x3e, 4, "Count", false, false, 1, ""},
    {0x3f, 2, "Rotation", true, false, 0.1, "°"},
    {0x40, 2, "Distance", false, false, 1, "mm"},
    {0x41, 2, "Distance", false, false, 0.1, "m"},
    {0x42, 3, "Duration", false, false, 0.001, "s"},
    {0x43, 2, "Current", false, false, 0.001, "A"},
    {0x44, 2, "Speed", false, false, 0.01, "m/s"},
    {0x45, 2, "Temperature", true, false, 0.1, "°C"},
    {0x46, 1, "UV index", false, false, 0.1, ""},
    {0x47, 2, "Volume", false, false, 0.1, "L"},
    {0x48, 2, "Volume", false, false, 1, "mL"},
    {0x49, 2, "Volume flow rate", false, false, 0.001, "m³/hr"},
    {0x4a, 2, "Voltage", false, false, 0.1, "V"},
    {0x4b, 3, "Gas", false, false, 0.001, "m³"},
    {0x4c, 4, "Gas", false, false, 0.001, "m³"},
    {0x4d, 4, "Energy", false, false, 0.001, "kWh"},
    {0x4e, 4, "Volume", false, false, 0.001, "L"},
    {0x4f, 4, "Water", false, false, 0.001, "L"},
    {0x50, 4, "Timestamp", false, false, 1, ""},
    {0x51, 2, "Acceleration", false, false, 0.001, "m/s²"},
    {0x52, 2, "Gyroscope", false, false, 0.001, "°/s"},
    {0x55, 4, "Volume storage", false, false, 0.001, "L"},
    {0x56, 2, "Conductivity", false, false, 1, "µS/cm"},
    {0x57, 1, "Temperature", true, false, 1, "°C"},
    {0x58, 1, "Temperature", true, false, 0.35, "°C"},
    {0x59, 1, "Count", true, false, 1, ""},
    {0x5a, 2, "Count", true, false, 1, ""},
    {0x5b, 4, "Count", true, false, 1, ""},
    {0x5c, 4, "Power", true, false, 0.01, "W"},
    {0x5d, 2, "Current", true, false, 0.001, "A"},
    {0x5e, 2, "Direction", false, false, 0.01, "°"},
    {0x5f, 2, "Precipitation", false, false, 0.1, "mm"},
    {0x60, 1, "Channel", false, false, 1, ""},
    {0x61, 2, "Rotational speed", false, false, 1, "rpm"},
    {0x62, 4, "Speed", true, false, 0.000001, "m/s"},
    {0x63, 4, "Acceleration", true, false, 0.000001, "m/s²"},
    {0x64, 1, "Light level", false, false, 1, ""},
    {0x65, 1, "Settings revision", false, false, 1, ""},
    {0xf0, 2, "Device type id", false, false, 1, ""},
    {0xf1, 4, "Firmware version", false, false, 1, ""},
    {0xf2, 3, "Firmware version", false, false, 1, ""},
    {0x0f, 1, "Boolean", false, true, 1, ""},
    {0x10, 1, "Power state", false, true, 1, ""},
    {0x11, 1, "Opening", false, true, 1, ""},
};
static const object *find(uint8_t id)
{
    for (size_t i = 0; i < sizeof(objects) / sizeof(objects[0]); i++)
        if (objects[i].id == id)
            return &objects[i];
    return NULL;
}
static bool accepts(nm_ble_bytes p, bool has_key, uint8_t first)
{
    (void)has_key;
    (void)first;
    return p.length && p.bytes[0] >> 5 == 2;
}
static bool utf8(nm_ble_bytes p)
{
    for (size_t i = 0; i < p.length;) {
        uint32_t c = p.bytes[i++], min = 0;
        unsigned n = 0;
        if (c < 128)
            continue;
        if (c >= 0xc2 && c <= 0xdf) {
            n = 1;
            min = 128;
            c &= 31;
        } else if (c >= 0xe0 && c <= 0xef) {
            n = 2;
            min = 2048;
            c &= 15;
        } else if (c >= 0xf0 && c <= 0xf4) {
            n = 3;
            min = 65536;
            c &= 7;
        } else
            return false;
        if (n > p.length - i)
            return false;
        while (n--) {
            uint8_t b = p.bytes[i++];
            if ((b & 0xc0) != 0x80)
                return false;
            c = (c << 6) | (b & 63);
        }
        if (c < min || c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff))
            return false;
    }
    return true;
}
static bool fail(nm_ble_output *o, const char *message, uint8_t id)
{
    o->used = 0;
    o->text[0] = 0;
    nm_ble_output_append(o, "%s (object 0x%02X)", message, id);
    return false;
}
static void label(nm_ble_output *o, const char *name, unsigned count)
{
    if (count > 1)
        nm_ble_output_append(o, "%s %u: ", name, count);
    else
        nm_ble_output_append(o, "%s: ", name);
}
static bool append_objects(nm_ble_bytes p, nm_ble_output *o)
{
    /* Object counts are bounded by the 255-byte advertisement. Labels shared by
     * several IDs count together, as in .NET. */
    uint8_t seen[256] = {0};
    static const char *binary[] = {"Battery low", "Battery charging", "Carbon monoxide",
                                   "Cold",        "Connectivity",     "Door",
                                   "Garage door", "Gas detected",     "Heat",
                                   "Light",       "Lock unlocked",    "Moisture detected",
                                   "Motion",      "Moving",           "Occupancy",
                                   "Plug",        "Presence",         "Problem",
                                   "Running",     "Safety",           "Smoke",
                                   "Sound",       "Tamper",           "Vibration",
                                   "Window"};
    for (size_t pos = 0; pos < p.length;) {
        uint8_t id = p.bytes[pos++];
        const object *spec = find(id);
        const char *name = spec ? spec->label : id >= 0x15 && id <= 0x2d ? binary[id - 0x15] : NULL;
        char unit_label[48];
        if (spec && (!strcmp(spec->label, "Mass") || !strcmp(spec->label, "Distance") ||
                     !strcmp(spec->label, "Volume"))) {
            int n = snprintf(unit_label, sizeof(unit_label), "%s %s", spec->label, spec->unit);
            if (n < 0 || (size_t)n >= sizeof(unit_label))
                return fail(o, "BTHome label too long", id);
            name = unit_label;
        }
        if (id == 0x53 || id == 0x54 || id == 0x3b)
            name = id == 0x53 ? "Text" : id == 0x54 ? "Raw" : "Command (opcode/arguments)";
        if (id == 0x3a)
            name = "Button";
        if (id == 0x3c)
            name = "Dimmer";
        if (!name) {
            nm_ble_output_append(
                o, "Unsupported BTHome object: 0x%02X; remaining objects were not decoded.\n", id);
            return true;
        }
        unsigned count = 1;
        for (unsigned j = 0; j < 256; j++) {
            const object *other = find((uint8_t)j);
            const char *other_name = other                    ? other->label
                                     : j >= 0x15 && j <= 0x2d ? binary[j - 0x15]
                                                              : NULL;
            char other_label[48];
            if (other && (!strcmp(other->label, "Mass") || !strcmp(other->label, "Distance") ||
                          !strcmp(other->label, "Volume"))) {
                snprintf(other_label, sizeof(other_label), "%s %s", other->label, other->unit);
                other_name = other_label;
            }
            if (j == id || (other_name && !strcmp(other_name, name)))
                count += seen[j];
        }
        seen[id]++;
        size_t width = spec ? spec->width : id == 0x3c ? 2 : 1;
        if (id == 0x53 || id == 0x54 || id == 0x3b) {
            if (pos >= p.length)
                return fail(o, "Truncated BTHome object", id);
            width = p.bytes[pos++];
            if (id == 0x3b) {
                if (width & 0xe0)
                    return fail(o, "Unsupported BTHome command length bits", id);
                width++;
            }
        }
        if (width > p.length - pos)
            return fail(o, "Truncated BTHome object", id);
        if (id == 0x53 && !utf8((nm_ble_bytes){p.bytes + pos, width}))
            return fail(o, "Invalid BTHome UTF-8", id);
        uint32_t raw = 0;
        if (spec || (id >= 0x15 && id <= 0x2d))
            for (size_t j = 0; j < width; j++)
                raw |= (uint32_t)p.bytes[pos + j] << (8 * j);
        bool is_binary = (spec && spec->binary) || (id >= 0x15 && id <= 0x2d);
        if (is_binary && raw > 1)
            return fail(o, "Invalid BTHome binary value", id);
        if ((spec && id != 0xf1 && id != 0xf2) || is_binary) {
            int64_t v = spec && spec->sign && (raw & (UINT32_C(1) << (width * 8 - 1)))
                            ? (int64_t)raw - (INT64_C(1) << (width * 8))
                            : raw;
            nm_ble_output_reading(o, name, count, v * (spec ? spec->scale : 1), true);
        }
        if (id == 0x3a || id == 0x3c)
            nm_ble_output_reading(o, name, count, p.bytes[pos], true);
        if (id == 0x3c)
            nm_ble_output_reading(o, "Dimmer steps", count, p.bytes[pos + 1], true);
        label(o, name, count);
        if (id == 0x53) {
            /* Embedded NUL cannot be represented in the C diagnostic contract. */
            for (size_t j = 0; j < width; j++) {
                if (!p.bytes[pos + j])
                    nm_ble_output_append(o, "\\0");
                else
                    nm_ble_output_append(o, "%c", p.bytes[pos + j]);
            }
        } else if (id == 0x54 || id == 0x3b) {
            for (size_t j = 0; j < width; j++)
                nm_ble_output_append(o, "%02X", p.bytes[pos + j]);
        } else if (id == 0x3a) {
            static const char *events[] = {"none",
                                           "press",
                                           "double press",
                                           "triple press",
                                           "long press",
                                           "long double press",
                                           "long triple press"};
            uint8_t v = p.bytes[pos];
            if (v < 7)
                nm_ble_output_append(o, "%s", events[v]);
            else if (v == 128)
                nm_ble_output_append(o, "hold press");
            else
                nm_ble_output_append(o, "unknown event 0x%02X", v);
        } else if (id == 0x3c) {
            uint8_t v = p.bytes[pos];
            if (!v)
                nm_ble_output_append(o, "none");
            else if (v < 3)
                nm_ble_output_append(o, "rotate %s %u steps", v == 1 ? "left" : "right",
                                     p.bytes[pos + 1]);
            else
                nm_ble_output_append(o, "unknown event 0x%02X (%u steps)", v, p.bytes[pos + 1]);
        } else if (is_binary)
            nm_ble_output_append(o, "%s", raw ? "on" : "off");
        else if (id == 0xf1 || id == 0xf2) {
            for (size_t j = width; j > 0; j--)
                nm_ble_output_append(o, "%u%s", p.bytes[pos + j - 1], j > 1 ? "." : "");
        } else if (id == 0x50) {
            time_t timestamp = (time_t)raw;
            struct tm utc;
            char text[40];
            if (!gmtime_r(&timestamp, &utc) ||
                !strftime(text, sizeof(text), "%Y-%m-%dT%H:%M:%S.0000000+00:00", &utc))
                return fail(o, "BTHome timestamp out of range", id);
            nm_ble_output_append(o, "%s", text);
        } else {
            int64_t v = spec->sign && (raw & (UINT32_C(1) << (width * 8 - 1)))
                            ? (int64_t)raw - (INT64_C(1) << (width * 8))
                            : raw;
            char number[64];
            snprintf(number, sizeof(number), "%.6f", v * spec->scale);
            size_t end = strlen(number);
            while (end && number[end - 1] == '0')
                number[--end] = 0;
            if (end && number[end - 1] == '.')
                number[--end] = 0;
            nm_ble_output_append(o, "%s%s%s", number, *spec->unit ? " " : "", spec->unit);
        }
        nm_ble_output_append(o, "\n");
        pos += width;
        if (o->failed)
            return false;
    }
    return true;
}
static bool decode(nm_ble_bytes p, const char *address, const uint8_t *key, size_t n,
                   nm_ble_output *o)
{
    if (!accepts(p, false, 0)) {
        nm_ble_output_append(o, "BTHome requires a v2 device-information byte");
        return false;
    }
    uint8_t info = p.bytes[0], plain[255], combined[255];
    nm_ble_bytes objects_data = {p.bytes + 1, p.length - 1};
    uint32_t counter = 0;
    if (info & 1) {
        if (n != 16 || p.length < 9) {
            nm_ble_output_append(
                o, "Encrypted BTHome requires a 16-byte key, counter and authentication tag");
            return false;
        }
        unsigned mac[6];
        int used = 0;
        if (!address ||
            sscanf(address, "%2x:%2x:%2x:%2x:%2x:%2x%n", &mac[0], &mac[1], &mac[2], &mac[3],
                   &mac[4], &mac[5], &used) != 6 ||
            used != 17 || address[used]) {
            nm_ble_output_append(o,
                                 "Encrypted BTHome requires the device's six-byte BLE MAC address");
            return false;
        }
        uint8_t nonce[13];
        for (unsigned i = 0; i < 6; i++)
            nonce[i] = (uint8_t)mac[i];
        nonce[6] = 0xd2;
        nonce[7] = 0xfc;
        nonce[8] = info;
        memcpy(nonce + 9, p.bytes + p.length - 8, 4);
        for (unsigned i = 0; i < 4; i++)
            counter |= (uint32_t)nonce[9 + i] << (8 * i);
        size_t cipher_length = p.length - 9;
        memcpy(combined, p.bytes + 1, cipher_length);
        memcpy(combined + cipher_length, p.bytes + p.length - 4, 4);
        if (!nm_ble_ccm_decrypt(key, nonce, (nm_ble_bytes){combined, cipher_length + 4}, plain,
                                sizeof(plain))) {
            nm_ble_output_append(
                o, "BTHome authentication failed: check key, device address and packet integrity");
            return false;
        }
        objects_data = (nm_ble_bytes){plain, cipher_length};
    }
    nm_ble_output_append(
        o, "BLE address: %s\nBLE protocol: BTHome v2\nEncrypted: %s\nTrigger based: %s\n", address,
        info & 1 ? "yes" : "no", info & 4 ? "yes" : "no");
    if (info & 1)
        nm_ble_output_append(o, "Encryption counter: %lu\n", (unsigned long)counter);
    return append_objects(objects_data, o);
}
const nm_ble_decoder nm_ble_bthome_decoder = {
    "bthome", -1, 0xfcd2, false, nm_ble_aes128_key_error, accepts, decode};
