#include "ble_decoder_internal.h"
#include <stdint.h>
typedef struct {
    const char *label;
    unsigned bit, width;
    bool sign;
    double scale;
    const char *unit;
    uint32_t na;
    double add;
    bool cell;
} field;
#define F(l, b, w, s, k, u, n, a) {l, b, w, s, k, u, n, a, false}
#define STATE F("Device state", 0, 8, false, 1, "", 255, 0)
#define ERROR F("Charger error", 8, 8, false, 1, "", 255, 0)
#define V(b, l) F(l, b, 16, true, .01, "V", 0x7fff, 0)
#define I(b, l) F(l, b, 16, true, .1, "A", 0x7fff, 0)
#define T(b) F("Battery temperature", b, 7, false, 1, "°C", 127, -40)
/* UINT32_MAX denotes no sentinel only for fields narrower than 32 bits.
 * Flags/off-reason fields use width 32 and are never unavailable. */
static const field fields_1[] = {V(16, "Battery voltage"),
                                 I(32, "Battery current"),
                                 F("Yield today", 48, 16, false, .01, "kWh", 65535, 0),
                                 F("PV power", 64, 16, false, 1, "W", 65535, 0),
                                 STATE,
                                 ERROR};
static const field fields_2[] = {F("Time to go", 0, 16, false, 1, "min", 65535, 0),
                                 V(16, "Battery voltage"),
                                 F("Alarm reason", 32, 16, false, 1, "", UINT32_MAX, 0),
                                 F("Aux input", 64, 2, false, 1, "", 3, 0),
                                 F("Battery current", 66, 22, true, .001, "A", 0x3fffff, 0),
                                 F("Consumed Ah", 88, 20, false, -.1, "Ah", 0xfffff, 0),
                                 F("State of charge", 108, 10, false, .1, "%", 1023, 0)};
static const field fields_3[] = {STATE,
                                 F("Alarm reason", 8, 16, false, 1, "", UINT32_MAX, 0),
                                 V(24, "Battery voltage"),
                                 F("AC apparent power", 40, 16, false, 1, "VA", 65535, 0),
                                 F("AC voltage", 56, 15, false, .01, "V", 0x7fff, 0),
                                 F("AC current", 71, 11, false, .1, "A", 2047, 0)};
static const field fields_4[] = {
    STATE, ERROR, F("Input voltage", 16, 16, false, .01, "V", 65535, 0), V(32, "Output voltage"),
    F("Off reason", 48, 32, false, 1, "", UINT32_MAX, 0)};
static const field fields_5[] = {F("BMS flags", 0, 32, false, 1, "", UINT32_MAX, 0),
                                 F("SmartLithium error", 32, 16, false, 1, "", UINT32_MAX, 0),
                                 {"Cell 1 voltage", 48, 7, false, .01, "V", 127, 2.6, true},
                                 {"Cell 2 voltage", 55, 7, false, .01, "V", 127, 2.6, true},
                                 {"Cell 3 voltage", 62, 7, false, .01, "V", 127, 2.6, true},
                                 {"Cell 4 voltage", 69, 7, false, .01, "V", 127, 2.6, true},
                                 {"Cell 5 voltage", 76, 7, false, .01, "V", 127, 2.6, true},
                                 {"Cell 6 voltage", 83, 7, false, .01, "V", 127, 2.6, true},
                                 {"Cell 7 voltage", 90, 7, false, .01, "V", 127, 2.6, true},
                                 {"Cell 8 voltage", 97, 7, false, .01, "V", 127, 2.6, true},
                                 F("Battery voltage", 104, 12, false, .01, "V", 4095, 0),
                                 F("Balancer status", 116, 4, false, 1, "", 15, 0),
                                 T(120)};
static const field fields_6[] = {STATE,
                                 ERROR,
                                 V(16, "Battery voltage"),
                                 I(32, "Battery current"),
                                 F("PV power", 48, 16, false, 1, "W", 65535, 0),
                                 F("Yield today", 64, 16, false, .01, "kWh", 65535, 0),
                                 F("AC out power", 80, 16, true, 1, "W", 0x7fff, 0)};
static const field fields_8[] = {STATE,
                                 ERROR,
                                 F("Battery voltage 1", 16, 13, false, .01, "V", 8191, 0),
                                 F("Battery current 1", 29, 11, false, .1, "A", 2047, 0),
                                 F("Battery voltage 2", 40, 13, false, .01, "V", 8191, 0),
                                 F("Battery current 2", 53, 11, false, .1, "A", 2047, 0),
                                 F("Battery voltage 3", 64, 13, false, .01, "V", 8191, 0),
                                 F("Battery current 3", 77, 11, false, .1, "A", 2047, 0),
                                 T(88),
                                 F("AC current", 95, 9, false, .1, "A", 511, 0)};
static const field fields_9[] = {STATE,
                                 F("Output state", 8, 8, false, 1, "", 255, 0),
                                 F("Error code", 16, 8, false, 1, "", 255, 0),
                                 F("Alarm reason", 24, 16, false, 1, "", UINT32_MAX, 0),
                                 F("Warning reason", 40, 16, false, 1, "", UINT32_MAX, 0),
                                 V(56, "Input voltage"),
                                 F("Output voltage", 72, 16, false, .01, "V", 65535, 0),
                                 F("Off reason", 88, 32, false, 1, "", UINT32_MAX, 0)};
static const field fields_10[] = {F("BMS error", 0, 8, false, 1, "", UINT32_MAX, 0),
                                  F("Time to go", 8, 16, false, 1, "min", 65535, 0),
                                  V(24, "Battery voltage"),
                                  I(40, "Battery current"),
                                  F("IO status", 56, 16, false, 1, "", UINT32_MAX, 0),
                                  F("Warnings/alarms", 72, 18, false, 1, "", UINT32_MAX, 0),
                                  F("State of charge", 90, 10, false, .1, "%", 1023, 0),
                                  F("Consumed Ah", 100, 20, false, -.1, "Ah", 0xfffff, 0),
                                  T(120)};
static const field fields_11[] = {STATE,
                                  ERROR,
                                  I(16, "Battery current"),
                                  F("Battery voltage", 32, 14, false, .01, "V", 16383, 0),
                                  F("Active AC input", 46, 2, false, 1, "", 3, 0),
                                  F("AC in power", 48, 16, true, 1, "W", 0x7fff, 0),
                                  F("AC out power", 64, 16, true, 1, "W", 0x7fff, 0),
                                  F("PV power", 80, 16, false, 1, "W", 65535, 0),
                                  F("Yield today", 96, 16, false, .01, "kWh", 65535, 0)};
static const field fields_12[] = {STATE,
                                  F("VE.Bus error", 8, 8, false, 1, "", 255, 0),
                                  I(16, "Battery current"),
                                  F("Battery voltage", 32, 14, false, .01, "V", 16383, 0),
                                  F("Active AC input", 46, 2, false, 1, "", 3, 0),
                                  F("AC in power", 48, 19, true, 1, "W", 0x3ffff, 0),
                                  F("AC out power", 67, 19, true, 1, "W", 0x3ffff, 0),
                                  F("Alarm", 86, 2, false, 1, "", 3, 0),
                                  T(88),
                                  F("State of charge", 95, 7, false, 1, "%", 127, 0)};
static const field fields_13[] = {F("Monitor mode", 0, 16, true, 1, "", UINT32_MAX, 0),
                                  V(16, "Battery voltage"),
                                  F("Alarm reason", 32, 16, false, 1, "", UINT32_MAX, 0),
                                  F("Aux input", 64, 2, false, 1, "", 3, 0),
                                  F("Battery current", 66, 22, true, .001, "A", 0x3fffff, 0)};
static const field fields_15[] = {STATE,
                                  ERROR,
                                  V(16, "Output voltage"),
                                  I(32, "Output current"),
                                  F("Input voltage", 48, 16, false, .01, "V", 65535, 0),
                                  F("Input current", 64, 16, false, .1, "A", 65535, 0),
                                  F("Off reason", 80, 32, false, 1, "", UINT32_MAX, 0)};
typedef struct {
    uint8_t type;
    const char *name;
    unsigned bits;
    const field *fields;
    size_t count;
} layout;
#define L(t, n, b) {t, n, b, fields_##t, sizeof(fields_##t) / sizeof(field)}
static const layout layouts[] = {L(1, "Solar charger", 80),    L(2, "Battery monitor", 118),
                                 L(3, "Inverter", 82),         L(4, "DC/DC converter", 80),
                                 L(5, "SmartLithium", 127),    L(6, "Inverter RS", 96),
                                 L(8, "AC charger", 104),      L(9, "Smart Battery Protect", 120),
                                 L(10, "Lynx Smart BMS", 127), L(11, "Multi RS", 112),
                                 L(12, "VE.Bus", 102),         L(13, "DC energy meter", 88),
                                 L(15, "Orion XS", 112)};
static const layout *find(uint8_t type)
{
    for (size_t i = 0; i < sizeof(layouts) / sizeof(layouts[0]); i++)
        if (layouts[i].type == type)
            return &layouts[i];
    return NULL;
}
bool nm_ble_victron_record_supported(uint8_t type)
{
    return find(type) != NULL;
}
static uint32_t bits(nm_ble_bytes p, unsigned bit, unsigned width)
{
    uint32_t v = 0;
    for (unsigned i = 0; i < width; i++)
        v |= (uint32_t)((p.bytes[(bit + i) / 8] >> ((bit + i) % 8)) & 1) << i;
    return v;
}
static void append(nm_ble_bytes p, const field *f, nm_ble_output *o)
{
    uint32_t raw = bits(p, f->bit, f->width);
    bool available = !(f->width < 32 && raw == f->na) && !(f->cell && (raw == 0 || raw == 126));
    int64_t numeric = f->sign && (raw & (UINT32_C(1) << (f->width - 1)))
                          ? (int64_t)raw - (INT64_C(1) << f->width)
                          : (int64_t)raw;
    nm_ble_output_reading(o, f->label, 1, numeric * f->scale + f->add, available);
    if (f->width < 32 && raw == f->na) {
        nm_ble_output_append(o, "%s: NA\n", f->label);
        return;
    }
    if (f->cell && (raw == 0 || raw == 126)) {
        nm_ble_output_append(o, "%s: %s V\n", f->label, raw == 0 ? "<2.61" : ">3.85");
        return;
    }
    int64_t v = f->sign && (raw & (UINT32_C(1) << (f->width - 1)))
                    ? (int64_t)raw - (INT64_C(1) << f->width)
                    : (int64_t)raw;
    int precision = f->scale == .001                      ? 3
                    : f->scale == .01                     ? 2
                    : (f->scale == .1 || f->scale == -.1) ? 1
                                                          : 0;
    nm_ble_output_append(o, "%s: %.*f%s%s\n", f->label, precision, v * f->scale + f->add,
                         *f->unit ? " " : "", f->unit);
}
bool nm_ble_victron_record_decode(uint8_t type, nm_ble_bytes p, nm_ble_output *o)
{
    const layout *l = find(type);
    if (!l || p.length < (l->bits + 7) / 8) {
        nm_ble_output_append(o, "Victron record 0x%02X is unsupported or too short", type);
        return false;
    }
    if (type != 1)
        nm_ble_output_append(o, "Victron device: %s\n", l->name);
    for (size_t i = 0; i < l->count; i++)
        append(p, &l->fields[i], o);
    if (type == 1 && p.length >= 12) {
        const field f = F("Load current", 80, 9, false, .1, "A", 511, 0);
        append(p, &f, o);
    }
    if (type == 2 || type == 13) {
        uint32_t mode = bits(p, 64, 2);
        const field aux[] = {
            F("Aux voltage", 48, 16, true, .01, "V", UINT32_MAX, 0),
            F("Mid voltage", 48, 16, false, .01, "V", UINT32_MAX, 0),
            F("Battery temperature", 48, 16, false, .01, "°C", UINT32_MAX, -273.15)};
        if (mode < 3)
            append(p, &aux[mode], o);
    }
    return !o->failed;
}
