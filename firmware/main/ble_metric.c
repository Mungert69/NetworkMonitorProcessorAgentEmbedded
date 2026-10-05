#include "ble_metric.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include "ble_metric_catalogue.inc"
const char *nm_ble_metric_canonical(const char *m)
{
    if (!strcmp(m, "pv") || !strcmp(m, "pvpower"))
        return "pv_power";
    if (!strcmp(m, "battery_v") || !strcmp(m, "battery_voltage_v"))
        return "battery_voltage";
    if (!strcmp(m, "battery_a") || !strcmp(m, "battery_current_a"))
        return "battery_current";
    if (!strcmp(m, "load_a") || !strcmp(m, "load_current_a"))
        return "load_current";
    if (!strcmp(m, "yield") || !strcmp(m, "yield_today_kwh"))
        return "yield_today";
    return m;
}
const nm_ble_metric_encoding *nm_ble_metric_find(const char *format, const char *metric)
{
    metric = nm_ble_metric_canonical(metric);
    char base[64];
    size_t n = strlen(metric);
    if (n >= sizeof(base))
        return NULL;
    memcpy(base, metric, n + 1);
    for (unsigned pass = 0; pass < 2; pass++) {
        for (size_t i = 0; i < sizeof(encodings) / sizeof(encodings[0]); i++)
            if (!strcmp(format, encodings[i].format) && !strcmp(base, encodings[i].metric))
                return &encodings[i];
        if (strcmp(format, "bthome"))
            break;
        char *suffix = strrchr(base, '_');
        if (!suffix || !suffix[1])
            break;
        for (char *p = suffix + 1; *p; p++)
            if (*p < '0' || *p > '9')
                return NULL;
        *suffix = 0;
    }
    return NULL;
}
bool nm_ble_metric_encode(const nm_ble_metric_encoding *e, double value, uint16_t *sample)
{
    if (!e || !sample || !isfinite(value) || value < e->minimum - e->scale * 1e-6 ||
        value > e->maximum + e->scale * 1e-6)
        return false;
    double number = round((value - e->offset) / e->scale);
    if (number < 0 || number > 65534)
        return false;
    *sample = (uint16_t)number;
    return true;
}
