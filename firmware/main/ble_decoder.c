#include "ble_decoder_internal.h"
#include "ble_filter.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
static const nm_ble_decoder *const decoders[] = {&nm_ble_victron_decoder, &nm_ble_ruuvi_decoder,
                                                 &nm_ble_bthome_decoder};
const nm_ble_decoder *nm_ble_decoder_find(const char *format)
{
    if (!format)
        return NULL;
    for (size_t i = 0; i < sizeof(decoders) / sizeof(decoders[0]); i++)
        if (!strcasecmp(format, decoders[i]->format))
            return decoders[i];
    return NULL;
}
const char *nm_ble_decoder_key_error(const nm_ble_decoder *d, size_t n)
{
    if (!d)
        return n == 0 || n == 16 || n == 24 || n == 32 ? NULL
                                                       : "Expected a 16-, 24-, or 32-byte AES key";
    return d->key_error(n);
}
const char *nm_ble_aes128_key_error(size_t n)
{
    return n == 0 || n == 16 ? NULL : "This BLE protocol requires a 16-byte AES-128 key";
}
const char *nm_ble_no_key_error(size_t n)
{
    return n ? "Ruuvi RAWv2 is unencrypted; leave Password/key empty" : NULL;
}

void nm_ble_output_append(nm_ble_output *o, const char *format, ...)
{
    if (o->failed)
        return;
    va_list args;
    va_start(args, format);
    int n = vsnprintf(o->text + o->used, o->capacity - o->used, format, args);
    va_end(args);
    if (n < 0 || (size_t)n >= o->capacity - o->used) {
        o->failed = true;
        return;
    }
    o->used += (size_t)n;
}
bool nm_ble_decoder_select(const nm_ble_decoder *d, nm_ble_bytes in, const char *type,
                           nm_ble_bytes *out)
{
    if (!d || !in.bytes || !in.length || in.length > 255 || !type || !out)
        return false;
    bool raw = !strcmp(type, "raw");
    if (raw) {
        if (!d->service_uuid)
            return nm_ble_ad_field(in.bytes, in.length, 0xff, d->manufacturer_id, &out->bytes,
                                   &out->length) &&
                   (out->bytes += 2, out->length -= 2, true);
        for (size_t p = 0; p < in.length;) {
            size_t n = in.bytes[p];
            if (!n || n > in.length - p - 1)
                break;
            uint8_t ad = in.bytes[p + 1];
            const uint8_t *v = in.bytes + p + 2;
            size_t u = ad == 0x16 ? 2 : ad == 0x20 ? 4 : ad == 0x21 ? 16 : 0;
            static const uint8_t base[12] = {0xfb, 0x34, 0x9b, 0x5f, 0x80, 0,
                                             0,    0x80, 0,    0x10, 0,    0};
            bool match = u && n >= 1 + u &&
                         ((u <= 4 && v[0] == (d->service_uuid & 255) &&
                           v[1] == (d->service_uuid >> 8) && (u == 2 || (!v[2] && !v[3]))) ||
                          (u == 16 && !memcmp(v, base, 12) && v[12] == (d->service_uuid & 255) &&
                           v[13] == (d->service_uuid >> 8) && !v[14] && !v[15]));
            if (match) {
                *out = (nm_ble_bytes){v + u, n - 1 - u};
                return true;
            }
            p += n + 1;
        }
        return false;
    }
    if (!d->service_uuid && !strcmp(type, "manufacturer") &&
        (in.length < 2 || in.bytes[0] != (d->manufacturer_id & 255) ||
         in.bytes[1] != (d->manufacturer_id >> 8)))
        return false;
    *out = in;
    unsigned id = d->service_uuid ? d->service_uuid : (unsigned)d->manufacturer_id;
    if (in.length >= 2 && in.bytes[0] == (id & 255) && in.bytes[1] == (id >> 8)) {
        out->bytes += 2;
        out->length -= 2;
    }
    return out->length > 0;
}
bool nm_ble_decoder_decode(const nm_ble_decoder *d, nm_ble_bytes in, const char *type,
                           const char *address, const uint8_t *key, size_t n, char *text,
                           size_t capacity)
{
    return nm_ble_decoder_decode_metric(d, in, type, address, key, n, text, capacity, NULL);
}
bool nm_ble_decoder_decode_metric(const nm_ble_decoder *d, nm_ble_bytes in, const char *type,
                                  const char *address, const uint8_t *key, size_t n, char *text,
                                  size_t capacity, nm_ble_metric_selection *selection)
{
    if (!text || !capacity)
        return false;
    text[0] = 0;
    const char *error = n && !key ? "BLE key is missing" : nm_ble_decoder_key_error(d, n);
    nm_ble_bytes payload;
    if (error || !nm_ble_decoder_select(d, in, type, &payload)) {
        snprintf(text, capacity, "%s", error ? error : "BLE protocol data not found");
        return false;
    }
    nm_ble_output out = {text, capacity, 0, false, selection};
    bool ok = d->decode(payload, address ? address : "unknown", key, n, &out);
    if (selection && (!ok || out.failed)) {
        selection->matches = 0;
        selection->available = false;
    }
    if (out.failed) {
        snprintf(text, capacity, "BLE decoded output limit exceeded");
        return false;
    }
    if (!ok) { /* Decoder errors are always complete single diagnostics. */
        return false;
    }
    return true;
}

void nm_ble_output_reading(nm_ble_output *o, const char *label, unsigned count, double value,
                           bool available)
{
    if (!o->selection)
        return;
    char metric[64];
    size_t used = 0;
    for (const unsigned char *p = (const unsigned char *)label; *p; p++) {
        if (used + 1 >= sizeof(metric)) {
            o->failed = true;
            return;
        }
        if ((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9'))
            metric[used++] = (char)*p;
        else if (*p >= 'A' && *p <= 'Z')
            metric[used++] = (char)(*p - 'A' + 'a');
        else if (used && metric[used - 1] != '_')
            metric[used++] = '_';
    }
    while (used && metric[used - 1] == '_')
        used--;
    metric[used] = 0;
    if (count > 1) {
        int n = snprintf(metric + used, sizeof(metric) - used, "_%u", count);
        if (n < 0 || (size_t)n >= sizeof(metric) - used) {
            o->failed = true;
            return;
        }
    }
    if (!strcmp(metric, o->selection->requested)) {
        o->selection->matches++;
        o->selection->available = available;
        o->selection->value = value;
    }
}
