#include "camera_jpeg.h"
#include "camera_jpeg_tables.h"
#include "nm_memory.h"
#include <string.h>
struct nm_camera_jpeg {
    uint8_t *data;
    size_t used, scan;
    uint32_t timestamp, ssrc;
    uint16_t sequence;
    unsigned width, height, type, q, restart;
    bool active, complete;
};
static const uint8_t luminance[64] = {16,  11,  10,  16,  24, 40, 51,  61,  12,  12,  14,  19,  26,
                                      58,  60,  55,  14,  13, 16, 24,  40,  57,  69,  56,  14,  17,
                                      22,  29,  51,  87,  80, 62, 18,  22,  37,  56,  68,  109, 103,
                                      77,  24,  35,  55,  64, 81, 104, 113, 92,  49,  64,  78,  87,
                                      103, 121, 120, 101, 72, 92, 95,  98,  112, 100, 103, 99};
static const uint8_t chrominance[64] = {
    17, 18, 24, 47, 99, 99, 99, 99, 18, 21, 26, 66, 99, 99, 99, 99, 24, 26, 56, 99, 99, 99,
    99, 99, 47, 66, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99};
static const uint8_t zigzag[64] = {0,  1,  8,  16, 9,  2,  3,  10, 17, 24, 32, 25, 18, 11, 4,  5,
                                   12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6,  7,  14, 21, 28,
                                   35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51,
                                   58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63};
static unsigned be16(const uint8_t *p)
{
    return ((unsigned)p[0] << 8) | p[1];
}
static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static bool bytes(nm_camera_jpeg *d, const void *p, size_t n)
{
    if (n > NM_CMD_RAW_MAX - d->used)
        return false;
    memcpy(d->data + d->used, p, n);
    d->used += n;
    return true;
}
static bool word(nm_camera_jpeg *d, unsigned w)
{
    uint8_t b[2] = {(uint8_t)(w >> 8), (uint8_t)w};
    return bytes(d, b, 2);
}
static bool header(nm_camera_jpeg *d, unsigned type, unsigned q, unsigned restart,
                   const uint8_t *tables)
{
    uint8_t generated[128];
    if (!tables) {
        if (!q || q > 99)
            return false;
        unsigned scale = q < 50 ? 5000 / q : 200 - 2 * q;
        for (unsigned i = 0; i < 128; ++i) {
            unsigned value =
                ((i < 64 ? luminance : chrominance)[zigzag[i % 64]] * scale + 50) / 100;
            generated[i] = (uint8_t)(value < 1 ? 1 : value > 255 ? 255 : value);
        }
        tables = generated;
    }
    uint8_t sof[] = {8,
                     (uint8_t)(d->height >> 8),
                     (uint8_t)d->height,
                     (uint8_t)(d->width >> 8),
                     (uint8_t)d->width,
                     3,
                     1,
                     (uint8_t)(type == 0 ? 0x21 : 0x22),
                     0,
                     2,
                     0x11,
                     1,
                     3,
                     0x11,
                     1};
    static const uint8_t sos[] = {3, 1, 0, 2, 0x11, 3, 0x11, 0, 63, 0};
    uint8_t id = 0;
    bool ok = word(d, 0xffd8) && word(d, 0xffdb) && word(d, 132) && bytes(d, &id, 1) &&
              bytes(d, tables, 64);
    id = 1;
    ok = ok && bytes(d, &id, 1) && bytes(d, tables + 64, 64) && word(d, 0xffc0) && word(d, 17) &&
         bytes(d, sof, sizeof(sof));
    if (restart)
        ok = ok && word(d, 0xffdd) && word(d, 4) && word(d, restart);
    return ok && word(d, 0xffc4) && word(d, sizeof(huffman) + 2) &&
           bytes(d, huffman, sizeof(huffman)) && word(d, 0xffda) && word(d, 12) &&
           bytes(d, sos, sizeof(sos));
}
/* Some C211 firmware overlays the first eight JPEG bytes with its RTP/JPEG
 * header, leaving 63 luma quantizers followed by a complete chroma DQT marker.
 * Restore only when all surviving quantizers match a standard quality table
 * and every matching quality implies the same missing DC quantizer. */
static bool c211_prefix(nm_camera_jpeg *d, const uint8_t *scan, size_t n)
{
    if (n < 68 || memcmp(scan + 63, "\xff\xdb\x00\x43\x01", 5))
        return false;
    unsigned dc = 0;
    for (unsigned q = 1; q <= 99; ++q) {
        unsigned scale = q < 50 ? 5000 / q : 200 - 2 * q;
        bool match = true;
        for (unsigned i = 1; i < 64; ++i) {
            unsigned v = (luminance[zigzag[i]] * scale + 50) / 100;
            v = v < 1 ? 1 : v > 255 ? 255 : v;
            if (scan[i - 1] != v) {
                match = false;
                break;
            }
        }
        if (!match)
            continue;
        unsigned v = (luminance[0] * scale + 50) / 100;
        v = v < 1 ? 1 : v > 255 ? 255 : v;
        if (dc && dc != v)
            return false;
        dc = v;
    }
    if (!dc)
        return false;
    uint8_t prefix[] = {255, 216, 255, 219, 0, 67, 0, (uint8_t)dc};
    return bytes(d, prefix, sizeof(prefix));
}
nm_camera_jpeg *nm_camera_jpeg_new(void)
{
    nm_camera_jpeg *d = nm_bulk_calloc(1, sizeof(*d));
    if (d) {
        d->data = nm_bulk_malloc(NM_CMD_RAW_MAX);
        if (!d->data) {
            free(d);
            return NULL;
        }
    }
    return d;
}
bool nm_camera_jpeg_packet(nm_camera_jpeg *d, const uint8_t *packet, size_t n)
{
    if (!d || !d->data || !packet || n < 20 || d->complete)
        return false;
    if ((packet[0] >> 6) != 2 || (packet[1] & 127) != 26)
        return false;
    size_t p = 12 + 4 * (packet[0] & 15);
    if (p > n)
        return false;
    if (packet[0] & 16) {
        if (n - p < 4)
            return false;
        size_t extra = 4 + 4 * be16(packet + p + 2);
        if (extra > n - p)
            return false;
        p += extra;
    }
    if (packet[0] & 32) {
        unsigned padding = packet[n - 1];
        if (!padding || padding > n - p)
            return false;
        n -= padding;
    }
    if (n - p < 8)
        return false;
    const uint8_t *j = packet + p;
    unsigned offset = ((unsigned)j[1] << 16) | ((unsigned)j[2] << 8) | j[3];
    unsigned type = j[4], q = j[5], width = j[6] ? j[6] * 8 : 2048, height = j[7] ? j[7] * 8 : 2048;
    unsigned restart = 0;
    p += 8;
    if (type >= 64 && type <= 65) {
        if (n - p < 4)
            return false;
        restart = be16(packet + p);
        p += 4;
        type -= 64;
    }
    if (type > 1 || !q || (q >= 100 && q < 128) || width > 2048 || height > 2048)
        return false;
    const uint8_t *quant = NULL;
    if (!offset && q >= 128) {
        if (n - p < 4 || packet[p] || packet[p + 1] || be16(packet + p + 2) != 128 ||
            n - p - 4 < 128)
            return false;
        quant = packet + p + 4;
        p += 132;
    }
    uint32_t timestamp = be32(packet + 4), ssrc = be32(packet + 8);
    uint16_t sequence = (uint16_t)be16(packet + 2);
    if (!offset) {
        d->active = false;
        d->used = 0;
        d->scan = 0;
        d->width = width;
        d->height = height;
        d->type = type;
        d->q = q;
        d->restart = restart;
        if (!c211_prefix(d, packet + p, n - p) && !header(d, type, q, restart, quant))
            return false;
        d->timestamp = timestamp;
        d->ssrc = ssrc;
        d->active = true;
    } else if (!d->active || timestamp != d->timestamp || ssrc != d->ssrc ||
               sequence != (uint16_t)(d->sequence + 1) || offset != d->scan || width != d->width ||
               height != d->height || type != d->type || q != d->q || restart != d->restart) {
        d->active = false;
        return false;
    }
    d->sequence = sequence;
    if (!bytes(d, packet + p, n - p)) {
        d->active = false;
        return false;
    }
    d->scan += n - p;
    if (packet[1] & 128) {
        /* RTP scan data normally omits EOI; tolerate cameras that include it. */
        if (d->used < 2 || d->data[d->used - 2] != 255 || d->data[d->used - 1] != 217)
            if (!word(d, 0xffd9)) {
                d->active = false;
                return false;
            }
        d->complete = true;
        return true;
    }
    return false;
}
uint8_t *nm_camera_jpeg_take(nm_camera_jpeg *d, size_t *length, unsigned *width, unsigned *height)
{
    if (!d || !d->complete)
        return NULL;
    uint8_t *data = d->data;
    d->data = NULL;
    *length = d->used;
    *width = d->width;
    *height = d->height;
    return data;
}
void nm_camera_jpeg_free(nm_camera_jpeg *d)
{
    if (d) {
        free(d->data);
        free(d);
    }
}
