#include "camera_jpeg.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void packet(uint8_t *p, unsigned seq, unsigned offset, bool last)
{
    memset(p, 0, 32);
    p[0] = 0x80;
    p[1] = 26 | (last ? 128 : 0);
    p[2] = seq >> 8;
    p[3] = seq;
    p[7] = 1;
    p[11] = 2;
    p[13] = offset >> 16;
    p[14] = offset >> 8;
    p[15] = offset;
    p[17] = 90;
    p[18] = 80;
    p[19] = 45;
    memset(p + 20, 0x45, 12);
}
int main(int argc, char **argv)
{
    uint8_t p[32];
    nm_camera_jpeg *d = nm_camera_jpeg_new();
    assert(d);
    packet(p, 65535, 0, false);
    assert(!nm_camera_jpeg_packet(d, p, sizeof(p)));
    packet(p, 0, 12, true);
    assert(nm_camera_jpeg_packet(d, p, sizeof(p)));
    size_t n;
    unsigned w, h;
    uint8_t *data = nm_camera_jpeg_take(d, &n, &w, &h);
    assert(data && n < NM_CMD_RAW_MAX && w == 640 && h == 360);
    assert(data[0] == 255 && data[1] == 216 && data[n - 2] == 255 && data[n - 1] == 217);
    free(data);
    nm_camera_jpeg_free(d);
    for (unsigned mode = 0; mode < 5; ++mode) {
        d = nm_camera_jpeg_new();
        packet(p, 1, 0, false);
        assert(!nm_camera_jpeg_packet(d, p, sizeof(p)));
        packet(p, 2, 12, true);
        if (mode == 0)
            p[3] = 3;
        if (mode == 1)
            p[7] = 2;
        if (mode == 2)
            p[11] = 3;
        if (mode == 3)
            p[15] = 11;
        if (mode == 4)
            p[18] = 81;
        assert(!nm_camera_jpeg_packet(d, p, sizeof(p)));
        packet(p, 4, 0, true);
        assert(nm_camera_jpeg_packet(d, p, sizeof(p)));
        nm_camera_jpeg_free(d);
    }
    d = nm_camera_jpeg_new();
    for (size_t nbytes = 0; nbytes < 20; ++nbytes)
        assert(!nm_camera_jpeg_packet(d, p, nbytes));
    packet(p, 1, 0, false);
    p[17] = 127;
    assert(!nm_camera_jpeg_packet(d, p, sizeof(p)));
    packet(p, 1, 0, false);
    p[17] = 128;
    assert(!nm_camera_jpeg_packet(d, p, sizeof(p)));
    packet(p, 1, 0, false);
    assert(!nm_camera_jpeg_packet(d, p, sizeof(p)));
    for (unsigned seq = 2, offset = 12; offset < NM_CMD_RAW_MAX + 12; ++seq, offset += 12) {
        packet(p, seq, offset, false);
        assert(!nm_camera_jpeg_packet(d, p, sizeof(p)));
    }
    packet(p, 6000, 0, true);
    assert(nm_camera_jpeg_packet(d, p, sizeof(p)));
    nm_camera_jpeg_free(d);
    assert(argc == 2);
    FILE *fixture = fopen(argv[1], "rb");
    assert(fixture);
    uint8_t source[4096], wire[532];
    size_t source_n = fread(source, 1, sizeof(source), fixture);
    fclose(fixture);
    assert(source_n > 100 && source_n < sizeof(source));
    d = nm_camera_jpeg_new();
    bool complete = false;
    for (size_t offset = 0; offset < source_n - 8;) {
        size_t part = source_n - 8 - offset;
        if (part > 512)
            part = 512;
        bool last = offset + part == source_n - 8;
        packet(wire, 1 + offset / 512, offset, last);
        wire[18] = 8;
        wire[19] = 6;
        memcpy(wire + 20, source + 8 + offset, part);
        complete = nm_camera_jpeg_packet(d, wire, 20 + part);
        assert(complete == last);
        offset += part;
    }
    assert(complete);
    data = nm_camera_jpeg_take(d, &n, &w, &h);
    assert(data && n == source_n && w == 64 && h == 48 && !memcmp(data, source, n));
    free(data);
    nm_camera_jpeg_free(d);
    puts("RTP/JPEG continuity, recovery, framing and bounds passed");
}
