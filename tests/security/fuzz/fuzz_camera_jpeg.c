#include "camera_jpeg.h"
#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    nm_camera_jpeg *decoder = nm_camera_jpeg_new();
    if (!decoder)
        return 0;
    size_t pos = 0;
    while (pos + 2 <= size) {
        size_t packet_size = ((size_t)data[pos] << 8) | data[pos + 1];
        pos += 2;
        if (packet_size > size - pos)
            packet_size = size - pos;
        (void)nm_camera_jpeg_packet(decoder, data + pos, packet_size);
        pos += packet_size;
    }
    size_t length = 0;
    unsigned width = 0, height = 0;
    uint8_t *jpeg = nm_camera_jpeg_take(decoder, &length, &width, &height);
    free(jpeg);
    nm_camera_jpeg_free(decoder);
    return 0;
}
