#include "camera_xml.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > 32768)
        return 0;
    char *input = malloc(size + 1);
    if (!input)
        return 0;
    memcpy(input, data, size);
    input[size] = 0;
    char output[4096];
    (void)nm_camera_xml_value(input, "Uri", NULL, 0, output, sizeof(output));
    (void)nm_camera_xml_value(input, "Profiles", "token", 0, output, sizeof(output));
    (void)nm_camera_xml_escape(input, output, sizeof(output));
    free(input);
    return 0;
}
