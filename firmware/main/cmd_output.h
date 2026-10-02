#ifndef NM_CMD_OUTPUT_H
#define NM_CMD_OUTPUT_H
#include "cmd_result.h"
#include <stddef.h>
typedef struct {
    char *text;
    size_t used, capacity, lines;
    bool valid;
} nm_cmd_output;
bool nm_cmd_output_init(nm_cmd_output *output, size_t capacity);
bool nm_cmd_output_append(nm_cmd_output *output, const char *format, ...);
/* Transfers output on success; failed construction frees it and returns a
 * failed result (never a truncated successful report). */
nm_cmd_result nm_cmd_output_finish(nm_cmd_output *output, bool success);
#endif
