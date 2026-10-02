#include "cmd_output.h"
#include "nm_memory.h"
#include <stdarg.h>
#include <stdio.h>
bool nm_cmd_output_init(nm_cmd_output *out, size_t capacity)
{
    *out = (nm_cmd_output){.capacity = capacity};
    out->text = nm_bulk_calloc(1, capacity);
    return out->valid = out->text != NULL;
}
bool nm_cmd_output_append(nm_cmd_output *out, const char *format, ...)
{
    if (!out->valid || out->used >= out->capacity)
        return false;
    va_list args;
    va_start(args, format);
    int count = vsnprintf(out->text + out->used, out->capacity - out->used, format, args);
    va_end(args);
    if (count < 0 || (size_t)count >= out->capacity - out->used)
        return out->valid = false;
    for (size_t i = out->used; i < out->used + (size_t)count; ++i)
        if (out->text[i] == '\n' && ++out->lines > 256)
            return out->valid = false;
    out->used += (size_t)count;
    return true;
}
nm_cmd_result nm_cmd_output_finish(nm_cmd_output *out, bool success)
{
    nm_cmd_result result = {.success = success && out->valid};
    if (out->valid)
        result.output = out->text;
    else {
        free(out->text);
        result.output = nm_bulk_strdup("Command output exceeds the embedded resource limit");
    }
    out->text = NULL;
    out->valid = false;
    return result;
}
