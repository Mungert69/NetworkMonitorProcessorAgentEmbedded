#include "service_hints.h"
#include <string.h>

extern const char service_hints_csv_start[] __asm__("_binary_service_hints_csv_start");
extern const char service_hints_csv_end[] __asm__("_binary_service_hints_csv_end");

static const char *data_start(void)
{
    const char *cursor = service_hints_csv_start;
    const char *end = service_hints_csv_end;
    while (cursor < end && *cursor == '#') {
        while (cursor < end && *cursor != '\n')
            ++cursor;
        if (cursor < end)
            ++cursor;
    }
    return cursor;
}

bool nm_service_hint_lookup(uint16_t port, char *name, size_t capacity)
{
    if (!port || !name || capacity < 2)
        return false;

    const char *start = data_start();
    const char *end = service_hints_csv_end;
    if (start >= end)
        return false;

    /* The embedded file is sorted by port. Search line boundaries in-place,
     * avoiding a boot-time RAM index or per-lookup allocation. */
    const char *low = start;
    const char *high = end - 1;
    while (low <= high) {
        const char *middle = low + (high - low) / 2;
        const char *line = middle;
        while (line > start && line[-1] != '\n')
            --line;
        if (line >= end)
            return false;

        unsigned candidate = 0;
        const char *cursor = line;
        bool valid = false;
        while (cursor < end && *cursor >= '0' && *cursor <= '9') {
            valid = true;
            candidate = candidate * 10U + (unsigned)(*cursor - '0');
            ++cursor;
        }
        if (!valid || cursor >= end || *cursor != ',')
            return false;

        const char *line_end = cursor + 1;
        while (line_end < end && *line_end != '\n' && *line_end != '\r')
            ++line_end;
        if (candidate == port) {
            size_t length = (size_t)(line_end - cursor - 1);
            if (!length || length >= capacity)
                return false;
            memcpy(name, cursor + 1, length);
            name[length] = '\0';
            return true;
        }
        if (candidate < port) {
            low = line_end;
            while (low < end && (*low == '\n' || *low == '\r'))
                ++low;
        } else {
            if (line == start)
                break;
            high = line - 1;
        }
    }
    return false;
}
