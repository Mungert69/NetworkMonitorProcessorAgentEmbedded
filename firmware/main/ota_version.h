#ifndef NM_OTA_VERSION_H
#define NM_OTA_VERSION_H
#include <stdbool.h>
#include <stddef.h>
#include <limits.h>
#include <string.h>

/* Strict, bounded major.minor.patch; deliberately excludes prerelease labels. */
static inline bool parse_version(const char *text, unsigned parts[3])
{
    if (!text || !*text || strlen(text) >= 32) return false;
    const char *cursor = text;
    for (size_t i = 0; i < 3; ++i) {
        if (*cursor < '0' || *cursor > '9') return false;
        if (*cursor == '0' && cursor[1] >= '0' && cursor[1] <= '9') return false;
        unsigned value = 0;
        do {
            unsigned digit = (unsigned)(*cursor - '0');
            if (value > (UINT_MAX - digit) / 10) return false;
            value = value * 10 + digit;
            ++cursor;
        } while (*cursor >= '0' && *cursor <= '9');
        parts[i] = value;
        if (i < 2) {
            if (*cursor++ != '.') return false;
        } else if (*cursor != '\0') return false;
    }
    return true;
}

static inline int compare_version(const unsigned left[3], const unsigned right[3])
{
    for (size_t i = 0; i < 3; ++i)
        if (left[i] != right[i]) return left[i] > right[i] ? 1 : -1;
    return 0;
}
/* An authenticated owner may upgrade or downgrade, but not reinstall the running version. */
static inline bool ota_version_permitted(const char *target, const char *running)
{
    unsigned proposed[3], current[3];
    return parse_version(target, proposed) && parse_version(running, current) &&
           compare_version(proposed, current) != 0;
}
#endif
