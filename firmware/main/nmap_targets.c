#include "nmap_targets.h"
#include <stdio.h>
#include <string.h>

static bool parse_octet(const char **cursor, uint8_t *value)
{
    if (!cursor || !*cursor || !value || **cursor < '0' || **cursor > '9')
        return false;
    const char *begin = *cursor;
    unsigned parsed = 0, digits = 0;
    while (**cursor >= '0' && **cursor <= '9') {
        if (++digits > 3)
            return false;
        parsed = parsed * 10U + (unsigned)(*(*cursor)++ - '0');
    }
    if (parsed > 255 || (digits > 1 && *begin == '0'))
        return false;
    *value = (uint8_t)parsed;
    return true;
}

static bool parse_address(const char **cursor, uint32_t *address)
{
    uint8_t octets[4];
    for (size_t i = 0; i < 4; ++i) {
        if (!parse_octet(cursor, &octets[i]))
            return false;
        if (i < 3) {
            if (**cursor != '.')
                return false;
            ++*cursor;
        }
    }
    *address = ((uint32_t)octets[0] << 24) | ((uint32_t)octets[1] << 16) |
               ((uint32_t)octets[2] << 8) | octets[3];
    return true;
}

bool nm_nmap_ipv4_parse(const char *text, uint32_t *address)
{
    if (!text || !address || strlen(text) > 15)
        return false;
    const char *cursor = text;
    uint32_t parsed;
    if (!parse_address(&cursor, &parsed) || *cursor)
        return false;
    *address = parsed;
    return true;
}

bool nm_nmap_ipv4_cidr_parse(const char *text, nm_nmap_ipv4_range *range)
{
    if (!text || !range || strlen(text) > 18)
        return false;
    const char *cursor = text;
    uint32_t address;
    if (!parse_address(&cursor, &address) || *cursor != '/')
        return false;
    ++cursor;
    if (*cursor < '0' || *cursor > '9')
        return false;
    unsigned prefix = 0, digits = 0;
    while (*cursor >= '0' && *cursor <= '9') {
        if (++digits > 2)
            return false;
        prefix = prefix * 10U + (unsigned)(*cursor++ - '0');
    }
    if (*cursor || prefix < 24 || prefix > 32)
        return false;

    uint32_t mask = prefix == 0 ? 0 : UINT32_MAX << (32U - prefix);
    uint32_t network = address & mask;
    uint32_t total = UINT32_C(1) << (32U - prefix);
    uint32_t first = network;
    uint32_t count = total;
    if (prefix <= 30) {
        first++;
        count -= 2;
    }
    if (!count || count > NM_NMAP_MAX_TARGETS || first > UINT32_MAX - (count - 1))
        return false;
    *range = (nm_nmap_ipv4_range){.first_address = first, .count = (uint16_t)count};
    return true;
}

bool nm_nmap_ipv4_format(uint32_t address, char *output, size_t capacity)
{
    if (!output || !capacity)
        return false;
    int n = snprintf(output, capacity, "%u.%u.%u.%u", (unsigned)(address >> 24),
                     (unsigned)((address >> 16) & 0xff), (unsigned)((address >> 8) & 0xff),
                     (unsigned)(address & 0xff));
    return n > 0 && (size_t)n < capacity;
}
