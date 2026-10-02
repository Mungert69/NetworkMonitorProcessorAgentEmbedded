#ifndef NM_NMAP_TARGETS_H
#define NM_NMAP_TARGETS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Current embedded sweep bound: at most one IPv4 /24. The range is normalized
 * and excludes network/broadcast addresses for prefixes through /30. */
enum { NM_NMAP_MAX_TARGETS = 254 };
typedef struct {
    uint32_t first_address;
    uint16_t count;
} nm_nmap_ipv4_range;

bool nm_nmap_ipv4_cidr_parse(const char *text, nm_nmap_ipv4_range *range);
bool nm_nmap_ipv4_parse(const char *text, uint32_t *address);
bool nm_nmap_ipv4_format(uint32_t address, char *output, size_t capacity);

#endif
