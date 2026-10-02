#ifndef NM_SERVICE_HINTS_H
#define NM_SERVICE_HINTS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Returns a registered TCP service-name hint, or false for an unknown port. */
bool nm_service_hint_lookup(uint16_t port, char *name, size_t capacity);

#endif
