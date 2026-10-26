#ifndef NM_SD_CARD_H
#define NM_SD_CARD_H
#include "nm_json.h"
#include <stdbool.h>
#include <stdint.h>
/* Startup only, borrowed settings/identity. Returns a process-lifetime borrowed
 * directory for this identity, or NULL. Never formats or erases a card. */
const char *nm_sd_card_mount(yyjson_mut_val *settings, const char *identity);
bool nm_sd_card_space(uint64_t *free_bytes);
#endif
