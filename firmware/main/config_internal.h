#ifndef NM_CONFIG_INTERNAL_H
#define NM_CONFIG_INTERNAL_H
#include "nm_esp.h"
/* Apply durable reset before binding/networking. Failed resets retain the marker. */
bool nm_config_apply_reset(nm_esp_config *config);
#endif
