#ifndef NM_COMMAND_SECURITY_H
#define NM_COMMAND_SECURITY_H
#include <stdbool.h>
#include <stddef.h>
#include "nm_json.h"

bool nm_command_requires_signature(const char *operation);
/* Returns owned authenticated JSON, or NULL. No unsigned fallback. */
yyjson_mut_doc *nm_command_verify(yyjson_mut_val *envelope, const char *operation,
                         const char *target, const unsigned char *public_key,
                         size_t public_key_length);
#endif
