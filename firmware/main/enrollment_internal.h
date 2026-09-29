#ifndef NM_ENROLLMENT_INTERNAL_H
#define NM_ENROLLMENT_INTERNAL_H
#include "nm_esp.h"
/* Returned documents/tokens are caller-owned. Registration commits monitor
 * state only after verifying the broker reply's command signature. */
yyjson_mut_doc *nm_enrollment_request(const char *url, const char *form, int *status);
char *nm_enrollment_authorize(yyjson_mut_val *root);
bool nm_enrollment_identity(yyjson_mut_doc *doc, yyjson_mut_val *root, const char *token);
bool nm_enrollment_register(nm_esp_config *config);
static inline const char *nm_enrollment_string(yyjson_mut_val *object, const char *key)
{
    yyjson_mut_val *value = yyjson_mut_obj_get(object, key);
    return yyjson_mut_is_str(value) ? yyjson_mut_get_str(value) : NULL;
}
#endif
