#ifndef NM_MONITOR_RECORD_INTERNAL_H
#define NM_MONITOR_RECORD_INTERNAL_H
#include "monitor_model.h"
/* Immutable unknown JSON fields are retained between copy-on-write snapshots.
 * These reference counts are owned exclusively by the processor task. */
nm_extension *nm_extension_create(yyjson_mut_val *value);
/* Internal use only: text must already be valid JSON. */
nm_extension *nm_extension_from_json(const char *json, size_t length);
nm_extension *nm_extension_retain(nm_extension *extension);
void nm_extension_release(nm_extension *extension);
yyjson_mut_val *nm_extension_decode(yyjson_mut_doc *doc, const nm_extension *extension);
#endif
