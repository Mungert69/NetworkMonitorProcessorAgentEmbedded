#ifndef NM_PROBE_CONFIG_H
#define NM_PROBE_CONFIG_H
#include "yyjson.h"

/* ESP32 resource bounds; the .NET setting has the same concurrency meaning,
 * but its server-sized default is unsuitable for this embedded network stack. */
enum { NM_PROBE_DEFAULT_WORKERS = 4, NM_PROBE_MAX_WORKERS = 8 };
enum { NM_ENDPOINT_DEFAULT_OPERATIONS = 4, NM_ENDPOINT_MAX_OPERATIONS = 8 };

static inline bool nm_config_concurrency_read(yyjson_mut_val *root, const char *key,
                                              unsigned fallback, unsigned maximum, unsigned *out)
{
    if (!yyjson_mut_is_obj(root) || !out)
        return false;
    yyjson_mut_val *value = yyjson_mut_obj_get(root, key);
    if (!value) {
        *out = fallback;
        return true;
    }
    if (!yyjson_mut_is_uint(value) || yyjson_mut_get_uint(value) < 1 ||
        yyjson_mut_get_uint(value) > maximum)
        return false;
    *out = (unsigned)yyjson_mut_get_uint(value);
    return true;
}

static inline bool nm_probe_config_read(yyjson_mut_val *root, unsigned *workers)
{
    return nm_config_concurrency_read(root, "MaxTaskQueueSize", NM_PROBE_DEFAULT_WORKERS,
                                      NM_PROBE_MAX_WORKERS, workers);
}

static inline bool nm_endpoint_operation_config_read(yyjson_mut_val *root, unsigned *operations)
{
    return nm_config_concurrency_read(root, "MaxOutstandingEndpointOperations",
                                      NM_ENDPOINT_DEFAULT_OPERATIONS, NM_ENDPOINT_MAX_OPERATIONS,
                                      operations);
}
#endif
