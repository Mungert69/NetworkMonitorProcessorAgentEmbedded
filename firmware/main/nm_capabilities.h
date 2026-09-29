#ifndef NM_CAPABILITIES_H
#define NM_CAPABILITIES_H
#include "nm_capability_defaults.h"
#include "nm_json.h"
#include <stdbool.h>
#include <string.h>

/* Merge additional restrictions; configuration cannot enable unimplemented code.
 * Bound the wire lists to the backend registration limits. */
static inline bool nm_capability_list(yyjson_mut_doc *doc, yyjson_mut_val *target, yyjson_mut_val *settings,
                                     const char *setting, const char *wire,
                                     const char *defaults) {
    yyjson_mut_doc *parsed = nm_json_read(defaults, strlen(defaults));
    yyjson_mut_val *list = yyjson_mut_val_mut_copy(doc, yyjson_mut_doc_get_root(parsed));
    yyjson_mut_doc_free(parsed);
    if (!list) return false;
    yyjson_mut_val *extra = yyjson_mut_obj_get(settings, setting);
    if (!extra) return yyjson_mut_obj_add_val(doc, target, wire, list);
    if (!yyjson_mut_is_arr(extra)) return false;
    yyjson_mut_val *item;
    size_t i, n;
    yyjson_mut_arr_foreach(extra, i, n, item) {
        if (!yyjson_mut_is_str(item) || !yyjson_mut_get_str(item)[0] ||
            strlen(yyjson_mut_get_str(item)) > 128) { return false; }
        bool found = false;
        yyjson_mut_val *existing;
        size_t j, m;
        yyjson_mut_arr_foreach(list, j, m, existing)
            if (!strcmp(yyjson_mut_get_str(existing), yyjson_mut_get_str(item))) found = true;
        if (!found) {
            if (yyjson_mut_arr_size(list) >= 128) { return false; }
            yyjson_mut_val *copy = yyjson_mut_strcpy(doc, yyjson_mut_get_str(item));
            if (!copy || !yyjson_mut_arr_append(list, copy)) {
                return false;
            }
        }
    }
    if (!yyjson_mut_obj_add_val(doc, target, wire, list)) { return false; }
    return true;
}

static inline bool nm_capabilities_add(yyjson_mut_doc *doc, yyjson_mut_val *target, yyjson_mut_val *settings) {
    return nm_capability_list(doc, target, settings, "DisabledEndpointTypes",
                              "DisabledEndPointTypes", NM_DISABLED_ENDPOINTS_JSON) &&
           nm_capability_list(doc, target, settings, "DisabledCommands",
                              "DisabledCommands", NM_DISABLED_COMMANDS_JSON);
}
#endif
