#ifndef NM_STORAGE_CHECKPOINT_H
#define NM_STORAGE_CHECKPOINT_H
#include "nm_esp.h"
#include "network.h"
#include <time.h>
/* Borrows and stamps an owned candidate snapshot, never the active model.
 * One blob write commits both clock and model; failure retains previous state. */
static inline bool nm_storage_checkpoint_save_at(yyjson_mut_doc *snapshot, time_t now)
{
    yyjson_mut_val *root = yyjson_mut_doc_get_root(snapshot);
    return snapshot &&
           nm_json_put(snapshot, root, "ClockUtc", yyjson_mut_sint(snapshot, (int64_t)now)) &&
           nm_esp_storage_save("monitoring", root);
}
static inline bool nm_storage_checkpoint_save(yyjson_mut_doc *snapshot)
{
    yyjson_mut_val *root = yyjson_mut_doc_get_root(snapshot);
    bool correcting = yyjson_mut_is_true(
        yyjson_mut_obj_get(yyjson_mut_obj_get(root, "ClockState"), "Correcting"));
    return nm_storage_checkpoint_save_at(snapshot,
                                         correcting ? time(NULL) : nm_network_recording_time());
}
#endif
