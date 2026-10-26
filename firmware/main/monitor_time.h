#ifndef NM_MONITOR_TIME_H
#define NM_MONITOR_TIME_H
#include "monitor_model.h"
/* Processor-local timestamp policy. Parameters borrowed; mutations only on a
 * disposable candidate. Unknown fields and absent/null timestamps survive. */
bool nm_monitor_time_decode(nm_time_state *state, yyjson_mut_val *value);
yyjson_mut_val *nm_monitor_time_encode(yyjson_mut_doc *doc, const nm_time_state *state);
bool nm_monitor_time_begin(nm_model *candidate, int64_t offset, uint64_t pages);
bool nm_monitor_time_ping(nm_ping_record *ping, nm_time_state *state);
void nm_monitor_time_observe(nm_time_state *state, uint32_t date);
void nm_monitor_time_finish(nm_time_state *state);
#endif
