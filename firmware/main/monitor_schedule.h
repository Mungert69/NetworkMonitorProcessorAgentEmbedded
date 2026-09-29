#ifndef NM_MONITOR_SCHEDULE_H
#define NM_MONITOR_SCHEDULE_H

#include <stdbool.h>
#include <stdint.h>
#include "yyjson.h"

/* JSON-view APIs for the host-only pre-refactor regression reference.
 * Runtime firmware uses monitor_schedule_typed.h; these functions are only
 * compiled with NM_SCHEDULE_REFERENCE by the reference test target.
 * Portable translation of ConfigurableEndpointFilterStrategy and the enabled
 * gate in NetConnectCollection.GetFilteredNetConnects. No clock, RNG or IDF.
 *
 * config: {"FilterStrategies":[...]}; absent/null list means no strategies.
 * monitors: ordered array of flat MonitorPingInfo objects. MonitorIPID defaults
 * to 0, EndPointType to "", Enabled to false, IsEnabled (connector flag) to true.
 * SkipCycles absent/null delegates to endpoint strategies; <=0 bypasses them.
 * Include EVERY connector, including disabled ones, in prepare and iteration.
 *
 * schedule_state must be an object owned by doc, initially {} or the previously
 * persisted object. Persist it inside the caller's unified snapshot. Config and
 * monitor values are borrowed; retained config is copied into doc. prepare once
 * per cycle, include once per connector in the same order. Changed strategy
 * config resets filter state (equivalent to constructing a new .NET strategy);
 * monitor changes alone retain state. Neither API resets state for data resets.
 *
 * utc_seconds is Unix UTC, within DateTime's year 1..9999 range. daily_hash is
 * the supplied .NET MonitorIPID.ToString().GetHashCode(), NOT the ID itself.
 * .NET string hashing is process-seeded; portable ID-only daily parity is not
 * possible. INT32_MIN is rejected when daily-slot evaluates (Math.Abs throws).
 * A caller may supply stable FNV-1a of the decimal ID as an explicit platform
 * adaptation: the slot distribution is comparable, but individual slots differ.
 * random_value is a finite NextDouble sample in [0,1); it is used at each
 * reached randomized gate. For independent samples at multiple matching gates,
 * use include_with_random with a caller-supplied sample callback instead.
 *
 * false means invalid input/state or allocation failure; *include is false on
 * error. Malformed JSON is validated before changing state. Allocation failures
 * can leave partial state: discard/reload the snapshot in that case. A reached
 * INT32_MIN daily hash or invalid callback sample can fail after preceding
 * counters have advanced, like a .NET evaluation throwing mid-filter.
 * Unknown JSON fields are ignored; known fields never coerce strings/floats to
 * ints. Duplicate object keys are rejected. Endpoint matching is ASCII ordinal
 * ignore-case; non-ASCII match text and blank strategy names are rejected rather
 * than silently substituting for .NET Unicode casing or generated GUID names.
 */
bool nm_monitor_schedule_prepare(yyjson_mut_doc *doc,
    yyjson_mut_val *schedule_state, yyjson_mut_val *config,
    yyjson_mut_val *monitors, int64_t utc_seconds);

bool nm_monitor_schedule_include(yyjson_mut_doc *doc,
    yyjson_mut_val *schedule_state, yyjson_mut_val *config,
    yyjson_mut_val *monitor, int64_t utc_seconds,
    double random_value, int32_t daily_hash, bool *include);

typedef double (*nm_monitor_schedule_random_fn)(void *context);

/* Calls random_next only after a randomized counter gate succeeds, once per
 * reached gate, in configuration order. Callback must return a finite [0,1)
 * sample and must not modify the JSON inputs. No callback calls for exclusions
 * at earlier filters, host overrides, daily slots, or plain counters. */
bool nm_monitor_schedule_include_with_random(yyjson_mut_doc *doc,
    yyjson_mut_val *schedule_state, yyjson_mut_val *config,
    yyjson_mut_val *monitor, int64_t utc_seconds,
    nm_monitor_schedule_random_fn random_next, void *random_context,
    int32_t daily_hash, bool *include);

#endif
