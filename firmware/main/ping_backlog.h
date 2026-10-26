#ifndef NM_PING_BACKLOG_H
#define NM_PING_BACKLOG_H
#include "monitor_model.h"
#include "ping_storage.h"

enum { NM_PING_WINDOW_PAGES = 8, NM_PING_WINDOW_RECORDS = 512 };
typedef struct nm_ping_backlog nm_ping_backlog;
typedef struct {
    uint64_t pending, free_bytes, reserve_bytes, estimated_seconds;
    bool paused, estimate_known;
    nm_ping_storage_mode mode;
} nm_ping_backlog_stats;

/* All calls are processor-task-local. Returned backlog is owned; model and JSON
 * are borrowed. open discards legacy pending readings or a different backing
 * store's backlog (the explicitly accepted switch policy), retaining parents,
 * monitor configuration, counters and the ID sequence. Invalid same-store
 * metadata/pages fail closed. No persistence occurs until cycle completion. */
nm_ping_backlog *nm_ping_backlog_open(yyjson_mut_val *snapshot, nm_model *model, uint64_t nonce,
                                      size_t window_records);
void nm_ping_backlog_free(nm_ping_backlog *backlog);
/* Adds a bounded delivery window transactionally; no model changes on failure. */
bool nm_ping_backlog_load(nm_ping_backlog *backlog, nm_model *model);
/* Called after all accepted probes drain and publication is attempted. Writes
 * immutable new pages before committing the existing NVS root snapshot, which
 * contains queue cursors/ack masks, not the stored PingInfos. Only successful
 * commit releases the unsaved RAM readings. Failure pauses new probes and keeps
 * both RAM state and the previous durable root/pages. */
bool nm_ping_backlog_save(nm_ping_backlog *backlog, nm_model *model);
uint64_t nm_ping_backlog_pages(const nm_ping_backlog *backlog);
/* During the first-sync pause: rotate one immutable block, then commit its
 * progress with the model. Failure leaves model/root/live pages unchanged.
 * Requires all new RAM readings to have been saved before begin. */
void nm_ping_backlog_time_begin(nm_ping_backlog *backlog);
bool nm_ping_backlog_time_step(nm_ping_backlog *backlog, nm_model *model);
void nm_ping_backlog_reset(nm_ping_backlog *backlog);
/* After validating an acknowledgement on a disposable model candidate, remember
 * removed-monitor cutoffs before committing that candidate. Transactional on
 * failure. Prevents re-adding an ID from resurrecting its old on-disk readings. */
bool nm_ping_backlog_ack(nm_ping_backlog *backlog, const nm_model *before,
                         yyjson_mut_val *response);
bool nm_ping_backlog_room(nm_ping_backlog *backlog, size_t maximum_results);
/* Checks sequence reuse outside RAM when uint32 wraps, at most eight pages per
 * call. False pauses probes until validation completes or colliding IDs drain. */
bool nm_ping_backlog_sequence_safe(nm_ping_backlog *backlog, uint32_t sequence,
                                   size_t maximum_results);
uint64_t nm_ping_backlog_pending(const nm_ping_backlog *backlog, const nm_model *model);
/* Filter an owned COW publication view to the retained delivery window. Newly
 * produced readings become eligible on the next cycle after their store commit.
 * Thus every published unacknowledged reading remains resident for ack matching. */
void nm_ping_backlog_delivery_view(const nm_ping_backlog *backlog, nm_model *view);
nm_ping_backlog_stats nm_ping_backlog_status(nm_ping_backlog *backlog, const nm_model *model,
                                             uint64_t monotonic_seconds);
#endif
