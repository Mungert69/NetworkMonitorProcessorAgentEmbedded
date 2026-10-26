#ifndef NM_PING_STORAGE_H
#define NM_PING_STORAGE_H
#include "nm_json.h"
#include <stdbool.h>
#include <stdint.h>

enum { NM_PING_PAGE_RECORDS = 64, NM_PING_PAGE_BYTES = 32768, NM_PING_NVS_PAGES = 64 };
enum { NM_PING_SD_SEGMENT_PAGES = 32 };
typedef enum { NM_PING_STORAGE_NONE, NM_PING_STORAGE_NVS, NM_PING_STORAGE_SD } nm_ping_storage_mode;
typedef struct {
    uint64_t free_bytes, reserve_bytes;
    bool healthy;
} nm_ping_storage_capacity;

/* Startup only. Configuration is borrowed. Failure to mount SD selects NVS;
 * no card is formatted. The selection stays fixed until reboot. */
bool nm_ping_storage_init(yyjson_mut_val *settings, const char *identity);
nm_ping_storage_mode nm_ping_storage_selected(void);
nm_ping_storage_capacity nm_ping_storage_space(void);
/* Bind the previous durable root before staging new blocks. SD appends may
 * truncate only its uncommitted suffix, never a referenced block. No I/O. */
/* Persisted NVS layout adds one scratch slot for crash-safe block rotation.
 * Legacy blocks before split retain modulo-64 addressing. No I/O. */
void nm_ping_storage_layout(bool rotating, uint64_t split, unsigned first_slot);
void nm_ping_storage_begin(uint64_t epoch, uint64_t durable_head, uint64_t durable_tail);
/* Processor-task only. Returned JSON documents are owned by the caller.
 * Pages are immutable while referenced by a committed monitoring snapshot.
 * write may replace only an uncommitted page; failed writes retain live pages. */
yyjson_mut_doc *nm_ping_storage_read(uint64_t epoch, uint64_t page);
bool nm_ping_storage_write(uint64_t epoch, uint64_t page, yyjson_mut_val *value);
bool nm_ping_storage_delete(uint64_t epoch, uint64_t page);
/* Best-effort bounded reclamation after the root commit. Removes only this
 * processor's unreferenced page files/keys, including abandoned store epochs. */
void nm_ping_storage_collect(uint64_t epoch, uint64_t head, uint64_t tail);

#endif
