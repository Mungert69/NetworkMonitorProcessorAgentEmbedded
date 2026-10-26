#ifndef NM_NETWORK_H
#define NM_NETWORK_H
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
/* Atomic, nonblocking queries. Ready requires IP, an NTP reply and committed timestamp correction
 * in this boot. Once synchronized, temporary NTP failure does not invalidate a running clock. */
bool nm_network_ready(void);
bool nm_network_time_synced(void);
/* Provisional monotonic recording timeline until the processor commits the
 * one-time correction. Offset is published once and remains stable this boot. */
time_t nm_network_recording_time(void);
bool nm_network_correction(int64_t *offset);
/* Processor task only, after corrected snapshot is durable. Nonblocking. */
void nm_network_accept_correction(void);
#endif
