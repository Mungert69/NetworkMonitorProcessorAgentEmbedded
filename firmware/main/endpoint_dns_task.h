#ifndef NM_ENDPOINT_DNS_TASK_H
#define NM_ENDPOINT_DNS_TASK_H
#include <stdbool.h>

/* Initialize once, before concurrent probes. A permanent internal-stack reaper
 * deletes completed PSRAM-stack DNS tasks without allocating on their exit path.
 * Each started task owns an endpoint-operation slot until it has been reaped.
 * Failed start leaves the slot and argument owned by the caller. */
bool nm_dns_tasks_init(void);
bool nm_dns_task_start(void (*run)(void *), void *argument);
/* Worker-only, after releasing its context; never returns on firmware. */
void nm_dns_task_finish(void);
#endif
