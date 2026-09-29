#ifndef NM_MONITOR_SCHEDULE_TYPED_H
#define NM_MONITOR_SCHEDULE_TYPED_H
#include "monitor_model.h"
#include "monitor_schedule.h"
typedef struct {
    char *name, **patterns;
    size_t pattern_count;
    int mode;
    int32_t every,offset,slots,counter,current_offset,total;
    double probability;
} nm_strategy;
typedef struct {
    int32_t id,skip,remaining;
    int64_t day;
    bool has_skip,has_day;
} nm_host_schedule;
typedef struct nm_schedule {
    nm_strategy *strategies;
    size_t strategy_count;
    nm_host_schedule *hosts;
    size_t host_count,host_limit;
    char *encoded_strategies; /* immutable wire metadata, not working state */
    bool initialized,changed;
} nm_schedule;
bool nm_schedule_open(nm_schedule *,yyjson_mut_val *saved,size_t limit);
bool nm_schedule_configure(nm_schedule *,yyjson_mut_val *config);
bool nm_schedule_clone(nm_schedule *,const nm_schedule *);
void nm_schedule_close(nm_schedule *);
yyjson_mut_val *nm_schedule_encode(yyjson_mut_doc *,const nm_schedule *);
bool nm_schedule_prepare(nm_schedule *,const nm_records *,int64_t now);
/* Stable across restarts; .NET's process-seeded string hash assigns different slots. */
int32_t nm_schedule_daily_hash(int32_t monitor_id);
bool nm_schedule_include(nm_schedule *,const nm_monitor_record *,int64_t now,
    nm_monitor_schedule_random_fn random_next,void *context,int32_t hash,bool *include);
#endif
