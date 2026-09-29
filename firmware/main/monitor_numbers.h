#ifndef NM_MONITOR_NUMBERS_H
#define NM_MONITOR_NUMBERS_H
#include "yyjson.h"
#include <stdint.h>
#include <stdbool.h>
bool nm_monitor_u64(yyjson_mut_val *,uint64_t *);
bool nm_monitor_u32(yyjson_mut_val *,uint32_t *);
bool nm_monitor_i32(yyjson_mut_val *,int32_t *);
int32_t nm_monitor_add_i32(int32_t,int32_t);
#endif
