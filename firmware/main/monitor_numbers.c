#include "monitor_numbers.h"
#include <limits.h>
bool nm_monitor_u64(yyjson_mut_val *v, uint64_t *out)
{
    if (!out) return false;
    if(yyjson_mut_is_uint(v)) { *out=yyjson_mut_get_uint(v); return true; }
    if(yyjson_mut_is_sint(v) && yyjson_mut_get_sint(v)>=0) {
        *out=(uint64_t)yyjson_mut_get_sint(v); return true;
    }
    return false;
}
bool nm_monitor_u32(yyjson_mut_val *v, uint32_t *out)
{
    uint64_t n; if (!out || !nm_monitor_u64(v, &n) || n > UINT32_MAX) return false;
    *out = (uint32_t)n; return true;
}
bool nm_monitor_i32(yyjson_mut_val *v, int32_t *out)
{
    if (!out) return false;
    if (yyjson_mut_is_uint(v)) {
        uint64_t n = yyjson_mut_get_uint(v);
        if (n > INT32_MAX) return false;
        *out = (int32_t)n; return true;
    }
    if (!yyjson_mut_is_sint(v)) return false;
    int64_t n = yyjson_mut_get_sint(v);
    if (n < INT32_MIN || n > INT32_MAX) return false;
    *out = (int32_t)n; return true;
}
/* Defined conversion rather than relying on implementation-defined uint->int. */
int32_t nm_monitor_add_i32(int32_t left, int32_t right)
{
    uint32_t sum = (uint32_t)left + (uint32_t)right;
    return sum <= INT32_MAX ? (int32_t)sum : -1 - (int32_t)(UINT32_MAX - sum);
}
