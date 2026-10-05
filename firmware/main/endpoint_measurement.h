#ifndef NM_ENDPOINT_MEASUREMENT_H
#define NM_ENDPOINT_MEASUREMENT_H
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* Fixed built-in policy, mirroring NetConnect.Measurement and timeout extension.
 * Data/API owns descriptive/analysis metadata through the shared .NET catalogue.
 * Borrowed endpoint name; no allocation or state mutation. */
enum { NM_EXTENDED_DURATION_SCALE = 10 };
static inline unsigned nm_endpoint_duration_scale(const char *type)
{
    return type && (!strcmp(type, "nmap") || !strcmp(type, "blebroadcastlisten"))
               ? NM_EXTENDED_DURATION_SCALE
               : 1;
}
static inline unsigned nm_endpoint_timeout_multiplier(const char *type)
{
    return type && (!strcmp(type, "nmap") || !strcmp(type, "blebroadcastlisten") ||
                    !strcmp(type, "blebroadcast"))
               ? NM_EXTENDED_DURATION_SCALE
               : 1;
}
/* Divide only elapsed durations. Sensor samples are already encoded by their
 * decoder catalogue and must bypass this function. No saturation; configured
 * base timeouts must fit the ushort sample range, just as on .NET. */
static inline uint16_t nm_endpoint_duration_sample(const char *type, bool ok, uint64_t elapsed_ms)
{
    return ok ? (uint16_t)(elapsed_ms / nm_endpoint_duration_scale(type)) : UINT16_MAX;
}
#endif
