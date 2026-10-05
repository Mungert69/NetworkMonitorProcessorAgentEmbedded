#ifndef NM_MONITOR_MODEL_H
#define NM_MONITOR_MODEL_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "yyjson.h"

/* Owned, typed runtime records. JSON is used by the codec only. Unknown or
 * specialist fields are retained as immutable encoded extension data, never
 * used as mutable working state. Records are shared by snapshots until edited.
 * All access is confined to the processor task (reference counts are not atomic).
 */
typedef struct nm_extension nm_extension;
typedef enum { NM_MONITOR, NM_STATUS, NM_PING, NM_SWAP, NM_PARAMS, NM_FLOW } nm_record_kind;
typedef struct {
    size_t references;
    uint64_t present, nulls;
    nm_record_kind kind;
    nm_extension *extension;
} nm_record;

#define NM_MONITOR_FIELDS(X)                                                                       \
    X(int32_t, ID, I32)                                                                            \
    X(int32_t, MonitorIPID, I32) X(int32_t, MonitorPingInfoID, I32) X(int32_t, DataSetID, I32)     \
        X(int32_t, Timeout, I32) X(uint16_t, Port, U16) X(double, LowThreshold, NDOUBLE) X(        \
            double, HighThreshold, NDOUBLE) X(nm_extension *, MeasurementBreach, JSON)             \
            X(int32_t, SkipCycles, NI32) X(bool, Enabled, BOOL) X(bool, IsEnabled, BOOL) X(        \
                bool, IsEmailVerified, BOOL) X(bool, Delete, BOOL) X(bool, DeleteAll, BOOL)        \
                X(bool, IsSwapping, BOOL) X(int32_t, PacketsSent, I32) X(                          \
                    int32_t, PacketsRecieved, I32) X(int32_t, PacketsLost, I32)                    \
                    X(float, PacketsLostPercentage, FLOAT) X(float, RoundTripTimeAverage, FLOAT)   \
                        X(int32_t, RoundTripTimeMinimum,                                           \
                          I32) X(int32_t, RoundTripTimeMaximum,                                    \
                                 I32) X(int32_t, RoundTripTimeTotal, I32)                          \
                            X(bool, IsArchived, BOOL) X(bool, IsDirtyDownCount, BOOL)              \
                                X(char *, AppID, STRING) X(char *, Address, STRING)                \
                                    X(char *, EndPointType, STRING)                                \
                                        X(char *, Host, STRING)                                    \
                                            X(char *, UserID, STRING) X(char *, Username, STRING)  \
                                                X(char *, Password, STRING) X(char *,              \
                                                                              Args, STRING)        \
                                                    X(char *, AddUserEmail, STRING)                \
                                                        X(char *, Status, STRING)                  \
                                                            X(char *, DateStarted, STRING)         \
                                                                X(char *, DateEnded, STRING)       \
                                                                    X(char *, SiteHash, STRING)    \
                                                                        X(nm_status_record *,      \
                                                                          MonitorStatus, STATUS)
#define NM_STATUS_FIELDS(X) \
 X(int32_t,ID,I32) X(int32_t,MonitorPingInfoID,I32) X(int32_t,DownCount,I32) \
 X(bool,AlertFlag,BOOL) X(bool,AlertSent,BOOL) X(bool,IsUp,NBOOL) \
 X(char *,EventTime,STRING) X(char *,Message,STRING)
/* PingInfo.Status must be a fixed category label: the backend interns each
 * distinct string in StatusList using a finite uint16_t StatusID space.
 * Never append measurements, addresses, timestamps, payloads or variable error
 * details. Use "BLE battery_voltage", not "BLE battery_voltage=13.67V".
 * Keep changing diagnostics in monitor messages and retain the endpoint's
 * existing numeric sample/scaling in RoundTripTime. Applies to all endpoints. */
#define NM_PING_FIELDS(X) \
 X(uint64_t,ID,U64) X(int32_t,MonitorPingInfoID,I32) X(uint32_t,DateSentInt,U32) \
 X(uint16_t,RoundTripTime,NU16) X(uint16_t,StatusID,U16) X(int32_t,RoundTripTimeInt,I32) \
 X(char *,DateSent,STRING) X(char *,Status,STRING)
#define NM_SWAP_FIELDS(X) X(int32_t,ID,I32) X(char *,AppID,STRING)
#define NM_PARAMS_FIELDS(X) X(int32_t,Timeout,I32)
#define NM_FLOW_FIELDS(X) X(bool,IsLoggedInWebsite,NBOOL) X(bool,IsHostsAdded,NBOOL)
#define NM_FIELD(type,name,kind) type name;
typedef struct nm_status_record { nm_record base; NM_STATUS_FIELDS(NM_FIELD) } nm_status_record;
typedef struct { nm_record base; NM_MONITOR_FIELDS(NM_FIELD) } nm_monitor_record;
typedef struct { nm_record base; NM_PING_FIELDS(NM_FIELD) } nm_ping_record;
typedef struct { nm_record base; NM_SWAP_FIELDS(NM_FIELD) } nm_swap_record;
typedef struct { nm_record base; NM_PARAMS_FIELDS(NM_FIELD) } nm_params_record;
typedef struct { nm_record base; NM_FLOW_FIELDS(NM_FIELD) } nm_flow_record;
#undef NM_FIELD
#define NM_FIELD(type,name,kind) NM_M_##name,
enum { NM_MONITOR_FIELDS(NM_FIELD) NM_M_FIELDS };
#undef NM_FIELD
#define NM_FIELD(type,name,kind) NM_S_##name,
enum { NM_STATUS_FIELDS(NM_FIELD) NM_S_FIELDS };
#undef NM_FIELD
#define NM_FIELD(type,name,kind) NM_P_##name,
enum { NM_PING_FIELDS(NM_FIELD) NM_P_FIELDS };
#undef NM_FIELD
#define NM_FIELD(type,name,kind) NM_W_##name,
enum { NM_SWAP_FIELDS(NM_FIELD) NM_W_FIELDS };
#undef NM_FIELD
enum { NM_PARAM_Timeout };
enum { NM_F_IsLoggedInWebsite, NM_F_IsHostsAdded };

typedef struct { nm_record **items; size_t count, capacity, limit; } nm_records;
typedef struct {
    nm_records hosts, infos, pings, removepings, removals, swaps;
    nm_params_record *params;
    nm_flow_record *flow;
    nm_extension *root_extra, *data_extra;
    struct nm_schedule *schedule;
    uint32_t sequence;
    bool changed;
} nm_model;

bool nm_record_has(const nm_record *r, unsigned field);
bool nm_record_null(const nm_record *r, unsigned field);
void nm_record_mark(nm_record *r, unsigned field, bool is_null);
nm_record *nm_record_new(nm_record_kind kind);
nm_record *nm_record_retain(nm_record *record);
void nm_record_release(nm_record *record);
nm_record *nm_record_copy(const nm_record *record);
bool nm_record_string(nm_record *record, unsigned field, const char *value);
nm_record *nm_record_decode(nm_record_kind kind, yyjson_mut_val *value);
yyjson_mut_val *nm_record_encode(yyjson_mut_doc *doc, const nm_record *record);
bool nm_records_append(nm_records *records, nm_record *owned);
void nm_records_remove(nm_records *records, size_t index);
void nm_records_free(nm_records *records);
bool nm_records_clone(nm_records *out, const nm_records *source);
nm_record *nm_records_edit(nm_records *records, size_t index);
nm_monitor_record *nm_model_info(const nm_model *model, int32_t id);
nm_monitor_record *nm_model_host(const nm_model *model, int32_t id);
bool nm_model_open(nm_model *model, yyjson_mut_val *snapshot,
                   yyjson_mut_val *legacy, yyjson_mut_val *hosts,
                   size_t max_monitors, size_t max_pings);
yyjson_mut_doc *nm_model_encode(const nm_model *model);
bool nm_model_clone(nm_model *out, const nm_model *source);
void nm_model_close(nm_model *model);
bool nm_model_updates(nm_model *, yyjson_mut_val *, const char *, const char *);
bool nm_model_init(nm_model *, yyjson_mut_val *, const char *, const char *);
bool nm_model_ack(nm_model *, yyjson_mut_val *);
bool nm_model_alert(nm_model *, const char *, yyjson_mut_val *, const char *);
bool nm_model_user_event(nm_model *, yyjson_mut_val *);
bool nm_model_reconcile(nm_model *, const char *, const char *);
/* Metadata strings are borrowed and copied into a latched breach. Call on a
 * disposable candidate; allocation failure must abort that candidate. */
bool nm_model_measurement_alert(nm_model *, int32_t id, uint16_t sample, double scale,
                                double offset, const char *unit, const char *when);
bool nm_model_probe(nm_model *, int32_t id, bool up, uint16_t rtt,
                    const char *status, const char *message, const char *when, uint32_t date);
#endif
