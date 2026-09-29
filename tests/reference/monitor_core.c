#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "monitor_core.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define GET yyjson_mut_obj_get
#define ROOT(c) yyjson_mut_doc_get_root((c)->doc)
#define TRY(x) do { if (!(x)) return false; } while (0)
static const char *arrays[] = { "MonitorPingInfos", "PingInfos", "RemovePingInfos",
    "RemoveMonitorPingInfoIDs", "SwapMonitorPingInfos", "MonitorStatusAlerts",
    "PredictStatusAlerts", "StatusList", "MonitorIPs" };

static bool put(nm_monitor_core *c, yyjson_mut_val *o, const char *k, yyjson_mut_val *v)
{ return v && yyjson_mut_obj_put(o, yyjson_mut_str(c->doc, k), v); }
static bool integer(nm_monitor_core *c, yyjson_mut_val *o, const char *k, int32_t n)
{ return put(c, o, k, yyjson_mut_sint(c->doc, n)); }
static bool text(nm_monitor_core *c, yyjson_mut_val *o, const char *k, const char *s)
{ return s && put(c, o, k, yyjson_mut_strcpy(c->doc, s)); }
static bool flag(nm_monitor_core *c, yyjson_mut_val *o, const char *k, bool b)
{ return put(c, o, k, yyjson_mut_bool(c->doc, b)); }
static bool copy(nm_monitor_core *c, yyjson_mut_val *o, const char *k, yyjson_mut_val *v)
{ return v && put(c, o, k, yyjson_mut_val_mut_copy(c->doc, v)); }
static int32_t i32(yyjson_mut_val *o, const char *key, int32_t fallback)
{ int32_t n; return nm_monitor_i32(GET(o,key), &n) ? n : fallback; }
static bool same_text(yyjson_mut_val *v, const char *s)
{ const char *p = yyjson_mut_get_str(v); return p && s && !strcmp(p,s); }
static yyjson_mut_val *find(yyjson_mut_val *arr, const char *key, int32_t id)
{
    size_t i, n; yyjson_mut_val *v;
    yyjson_mut_arr_foreach(arr, i, n, v) if (i32(v,key,-1)==id) return v;
    return NULL;
}
static bool delete_id(yyjson_mut_val *arr, const char *key, int32_t id)
{
    for (size_t i=yyjson_mut_arr_size(arr); i>0; --i)
        if (i32(yyjson_mut_arr_get(arr,i-1),key,-1)==id)
            if (!yyjson_mut_arr_remove(arr,i-1)) return false;
    return true;
}
yyjson_mut_val *nm_monitor_root(const nm_monitor_core *c) { return c && c->doc ? ROOT(c) : NULL; }
yyjson_mut_val *nm_monitor_data(const nm_monitor_core *c) { return GET(nm_monitor_root(c),"ProcessorData"); }
yyjson_mut_val *nm_monitor_hosts(const nm_monitor_core *c) { return GET(nm_monitor_root(c),"MonitorIPs"); }
yyjson_mut_val *nm_monitor_info(const nm_monitor_core *c, int32_t id)
{ return find(GET(nm_monitor_data(c),"MonitorPingInfos"),"MonitorIPID",id); }
void nm_monitor_close(nm_monitor_core *c) { if (c) { yyjson_mut_doc_free(c->doc); c->doc=NULL; } }

static bool valid_ids(yyjson_mut_val *arr, const char *key, bool wide)
{
    if (!yyjson_mut_is_arr(arr)) return false;
    size_t i,n; yyjson_mut_val *v;
    yyjson_mut_arr_foreach(arr,i,n,v) {
        uint64_t u; int32_t s;
        yyjson_mut_val *id = key ? GET(v,key) : v;
        if (wide ? !nm_monitor_u64(id,&u) : !nm_monitor_i32(id,&s)) return false;
    }
    return true;
}
static bool valid_i32_fields(yyjson_mut_val *obj, const char *const *keys, size_t count)
{
    if(!yyjson_mut_is_obj(obj)) return false;
    for(size_t i=0;i<count;++i) {
        yyjson_mut_val *v=GET(obj,keys[i]); int32_t n;
        if(v && !nm_monitor_i32(v,&n)) return false;
    }
    return true;
}
static bool valid_host(yyjson_mut_val *host)
{
    static const char *const ints[]={"ID","Timeout"};
    TRY(valid_i32_fields(host,ints,sizeof(ints)/sizeof(ints[0])));
    yyjson_mut_val *v=GET(host,"Port"); uint64_t n;
    if(v) TRY(nm_monitor_u64(v,&n) && n<=UINT16_MAX);
    v=GET(host,"SkipCycles"); int32_t skip;
    if(v && !yyjson_mut_is_null(v)) TRY(nm_monitor_i32(v,&skip));
    const char *bools[]={"Enabled","IsEmailVerified","Delete","DeleteAll","IsSwapping"};
    for(size_t i=0;i<sizeof(bools)/sizeof(bools[0]);++i) {
        v=GET(host,bools[i]); if(v) TRY(yyjson_mut_is_bool(v));
    }
    return true;
}
static bool validate(nm_monitor_core *c)
{
    yyjson_mut_val *data=nm_monitor_data(c); uint32_t sequence;
    TRY(yyjson_mut_is_obj(ROOT(c)) && yyjson_mut_is_obj(data));
    TRY(nm_monitor_u32(GET(data,"PiIDKey"),&sequence));
    TRY(valid_ids(nm_monitor_hosts(c),"ID",false));
    TRY(valid_ids(GET(data,"MonitorPingInfos"),"MonitorIPID",false));
    TRY(valid_ids(GET(data,"PingInfos"),"ID",true));
    TRY(valid_ids(GET(data,"PingInfos"),"MonitorPingInfoID",false));
    TRY(valid_ids(GET(data,"RemovePingInfos"),"ID",true));
    TRY(valid_ids(GET(data,"RemoveMonitorPingInfoIDs"),NULL,false));
    TRY(valid_ids(GET(data,"SwapMonitorPingInfos"),"ID",false));
    size_t i,n; yyjson_mut_val *v;
    yyjson_mut_arr_foreach(nm_monitor_hosts(c),i,n,v) TRY(valid_host(v));
    static const char *const stats[]={"ID","MonitorIPID","DataSetID","Timeout","PacketsSent","PacketsRecieved",
        "PacketsLost","RoundTripTimeMinimum","RoundTripTimeMaximum","RoundTripTimeTotal"};
    yyjson_mut_arr_foreach(GET(data,"MonitorPingInfos"),i,n,v) {
        TRY(valid_i32_fields(v,stats,sizeof(stats)/sizeof(stats[0])));
        yyjson_mut_val *status=GET(v,"MonitorStatus");
        if(status) {
            static const char *const fields[]={"ID","DownCount","MonitorPingInfoID"};
            TRY(valid_i32_fields(status,fields,sizeof(fields)/sizeof(fields[0])));
        }
    }
    yyjson_mut_arr_foreach(GET(data,"PingInfos"),i,n,v) {
        uint64_t value; uint32_t date; int32_t rtt;
        yyjson_mut_val *p=GET(v,"RoundTripTime");
        if(p && !yyjson_mut_is_null(p)) TRY(nm_monitor_u64(p,&value) && value<=UINT16_MAX);
        p=GET(v,"StatusID"); if(p) TRY(nm_monitor_u64(p,&value) && value<=UINT16_MAX);
        p=GET(v,"DateSentInt"); if(p) TRY(nm_monitor_u32(p,&date));
        p=GET(v,"RoundTripTimeInt"); if(p) TRY(nm_monitor_i32(p,&rtt));
    }
    return true;
}
bool nm_monitor_open(nm_monitor_core *c, yyjson_mut_val *snapshot,
                     yyjson_mut_val *legacy, yyjson_mut_val *hosts)
{
    c->doc=yyjson_mut_doc_new(NULL); if (!c->doc) return false;
    yyjson_mut_val *root=snapshot ? yyjson_mut_val_mut_copy(c->doc,snapshot) : yyjson_mut_obj(c->doc);
    yyjson_mut_doc_set_root(c->doc,root);
    if (!root || !yyjson_mut_is_obj(root)) goto fail;
    if (!snapshot) {
        yyjson_mut_val *data=legacy ? yyjson_mut_val_mut_copy(c->doc,legacy) : yyjson_mut_obj(c->doc);
        if (!put(c,root,"ProcessorData",data) || !yyjson_mut_is_obj(data) ||
            !put(c,root,"MonitorIPs",hosts ? yyjson_mut_val_mut_copy(c->doc,hosts) : yyjson_mut_arr(c->doc))) goto fail;
        if (!GET(data,"PiIDKey") && !put(c,data,"PiIDKey",yyjson_mut_uint(c->doc,1))) goto fail;
        for (size_t i=0;i<sizeof(arrays)/sizeof(arrays[0]);++i)
            if (!GET(data,arrays[i]) && !put(c,data,arrays[i],yyjson_mut_arr(c->doc))) goto fail;
        if (!put(c,root,"PingParams",yyjson_mut_obj(c->doc)) ||
            !put(c,root,"AgentUserFlow",yyjson_mut_obj(c->doc)) ||
            !put(c,root,"Schedule",yyjson_mut_obj(c->doc))) goto fail;
    }
    if (validate(c)) return true;
fail: nm_monitor_close(c); return false;
}
bool nm_monitor_clone(nm_monitor_core *out, const nm_monitor_core *source)
{ out->doc=yyjson_mut_doc_mut_copy(source->doc,NULL); return out->doc!=NULL; }
bool nm_monitor_commit(nm_monitor_core *current, nm_monitor_core *candidate,
                       nm_monitor_save save, void *context)
{
    TRY(validate(candidate) && save && save(context,ROOT(candidate)));
    nm_monitor_close(current); current->doc=candidate->doc; candidate->doc=NULL; return true;
}
static bool pending_remove(yyjson_mut_val *arr, int32_t id)
{
    size_t i,n; yyjson_mut_val *v;
    yyjson_mut_arr_foreach(arr,i,n,v) { int32_t x; if(nm_monitor_i32(v,&x) && x==id) return true; }
    return false;
}
static bool prune_drained(nm_monitor_core *c)
{
    yyjson_mut_val *data=nm_monitor_data(c),*infos=GET(data,"MonitorPingInfos");
    for(size_t i=yyjson_mut_arr_size(infos);i>0;--i) {
        int32_t id=i32(yyjson_mut_arr_get(infos,i-1),"MonitorIPID",-1);
        if(!find(nm_monitor_hosts(c),"ID",id) && !find(GET(data,"PingInfos"),"MonitorPingInfoID",id) &&
           !find(GET(data,"SwapMonitorPingInfos"),"ID",id) && !pending_remove(GET(data,"RemoveMonitorPingInfoIDs"),id))
            TRY(yyjson_mut_arr_remove(infos,i-1));
    }
    return true;
}

bool nm_monitor_ack(nm_monitor_core *c, yyjson_mut_val *response)
{
    TRY(yyjson_mut_is_obj(response));
    const char *names[]={"RemovePingInfos","RemoveMonitorPingInfoIDs","SwapMonitorPingInfos"};
    for (size_t a=0;a<3;++a) {
        yyjson_mut_val *acks=GET(response,names[a]);
        if (!acks || yyjson_mut_is_null(acks)) continue;
        TRY(valid_ids(acks,a==1?NULL:"ID",a==0));
        yyjson_mut_val *pending=GET(nm_monitor_data(c),a==0?"PingInfos":names[a]);
        for (size_t i=yyjson_mut_arr_size(pending);i>0;--i) {
            yyjson_mut_val *p=yyjson_mut_arr_get(pending,i-1),*ack; size_t j,n;
            yyjson_mut_arr_foreach(acks,j,n,ack) {
                bool match=false;
                if (a==0) {
                    uint64_t x,y; TRY(nm_monitor_u64(GET(p,"ID"),&x)); TRY(nm_monitor_u64(GET(ack,"ID"),&y));
                    match=x==y; /* .NET ConcurrentDictionary<ulong, PingInfo> key. */
                } else if (a==1) {
                    int32_t x,y; TRY(nm_monitor_i32(p,&x)); TRY(nm_monitor_i32(ack,&y)); match=x==y;
                } else {
                    /* SwapMonitorPingInfoComparer uses ID only, not AppID. */
                    match=i32(p,"ID",-1)==i32(ack,"ID",-2);
                }
                if (match) { TRY(yyjson_mut_arr_remove(pending,i-1)); break; }
            }
        }
        if(a==1) {
            /* The backend has acknowledged deletion of this entire dataset.
             * Retire its residual events only when the host is no longer owned
             * here. This is an application acknowledgement, never PUBACK. */
            size_t i,n; yyjson_mut_val *ack;
            yyjson_mut_arr_foreach(acks,i,n,ack) {
                int32_t id; TRY(nm_monitor_i32(ack,&id));
                if(!find(nm_monitor_hosts(c),"ID",id)) {
                    TRY(delete_id(GET(nm_monitor_data(c),"PingInfos"),"MonitorPingInfoID",id));
                    TRY(delete_id(GET(nm_monitor_data(c),"MonitorPingInfos"),"MonitorIPID",id));
                }
            }
        }
    }
    return prune_drained(c);
}

static bool fill(nm_monitor_core *c, yyjson_mut_val *info, yyjson_mut_val *host,
                 const char *app, const char *when)
{
    int32_t id; TRY(valid_host(host) && nm_monitor_i32(GET(host,"ID"),&id) && id>=0);
    bool fresh=!GET(info,"MonitorIPID");
    TRY(integer(c,info,"ID",id) && integer(c,info,"MonitorPingInfoID",id) && integer(c,info,"MonitorIPID",id) && text(c,info,"AppID",app));
    const char *fields[]={"Address","EndPointType","Port","Enabled","UserID","Username","Password",
        "Args","AddUserEmail","IsEmailVerified","SkipCycles"};
    for(size_t i=0;i<sizeof(fields)/sizeof(fields[0]);++i) {
        yyjson_mut_val *value=GET(host,fields[i]);
        if(value) TRY(copy(c,info,fields[i],value));
        else if(!strcmp(fields[i],"Port")) TRY(put(c,info,fields[i],yyjson_mut_uint(c->doc,0)));
        else if(!strcmp(fields[i],"Enabled") || !strcmp(fields[i],"IsEmailVerified")) TRY(flag(c,info,fields[i],false));
        else TRY(put(c,info,fields[i],yyjson_mut_null(c->doc)));
    }
    int32_t timeout=i32(host,"Timeout",0);
    if (timeout==0) timeout=i32(GET(ROOT(c),"PingParams"),"Timeout",59000);
    TRY(integer(c,info,"Timeout",timeout));
    TRY(copy(c,info,"Host",GET(info,"Address")));
    if(!fresh) return true;
    TRY(integer(c,info,"ID",id) && integer(c,info,"MonitorPingInfoID",id));
    const char *zero[]={"DataSetID","PacketsSent","PacketsRecieved","PacketsLost","PacketsLostPercentage",
        "RoundTripTimeAverage","RoundTripTimeMaximum","RoundTripTimeTotal"};
    for(size_t i=0;i<sizeof(zero)/sizeof(zero[0]);++i) TRY(integer(c,info,zero[i],0));
    /* MonitorPingInfo constructor default; Zero() uses PingParams.Timeout later. */
    TRY(integer(c,info,"RoundTripTimeMinimum",9999));
    TRY(text(c,info,"DateStarted",when) && text(c,info,"DateEnded",when));
    const char *nulls[]={"PredictStatus","MessageForUser","AgentLocation","ModelConfig","EffectiveModelParameters","SiteHash"};
    for(size_t i=0;i<sizeof(nulls)/sizeof(nulls[0]);++i) TRY(put(c,info,nulls[i],yyjson_mut_null(c->doc)));
    const char *optional[]={"UserID","Username","Password","Args","AddUserEmail","SkipCycles"};
    for(size_t i=0;i<sizeof(optional)/sizeof(optional[0]);++i)
        if(!GET(info,optional[i])) TRY(put(c,info,optional[i],yyjson_mut_null(c->doc)));
    if(!GET(info,"Port")) TRY(put(c,info,"Port",yyjson_mut_uint(c->doc,0)));
    if(!GET(info,"Enabled")) TRY(flag(c,info,"Enabled",false));
    if(!GET(info,"IsEmailVerified")) TRY(flag(c,info,"IsEmailVerified",false));
    TRY(put(c,info,"PingInfos",yyjson_mut_arr(c->doc)) && flag(c,info,"IsArchived",false) && flag(c,info,"IsDirtyDownCount",false));
    yyjson_mut_val *s=yyjson_mut_obj(c->doc); TRY(put(c,info,"MonitorStatus",s));
    TRY(integer(c,s,"ID",0) && integer(c,s,"DownCount",0) && integer(c,s,"MonitorPingInfoID",0));
    TRY(flag(c,s,"AlertFlag",false) && flag(c,s,"AlertSent",false));
    TRY(put(c,s,"IsUp",yyjson_mut_null(c->doc)) && put(c,s,"EventTime",yyjson_mut_null(c->doc)));
    TRY(text(c,s,"Message","") && text(c,info,"Status",""));
    return true;
}

bool nm_monitor_reconcile(nm_monitor_core *c, const char *app, const char *when)
{
    size_t i,n; yyjson_mut_val *host;
    yyjson_mut_arr_foreach(nm_monitor_hosts(c),i,n,host) {
        int32_t id; TRY(nm_monitor_i32(GET(host,"ID"),&id));
        yyjson_mut_val *info=nm_monitor_info(c,id);
        if(!info) {
            info=yyjson_mut_obj(c->doc); TRY(info && yyjson_mut_arr_append(GET(nm_monitor_data(c),"MonitorPingInfos"),info));
            TRY(fill(c,info,host,app,when));
        }
    }
    yyjson_mut_val *info;
    yyjson_mut_arr_foreach(GET(nm_monitor_data(c),"MonitorPingInfos"),i,n,info)
        if(!find(nm_monitor_hosts(c),"ID",i32(info,"MonitorIPID",-1))) TRY(flag(c,info,"Enabled",false));
    return true;
}

bool nm_monitor_updates(nm_monitor_core *c, yyjson_mut_val *updates,
                        const char *app, unsigned maximum, const char *when)
{
    TRY(yyjson_mut_is_arr(updates));
    yyjson_mut_val *hosts=nm_monitor_hosts(c), *data=nm_monitor_data(c),*infos=GET(data,"MonitorPingInfos");
    size_t i,n; yyjson_mut_val *u;
    yyjson_mut_arr_foreach(updates,i,n,u) {
        int32_t id; TRY(valid_host(u) && nm_monitor_i32(GET(u,"ID"),&id) && id>=0);
        bool all=yyjson_mut_is_true(GET(u,"DeleteAll")), deleted=yyjson_mut_is_true(GET(u,"Delete"));
        if (all) {
            TRY(yyjson_mut_arr_clear(hosts));
            /* Existing pending data remains available for its acknowledgement. */
            continue;
        }
        yyjson_mut_val *existing=find(infos,"MonitorIPID",id);
        TRY(delete_id(hosts,"ID",id));
        if(deleted) {
            if(existing && !yyjson_mut_is_true(GET(u,"IsSwapping")) && !pending_remove(GET(data,"RemoveMonitorPingInfoIDs"),id))
                TRY(yyjson_mut_arr_append(GET(data,"RemoveMonitorPingInfoIDs"),yyjson_mut_sint(c->doc,id)));
            /* Retain info while its pending pings still need sending, but never probe it. */
            if(existing) TRY(flag(c,existing,"Enabled",false));
            continue;
        }
        TRY(yyjson_mut_arr_append(hosts,yyjson_mut_val_mut_copy(c->doc,u)));
        TRY(yyjson_mut_arr_size(hosts)<=maximum);
        yyjson_mut_val *supplied=GET(u,"MonitorPingInfo");
        if(!existing && yyjson_mut_is_true(GET(u,"IsSwapping")) && yyjson_mut_is_obj(supplied)) {
            TRY(i32(supplied,"MonitorIPID",-1)==id);
            existing=yyjson_mut_val_mut_copy(c->doc,supplied);
            TRY(existing && text(c,existing,"AppID",app) && yyjson_mut_arr_append(infos,existing));
            yyjson_mut_val *swap=yyjson_mut_obj(c->doc);
            TRY(integer(c,swap,"ID",id) && text(c,swap,"AppID",app));
            TRY(yyjson_mut_arr_append(GET(data,"SwapMonitorPingInfos"),swap));
        } else {
            if(!existing) { existing=yyjson_mut_obj(c->doc); TRY(existing && yyjson_mut_arr_append(infos,existing)); }
            TRY(fill(c,existing,u,app,when));
        }
    }
    TRY(prune_drained(c));
    /* Retained hosts consume the same configured resource budget until their
     * data drains. Repeated add/delete during an outage must not grow metadata. */
    TRY(yyjson_mut_arr_size(infos)<=maximum);
    TRY(yyjson_mut_arr_size(GET(data,"RemoveMonitorPingInfoIDs"))<=maximum);
    TRY(yyjson_mut_arr_size(GET(data,"SwapMonitorPingInfos"))<=maximum);
    return true;
}

bool nm_monitor_init(nm_monitor_core *c, yyjson_mut_val *request,
                     const char *app, unsigned maximum, const char *when)
{
    TRY(yyjson_mut_is_obj(request));
    if(yyjson_mut_is_true(GET(request,"TotalReset"))) {
        nm_monitor_core empty={0}; TRY(nm_monitor_open(&empty,NULL,NULL,NULL));
        nm_monitor_close(c); *c=empty;
    }
    yyjson_mut_val *params=GET(request,"PingParams");
    yyjson_mut_val *data=nm_monitor_data(c);
    if(yyjson_mut_is_true(GET(request,"Reset"))) {
        yyjson_mut_val *info; size_t i,n;
        const char *zeros[]={"PacketsLost","PacketsLostPercentage","PacketsRecieved","PacketsSent",
            "RoundTripTimeAverage","RoundTripTimeMaximum","RoundTripTimeTotal"};
        yyjson_mut_arr_foreach(GET(data,"MonitorPingInfos"),i,n,info) {
            for(size_t j=0;j<sizeof(zeros)/sizeof(zeros[0]);++j) TRY(integer(c,info,zeros[j],0));
            TRY(integer(c,info,"RoundTripTimeMinimum",i32(GET(ROOT(c),"PingParams"),"Timeout",59000)));
            TRY(text(c,info,"DateStarted",when));
        }
        TRY(put(c,data,"PingInfos",yyjson_mut_arr(c->doc)) && put(c,data,"PiIDKey",yyjson_mut_uint(c->doc,1)));
    }
    /* .NET zeroes existing datasets before applying the incoming PingParams. */
    if(params && !yyjson_mut_is_null(params)) {
        TRY(yyjson_mut_is_obj(params));
        yyjson_mut_val *timeout=GET(params,"Timeout"); int32_t value;
        if(timeout) TRY(nm_monitor_i32(timeout,&value));
        TRY(copy(c,ROOT(c),"PingParams",params));
    }
    yyjson_mut_val *hosts=GET(request,"MonitorIPs");
    if(hosts && !yyjson_mut_is_null(hosts)) {
        TRY(yyjson_mut_is_arr(hosts) && yyjson_mut_arr_size(hosts)<=maximum);
        TRY(put(c,ROOT(c),"MonitorIPs",yyjson_mut_arr(c->doc)));
        TRY(nm_monitor_updates(c,hosts,app,maximum,when));
    }
    return true;
}
bool nm_monitor_alert(nm_monitor_core *c, const char *operation, yyjson_mut_val *ids, const char *app)
{
    TRY(valid_ids(ids,NULL,false));
    bool reset=!strcmp(operation,"processorResetAlerts");
    const char *key=!strcmp(operation,"processorAlertFlag")?"AlertFlag":
                    !strcmp(operation,"processorAlertSent")?"AlertSent":NULL;
    TRY(reset || key);
    size_t i,n; yyjson_mut_val *v;
    yyjson_mut_arr_foreach(ids,i,n,v) {
        int32_t id; TRY(nm_monitor_i32(v,&id));
        yyjson_mut_val *info=find(GET(nm_monitor_data(c),"MonitorPingInfos"),"MonitorIPID",id);
        /* .NET reports each absent ID but continues applying the other IDs. */
        if(!info || (reset && !same_text(GET(info,"AppID"),app))) continue;
        yyjson_mut_val *s=GET(info,"MonitorStatus"); TRY(yyjson_mut_is_obj(s));
        if(reset) {
            TRY(flag(c,s,"AlertFlag",false) && flag(c,s,"AlertSent",false) && integer(c,s,"DownCount",0));
            TRY(flag(c,info,"IsDirtyDownCount",true));
            if(same_text(GET(info,"EndPointType"),"sitehash")) TRY(put(c,info,"SiteHash",yyjson_mut_null(c->doc)));
        } else TRY(flag(c,s,key,true));
    }
    return true;
}
bool nm_monitor_user_event(nm_monitor_core *c, yyjson_mut_val *event)
{
    TRY(yyjson_mut_is_obj(event));
    const char *fields[]={"IsLoggedInWebsite","IsHostsAdded"};
    for(size_t i=0;i<2;++i) {
        yyjson_mut_val *v=GET(event,fields[i]);
        if(v && !yyjson_mut_is_null(v)) {
            TRY(yyjson_mut_is_bool(v)); TRY(copy(c,GET(ROOT(c),"AgentUserFlow"),fields[i],v));
        }
    }
    return true;
}
bool nm_monitor_probe(nm_monitor_core *c, yyjson_mut_val *host, bool up, uint16_t rtt,
                      const char *status, const char *message, const char *when, uint32_t date)
{
    yyjson_mut_val *data=nm_monitor_data(c),*pings=GET(data,"PingInfos");
    int32_t id; uint32_t sequence;
    TRY(nm_monitor_i32(GET(host,"ID"),&id) && nm_monitor_u32(GET(data,"PiIDKey"),&sequence));
    yyjson_mut_val *info=find(GET(data,"MonitorPingInfos"),"MonitorIPID",id);
    TRY(info);
    /* Match uint counter rollover, but do not discard a pending sample by reusing its key. */
    size_t i,n; yyjson_mut_val *v;
    yyjson_mut_arr_foreach(pings,i,n,v) { uint64_t p; TRY(nm_monitor_u64(GET(v,"ID"),&p)); TRY(p!=sequence); }
    yyjson_mut_val *s=GET(info,"MonitorStatus"); TRY(yyjson_mut_is_obj(s));
    int32_t sent=nm_monitor_add_i32(i32(info,"PacketsSent",0),1);
    int32_t received=i32(info,"PacketsRecieved",0), lost=i32(info,"PacketsLost",0);
    TRY(integer(c,info,"PacketsSent",sent));
    if(up) {
        received=nm_monitor_add_i32(received,1);
        int32_t total=nm_monitor_add_i32(i32(info,"RoundTripTimeTotal",0),rtt);
        TRY(integer(c,info,"PacketsRecieved",received) && integer(c,info,"RoundTripTimeTotal",total));
        if(i32(info,"RoundTripTimeMinimum",59000)>rtt) TRY(integer(c,info,"RoundTripTimeMinimum",rtt));
        if(i32(info,"RoundTripTimeMaximum",0)<rtt) TRY(integer(c,info,"RoundTripTimeMaximum",rtt));
        TRY(put(c,info,"RoundTripTimeAverage",yyjson_mut_real(c->doc,(float)total/(float)received)));
        TRY(integer(c,s,"DownCount",0) && flag(c,info,"IsDirtyDownCount",false));
    } else {
        lost=nm_monitor_add_i32(lost,1);
        TRY(integer(c,info,"PacketsLost",lost) && integer(c,s,"DownCount",nm_monitor_add_i32(i32(s,"DownCount",0),1)));
    }
    TRY(put(c,info,"PacketsLostPercentage",yyjson_mut_real(c->doc,(float)((double)lost/(double)sent*100))));
    if(yyjson_mut_is_true(GET(info,"IsDirtyDownCount"))) TRY(integer(c,s,"DownCount",0) && flag(c,info,"IsDirtyDownCount",false));
    TRY(flag(c,s,"IsUp",up) && text(c,s,"EventTime",when) && text(c,s,"Message",message) && text(c,info,"Status",message));
    yyjson_mut_val *ping=yyjson_mut_obj(c->doc);
    TRY(put(c,ping,"ID",yyjson_mut_uint(c->doc,sequence)) && integer(c,ping,"MonitorPingInfoID",id));
    /* PingInfo.DateSent is a serialized getter derived from DateSentInt. */
    _Static_assert(sizeof(time_t)>=8,"Full .NET uint DateSentInt requires 64-bit time_t");
    time_t instant=(time_t)(UINT64_C(1640995200)+date); struct tm utc; char sent_time[32];
    TRY(gmtime_r(&instant,&utc) && strftime(sent_time,sizeof(sent_time),"%Y-%m-%dT%H:%M:%SZ",&utc));
    TRY(text(c,ping,"DateSent",sent_time));
    TRY(text(c,ping,"Status",status) && integer(c,ping,"StatusID",0) && integer(c,ping,"RoundTripTimeInt",0));
    TRY(put(c,ping,"RoundTripTime",yyjson_mut_uint(c->doc,rtt)) && put(c,ping,"DateSentInt",yyjson_mut_uint(c->doc,date)));
    TRY(yyjson_mut_arr_append(pings,ping));
    TRY(put(c,data,"PiIDKey",yyjson_mut_uint(c->doc,(uint32_t)(sequence+UINT32_C(1)))));
    return true;
}
