/* Reuse every .NET-derived scheduler assertion with the typed runtime. */
#include "monitor_schedule_typed.h"
#include <math.h>
static bool export_schedule(yyjson_mut_doc *doc,yyjson_mut_val *root,nm_schedule *s,bool ok)
{
    if(ok) {
        yyjson_mut_val *encoded=nm_schedule_encode(doc,s);
        if(!encoded) ok=false;
        else {
            yyjson_mut_obj_clear(root);
            size_t i,n; yyjson_mut_val *k,*v;
            yyjson_mut_obj_foreach(encoded,i,n,k,v)
                if(!yyjson_mut_obj_add_val(doc,root,yyjson_mut_get_str(k),yyjson_mut_val_mut_copy(doc,v))) ok=false;
        }
    }
    nm_schedule_close(s); return ok;
}
static bool typed_prepare(yyjson_mut_doc *doc,yyjson_mut_val *root,yyjson_mut_val *config,yyjson_mut_val *monitors,int64_t now)
{
    nm_schedule s; if(!nm_schedule_open(&s,root,4096)) return false;
    nm_records records={.limit=4096}; bool ok=yyjson_mut_is_arr(monitors);
    size_t i,n; yyjson_mut_val *v;
    yyjson_mut_arr_foreach(monitors,i,n,v) {
        nm_record *r=nm_record_decode(NM_MONITOR,v);
        if(!r || !nm_records_append(&records,r)) { nm_record_release(r); ok=false; break; }
    }
    ok=ok && nm_schedule_configure(&s,config) && nm_schedule_prepare(&s,&records,now);
    nm_records_free(&records); return export_schedule(doc,root,&s,ok);
}
static bool typed_include_random(yyjson_mut_doc *doc,yyjson_mut_val *root,yyjson_mut_val *config,yyjson_mut_val *monitor,int64_t now,
    nm_monitor_schedule_random_fn random,void *context,int32_t hash,bool *include)
{
    (void)config; if(!include) return false; *include=false;
    nm_schedule s; if(!nm_schedule_open(&s,root,4096)) return false;
    nm_monitor_record *r=(nm_monitor_record *)nm_record_decode(NM_MONITOR,monitor);
    bool ok=r && nm_schedule_include(&s,r,now,random,context,hash,include);
    nm_record_release((nm_record *)r); return export_schedule(doc,root,&s,ok);
}
static double typed_random(void *context) { return *(double *)context; }
static bool typed_include(yyjson_mut_doc *doc,yyjson_mut_val *root,yyjson_mut_val *config,yyjson_mut_val *monitor,int64_t now,double random,int32_t hash,bool *include)
{
    if(include) *include=false;
    if(!isfinite(random)||random<0||random>=1) return false;
    return typed_include_random(doc,root,config,monitor,now,typed_random,&random,hash,include);
}
#define nm_monitor_schedule_prepare typed_prepare
#define nm_monitor_schedule_include typed_include
#define nm_monitor_schedule_include_with_random typed_include_random
#define main reference_tests_main
#include "test_monitor_schedule.c"
#undef main

static void actual_daily_hash(void)
{
    const int32_t ids[]={0,1,13,21,-1,INT32_MIN,INT32_MAX};
    const int32_t expected[]={890022063,873244444,518729469,217225196,348981803,336980561,500604841};
    for(size_t i=0;i<sizeof(ids)/sizeof(ids[0]);++i)
        CHECK(nm_schedule_daily_hash(ids[i])==expected[i]);

    /* Distribution regression bounds, not a guarantee of equal occupancy for
     * arbitrary user-selected IDs. No hash can promise collision-free slots. */
    unsigned bins[24]={0};
    for(int32_t id=1;id<=24000;++id) ++bins[nm_schedule_daily_hash(id)%24];
    for(size_t i=0;i<24;++i) CHECK(bins[i]>=850 && bins[i]<=1150);
    const int32_t starts[]={1,1000,INT32_MAX-49};
    for(size_t group=0;group<3;++group) {
        memset(bins,0,sizeof(bins));
        for(int32_t j=0;j<50;++j) ++bins[nm_schedule_daily_hash(starts[group]+j)%24];
        unsigned occupied=0;
        for(size_t i=0;i<24;++i) { CHECK(bins[i]<=6); occupied+=bins[i]!=0; }
        CHECK(occupied>=20);
    }

    /* Use the production hash through the real scheduler, testing every hour
     * for 50 hosts. The adapter encodes/reopens state at each call, also
     * exercising restart persistence. */
    for(int32_t id=1;id<=50;++id) {
        char monitor[128];
        snprintf(monitor,sizeof(monitor),"[{\"MonitorIPID\":%ld,\"EndPointType\":\"http\",\"Enabled\":true}]",(long)id);
        struct fixture f=fixture("{\"FilterStrategies\":[{\"StrategyName\":\"http\",\"FireInterval\":{\"Mode\":\"daily-slot\",\"SlotsPerDay\":24}}]}",monitor);
        prepare(&f);
        int32_t hash=nm_schedule_daily_hash(id),slot=hash%24;
        unsigned runs=0;
        for(int hour=0;hour<24;++hour) {
            bool run=include_at(&f,0,hour*3600,0.5,hash);
            CHECK(run==(hour==slot)); runs+=run;
            CHECK(!include_at(&f,0,hour*3600+1,0.5,nm_schedule_daily_hash(id)));
        }
        CHECK(runs==1);
        CHECK(include_at(&f,0,86400+slot*3600,0.5,nm_schedule_daily_hash(id)));
        free_fixture(&f);
    }
}

int main(void)
{
    int result=reference_tests_main();
    actual_daily_hash();
    puts("Production daily hash: golden vectors, distribution and 50-host daily/restart tests passed");
    return result;
}
