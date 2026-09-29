#include "monitor_model.h"
#include "monitor_schedule_typed.h"
#include "nm_json.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void *__real_malloc(size_t);
void *__real_calloc(size_t,size_t);
void *__real_realloc(void *,size_t);
char *__real_strdup(const char *);
static long fail_at=-1,allocations;
static bool fail(void) { return fail_at>=0 && allocations++==fail_at; }
void *__wrap_malloc(size_t n) { return fail()?NULL:__real_malloc(n); }
void *__wrap_calloc(size_t n,size_t size) { return fail()?NULL:__real_calloc(n,size); }
void *__wrap_realloc(void *p,size_t n) { return fail()?NULL:__real_realloc(p,n); }
char *__wrap_strdup(const char *s) { return fail()?NULL:__real_strdup(s); }
static yyjson_mut_doc *parse(const char *s) { yyjson_mut_doc *d=nm_json_read(s,strlen(s)); assert(d); return d; }
static const char *when="2026-09-27T12:00:00Z";
static void compare(const nm_model *m,yyjson_mut_doc *expected)
{
    yyjson_mut_doc *actual=nm_model_encode(m); assert(actual);
    assert(yyjson_mut_equals(yyjson_mut_doc_get_root(actual),yyjson_mut_doc_get_root(expected)));
    yyjson_mut_doc_free(actual);
}
int main(void)
{
    nm_model live;
    assert(nm_model_open(&live,NULL,NULL,NULL,50,500));
    yyjson_mut_doc *input=parse("[{\"ID\":7,\"Address\":\"example.test\",\"EndPointType\":\"http\",\"Enabled\":true,\"Future\":{\"ID\":18446744073709551615}},"
                               "{\"ID\":8,\"Address\":\"second.test\",\"EndPointType\":\"icmp\",\"Enabled\":true}]");
    assert(nm_model_updates(&live,yyjson_mut_doc_get_root(input),"test-app",when));
    assert(nm_model_probe(&live,7,true,5,"OK","up",when,1));
    yyjson_mut_doc *config=parse("{\"FilterStrategies\":[{\"StrategyName\":\"http\",\"EndpointTypeContains\":[\"http\"],\"FireInterval\":{\"Every\":2}}]}");
    assert(nm_schedule_configure(live.schedule,yyjson_mut_doc_get_root(config)));
    yyjson_mut_doc *before=nm_model_encode(&live); assert(before);
    nm_model candidate; assert(nm_model_clone(&candidate,&live));
    assert(candidate.infos.items[0]==live.infos.items[0] && candidate.infos.items[1]==live.infos.items[1]);
    assert(candidate.pings.items[0]==live.pings.items[0]);
    assert(nm_model_probe(&candidate,7,false,65535,"TimedOut","down",when,2));
    assert(candidate.infos.items[0]!=live.infos.items[0] && candidate.infos.items[1]==live.infos.items[1]);
    assert(candidate.pings.items[0]==live.pings.items[0] && live.pings.count==1 && candidate.pings.count==2);
    assert(nm_model_info(&live,7)->MonitorStatus!=nm_model_info(&candidate,7)->MonitorStatus);
    nm_model_close(&candidate); compare(&live,before);
    assert(live.infos.items[0]->references==1 && live.pings.items[0]->references==1);

    /* Fail each allocation in turn, not just one hand-picked error branch.
     * The owning cleanup path must accept every partially constructed state. */
    unsigned failures=0;
    for(unsigned operation=0;operation<4;++operation) {
        bool reached_end=false;
        for(long position=0;position<4096;++position) {
            nm_model trial={0}; yyjson_mut_doc *encoded=NULL;
            fail_at=position; allocations=0;
            bool ok;
            if(operation==0) ok=nm_model_open(&trial,yyjson_mut_doc_get_root(before),NULL,NULL,50,500);
            else {
                ok=nm_model_clone(&trial,&live);
                if(ok && operation==1) ok=nm_model_probe(&trial,7,true,9,"OK","up",when,3);
                if(ok && operation==2) { encoded=nm_model_encode(&trial); ok=encoded!=NULL; }
                if(ok && operation==3) ok=nm_model_updates(&trial,yyjson_mut_doc_get_root(input),"test-app",when);
            }
            long called=allocations; fail_at=-1;
            yyjson_mut_doc_free(encoded); nm_model_close(&trial);
            compare(&live,before);
            assert(live.infos.items[0]->references==1 && live.infos.items[1]->references==1 && live.pings.items[0]->references==1);
            if(called<=position) { assert(ok); reached_end=true; break; }
            ++failures;
        }
        assert(reached_end);
    }
    nm_records bounded={.limit=1}; nm_record *a=nm_record_new(NM_PING),*b=nm_record_new(NM_PING);
    assert(a&&b&&nm_records_append(&bounded,a)); assert(!nm_records_append(&bounded,b));
    nm_record_release(b); nm_records_free(&bounded);
    yyjson_mut_doc_free(before); yyjson_mut_doc_free(input); yyjson_mut_doc_free(config); nm_model_close(&live);
    printf("Typed ownership/COW/bounds and %u allocation-failure positions passed\n",failures);
    return 0;
}
