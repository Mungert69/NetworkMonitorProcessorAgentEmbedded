/* Test-only boundary adapter: run the existing .NET-derived JSON assertions
 * against the typed implementation. Its document is fixture input/output, not
 * firmware state. Re-import before each action permits deliberately malformed
 * fixture mutations without exposing mutable JSON inside the production model.
 */
#include "monitor_model.h"
#include "monitor_core.h"
#include <string.h>
static bool typed_open(nm_monitor_core *out,yyjson_mut_val *root,yyjson_mut_val *legacy,yyjson_mut_val *hosts)
{
    nm_model m; if(!nm_model_open(&m,root,legacy,hosts,4096,65536)) { out->doc=NULL; return false; }
    out->doc=nm_model_encode(&m); nm_model_close(&m); return out->doc!=NULL;
}
static bool typed_finish(nm_monitor_core *c,nm_model *m,bool ok)
{
    yyjson_mut_doc *doc=ok?nm_model_encode(m):NULL; nm_model_close(m);
    if(!doc) return false;
    yyjson_mut_doc_free(c->doc); c->doc=doc; return true;
}
static bool typed_load(nm_monitor_core *c,nm_model *m)
{ return nm_model_open(m,yyjson_mut_doc_get_root(c->doc),NULL,NULL,4096,65536); }
static bool typed_updates(nm_monitor_core *c,yyjson_mut_val *v,const char *app,unsigned maximum,const char *when)
{
    nm_model m; if(!typed_load(c,&m)) return false;
    m.hosts.limit=m.infos.limit=m.removals.limit=m.swaps.limit=maximum;
    return typed_finish(c,&m,nm_model_updates(&m,v,app,when));
}
static bool typed_init(nm_monitor_core *c,yyjson_mut_val *v,const char *app,unsigned maximum,const char *when)
{
    nm_model m; if(!typed_load(c,&m)) return false;
    m.hosts.limit=m.infos.limit=m.removals.limit=m.swaps.limit=maximum;
    return typed_finish(c,&m,nm_model_init(&m,v,app,when));
}
static bool typed_ack(nm_monitor_core *c,yyjson_mut_val *v)
{ nm_model m; if(!typed_load(c,&m)) return false; return typed_finish(c,&m,nm_model_ack(&m,v)); }
static bool typed_alert(nm_monitor_core *c,const char *op,yyjson_mut_val *v,const char *app)
{ nm_model m; if(!typed_load(c,&m)) return false; return typed_finish(c,&m,nm_model_alert(&m,op,v,app)); }
static bool typed_event(nm_monitor_core *c,yyjson_mut_val *v)
{ nm_model m; if(!typed_load(c,&m)) return false; return typed_finish(c,&m,nm_model_user_event(&m,v)); }
static bool typed_reconcile(nm_monitor_core *c,const char *app,const char *when)
{ nm_model m; if(!typed_load(c,&m)) return false; return typed_finish(c,&m,nm_model_reconcile(&m,app,when)); }
static bool typed_probe(nm_monitor_core *c,yyjson_mut_val *host,bool up,uint16_t rtt,const char *status,const char *message,const char *when,uint32_t date)
{
    int32_t id; if(!nm_monitor_i32(yyjson_mut_obj_get(host,"ID"),&id)) return false;
    nm_model m; if(!typed_load(c,&m)) return false;
    return typed_finish(c,&m,nm_model_probe(&m,id,up,rtt,status,message,when,date));
}
static bool typed_commit(nm_monitor_core *current,nm_monitor_core *candidate,nm_monitor_save save,void *context)
{
    nm_model m; if(!typed_load(candidate,&m)) return false; nm_model_close(&m);
    if(!save || !save(context,yyjson_mut_doc_get_root(candidate->doc))) return false;
    nm_monitor_close(current); current->doc=candidate->doc; candidate->doc=NULL; return true;
}
#define nm_monitor_open typed_open
#define nm_monitor_updates typed_updates
#define nm_monitor_init typed_init
#define nm_monitor_ack typed_ack
#define nm_monitor_alert typed_alert
#define nm_monitor_user_event typed_event
#define nm_monitor_reconcile typed_reconcile
#define nm_monitor_probe typed_probe
#define nm_monitor_commit typed_commit
