#ifndef NM_REREGISTER_CONFIG_H
#define NM_REREGISTER_CONFIG_H
#include <stdbool.h>
#include "nm_json.h"
#include "probe_config.h"

static inline bool nm_reregister_config(yyjson_mut_doc *doc, yyjson_mut_val *root)
{
    if (!yyjson_mut_is_obj(root)) return false;
    if (!nm_json_put(doc, root, "AuthDevice", yyjson_mut_bool(doc, true))) return false;
    const char *keys[]={"mqtt_username","mqtt_password","auth_key","app_id","MonitorLocation"};
    for (unsigned i=0;i<sizeof(keys)/sizeof(keys[0]);++i)
        yyjson_mut_obj_remove_key(root,keys[i]);
    return true;
}

static inline yyjson_mut_doc *nm_factory_config(yyjson_mut_val *old)
{
    yyjson_mut_doc *doc=yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root=yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc,root);
    if (!root) { yyjson_mut_doc_free(doc); return NULL; }
    bool ok=yyjson_mut_obj_add_bool(doc,root,"AuthDevice",true) &&
        yyjson_mut_obj_add_bool(doc,root,"WiFiSetup",true) &&
        yyjson_mut_obj_add_bool(doc,root,"IsQuantumCapable",false) &&
        yyjson_mut_obj_add_uint(doc,root,"max_monitors",50) &&
        yyjson_mut_obj_add_uint(doc,root,"max_pending_ping_infos",500) &&
        yyjson_mut_obj_add_uint(doc,root,"MaxTaskQueueSize",NM_PROBE_DEFAULT_WORKERS) &&
        yyjson_mut_obj_add_uint(doc,root,"MaxOutstandingEndpointOperations",NM_ENDPOINT_DEFAULT_OPERATIONS) &&
        yyjson_mut_obj_add_uint(doc,root,"poll_seconds",60);
    /* Deployment endpoints/trust survive; device/user-specific settings don't. */
    const char *keys[]={"BaseFusionAuthURL","ClientId","LoadServer","ota_ca_pem"};
    for (unsigned i=0;ok && i<sizeof(keys)/sizeof(keys[0]);++i) {
        yyjson_mut_val *value=yyjson_mut_obj_get(old,keys[i]);
        if (!value) continue;
        yyjson_mut_val *copy=yyjson_mut_val_mut_copy(doc,value);
        ok=copy && yyjson_mut_obj_add_val(doc,root,keys[i],copy);
    }
    if (!ok) { yyjson_mut_doc_free(doc); return NULL; }
    return doc;
}
#endif
