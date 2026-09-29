#include "nm_capabilities.h"
#include <stdio.h>
#include <stdlib.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed: %s at %d\n", #x, __LINE__); exit(1); } } while (0)
static bool contains(yyjson_mut_val *array, const char *value) {
    yyjson_mut_val *item;
    size_t i,n;
    yyjson_mut_arr_foreach(array,i,n,item)
        if (yyjson_mut_is_str(item) && !strcmp(yyjson_mut_get_str(item),value)) return true;
    return false;
}
int main(void) {
    yyjson_mut_doc *doc=yyjson_mut_doc_new(NULL);
    yyjson_mut_val *data=yyjson_mut_obj(doc);
    CHECK(nm_capabilities_add(doc,data,NULL));
    yyjson_mut_val *endpoints=yyjson_mut_obj_get(data,"DisabledEndPointTypes");
    CHECK(yyjson_mut_arr_size(endpoints)==14);
    const char *supported[]={"icmp","http","https","httphtml","dns","rawconnect"};
    for (unsigned i=0;i<sizeof(supported)/sizeof(*supported);i++)
        CHECK(!contains(endpoints,supported[i]));
    CHECK(contains(endpoints,"quantum"));
    CHECK(contains(endpoints,"configintegrity"));
    CHECK(contains(yyjson_mut_obj_get(data,"DisabledCommands"),"ping"));
    CHECK(contains(yyjson_mut_obj_get(data,"DisabledCommands"),"nmap"));
    yyjson_mut_doc_free(doc);
    const char *json="{\"DisabledEndpointTypes\":[\"smtp\",\"http\"],\"DisabledCommands\":[\"nmap\",\"custom\"]}";
    yyjson_mut_doc *settings_doc=nm_json_read(json,strlen(json));
    yyjson_mut_val *settings=yyjson_mut_doc_get_root(settings_doc);
    doc=yyjson_mut_doc_new(NULL); data=yyjson_mut_obj(doc);
    CHECK(nm_capabilities_add(doc,data,settings));
    CHECK(yyjson_mut_arr_size(yyjson_mut_obj_get(data,"DisabledEndPointTypes"))==15);
    CHECK(contains(yyjson_mut_obj_get(data,"DisabledCommands"),"custom"));
    yyjson_mut_doc_free(doc); yyjson_mut_doc_free(settings_doc);
    const char *invalid[]={"{\"DisabledCommands\":true}","{\"DisabledEndpointTypes\":[42]}","{\"DisabledCommands\":[\"\"]}"};
    for (unsigned i=0;i<sizeof(invalid)/sizeof(*invalid);i++) {
        doc=yyjson_mut_doc_new(NULL); data=yyjson_mut_obj(doc); settings_doc=nm_json_read(invalid[i],strlen(invalid[i])); settings=yyjson_mut_doc_get_root(settings_doc);
        CHECK(!nm_capabilities_add(doc,data,settings));
        yyjson_mut_doc_free(doc); yyjson_mut_doc_free(settings_doc);
    }
    puts("Capability defaults, merge and invalid configuration tests passed");
    return 0;
}
