#include "nm_json.h"
#include "nm_capabilities.h"
#include "reregister_config.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

static void parsed_strings_and_clone(void)
{
    const char *json="{\"auth_key\":\"pending\",\"ID\":18446744073709551615,\"nested\":[{\"value\":\"owned\"}]}";
    char *input=malloc(strlen(json)+1);
    assert(input); strcpy(input,json);
    yyjson_mut_doc *doc=nm_json_read(input,strlen(input));
    memset(input,'x',strlen(input)); free(input);
    yyjson_mut_val *root=yyjson_mut_doc_get_root(doc);
    assert(yyjson_mut_equals_str(yyjson_mut_obj_get(root,"auth_key"),"pending"));
    yyjson_mut_doc *copy=nm_json_clone(root);
    yyjson_mut_doc_free(doc);
    root=yyjson_mut_doc_get_root(copy);
    assert(yyjson_mut_get_uint(yyjson_mut_obj_get(root,"ID"))==UINT64_MAX);
    assert(yyjson_mut_equals_str(yyjson_mut_obj_get(yyjson_mut_arr_get(yyjson_mut_obj_get(root,"nested"),0),"value"),"owned"));
    char *serialized=yyjson_mut_val_write(root,0,NULL);
    assert(serialized && !strcmp(serialized,json)); free(serialized);

    /* Signed reply lives in a separate document, freed before config is saved. */
    const char *reply="{\"AuthKey\":\"authenticated-key\"}";
    yyjson_mut_doc *reply_doc=nm_json_read(reply,strlen(reply));
    const char *borrowed=yyjson_mut_get_str(yyjson_mut_obj_get(yyjson_mut_doc_get_root(reply_doc),"AuthKey"));
    assert(nm_json_put_str(copy,root,"auth_key",borrowed));
    yyjson_mut_doc_free(reply_doc);
    assert(yyjson_mut_equals_str(yyjson_mut_obj_get(root,"auth_key"),"authenticated-key"));
    char scratch[]="temporary-password";
    assert(nm_json_put_str(copy,root,"wifi_password",scratch));
    memset(scratch,0,sizeof(scratch));
    assert(yyjson_mut_equals_str(yyjson_mut_obj_get(root,"wifi_password"),"temporary-password"));
    yyjson_mut_doc_free(copy);
    assert(!nm_json_clone(NULL));
    assert(!nm_json_read("{}garbage",9));
}

static void capability_and_factory_copies(void)
{
    const char *json="{\"DisabledCommands\":[\"custom-command\"],\"LoadServer\":\"fixture.invalid\",\"ota_ca_pem\":\"trust-data\"}";
    yyjson_mut_doc *settings=nm_json_read(json,strlen(json));
    yyjson_mut_doc *event=yyjson_mut_doc_new(NULL);
    yyjson_mut_val *data=yyjson_mut_obj(event);
    assert(nm_capabilities_add(event,data,yyjson_mut_doc_get_root(settings)));
    yyjson_mut_doc *factory=nm_factory_config(yyjson_mut_doc_get_root(settings));
    yyjson_mut_doc_free(settings);
    char *serialized=yyjson_mut_val_write(data,0,NULL);
    assert(serialized && strstr(serialized,"custom-command")); free(serialized);
    yyjson_mut_doc_free(event);
    yyjson_mut_val *root=yyjson_mut_doc_get_root(factory);
    assert(yyjson_mut_equals_str(yyjson_mut_obj_get(root,"LoadServer"),"fixture.invalid"));
    assert(yyjson_mut_equals_str(yyjson_mut_obj_get(root,"ota_ca_pem"),"trust-data"));
    assert(nm_reregister_config(factory,root));
    assert(yyjson_mut_equals_str(yyjson_mut_obj_get(root,"ota_ca_pem"),"trust-data"));
    yyjson_mut_doc_free(factory);
}

int main(void)
{
    parsed_strings_and_clone();
    capability_and_factory_copies();
    puts("JSON lifecycle: parsed/copied documents and transient strings retain ownership");
    return 0;
}
