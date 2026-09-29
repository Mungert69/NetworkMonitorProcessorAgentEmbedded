#include "enrollment_policy.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
int main(void)
{
    const char *owner="84ab1c49-e8f2-4bb0-b347-06a3713c4798";
    const uint8_t mac[6]={0x24,0x0a,0xc4,0,0,1};
    nm_enrollment_names names;
    assert(nm_enrollment_build_names(owner,"user@example.com",NULL,NULL,mac,&names));
    assert(!strcmp(names.app_id,"84ab1c49-e8f2-4bb0-b347-06a3713c4798-esp32.240ac4000001"));
    assert(!strcmp(names.location,"user@example.com-esp32.240ac4000001"));
    assert(nm_enrollment_build_names(owner,"user@example.com","QSAX","my-board-1",mac,&names));
    assert(!strcmp(names.app_id,"84ab1c49-e8f2-4bb0-b347-06a3713c4798-QSAX-my.board.1"));
    assert(!strcmp(names.location,"user@example.com-QSAX-my.board.1"));
    assert(nm_enrollment_build_names(owner,NULL,"",NULL,mac,&names));
    assert(!strcmp(names.location,"-esp32.240ac4000001"));
    char long_app[129],long_machine[129];
    memset(long_app,'a',128); long_app[128]=0;
    memset(long_machine,'b',100); long_machine[100]=0;
    assert(nm_enrollment_build_names(owner,"x",long_app,long_machine,mac,&names));
    assert(strlen(names.app_id)==255);
    memset(long_machine,'b',128); long_machine[128]=0;
    assert(!nm_enrollment_build_names(owner,"x",long_app,long_machine,mac,&names));
    assert(!nm_enrollment_build_names("invalid","x",NULL,NULL,mac,&names));
    assert(!nm_enrollment_build_names(owner,"x",NULL,"",mac,&names));
    assert(nm_enrollment_endpoint("https://auth.test:2096","https://auth.test:2096/oauth/token"));
    assert(!nm_enrollment_endpoint("https://auth.test","https://auth.test.evil/token"));
    assert(!nm_enrollment_endpoint("https://auth.test","https://auth.test@evil/token"));
    assert(!nm_enrollment_endpoint("https://auth.test","http://auth.test/token"));
    assert(!nm_enrollment_endpoint("https://auth.test","https://auth.test"));
    assert(!nm_enrollment_endpoint("https://","https:///token"));
    assert(!nm_enrollment_endpoint("https://user@auth.test","https://user@auth.test/token"));
    assert(!nm_enrollment_endpoint(NULL,NULL));
    assert(nm_enrollment_owner("84ab1c49-e8f2-4bb0-b347-06a3713c4798"));
    assert(!nm_enrollment_owner("84AB1C49-e8f2-4bb0-b347-06a3713c4798"));
    assert(!nm_enrollment_owner("84ab1c49/e8f2-4bb0-b347-06a3713c4798"));
    assert(!nm_enrollment_owner("84ab1c49-e8f2-4bb0-b347-06a3713c4798-extra"));
    assert(!nm_enrollment_owner(NULL));
    /* Integer-token rejection matches System.Text.Json's source-linked oracle:
     * tests/dotnet/JsonParity/Program.cs invalidNumeric and deserialization-cases.json. */
    const char *bad[]={"{}","null","[null]","[{\"ID\":-1}]","[{\"ID\":0.5}]",
                       "[{\"ID\":1.0}]","[{\"ID\":1e0}]","[{\"ID\":0e0}]",
                       "[{\"ID\":2147483648}]","[{\"ID\":18446744073709551616}]","[{\"ID\":\"1\"}]","[{}]"};
    for (size_t i=0;i<sizeof(bad)/sizeof(bad[0]);++i) {
        yyjson_mut_doc *doc=nm_json_read(bad[i],strlen(bad[i]));
        yyjson_mut_val *value=yyjson_mut_doc_get_root(doc);
        assert(!nm_enrollment_monitors(value,50)); yyjson_mut_doc_free(doc);
    }
    const char *json="[{\"ID\":1,\"Address\":\"1.1.1.1\"},{\"ID\":2}]";
    yyjson_mut_doc *doc=nm_json_read(json,strlen(json));
    yyjson_mut_val *value=yyjson_mut_doc_get_root(doc);
    assert(nm_enrollment_monitors(value,2));
    assert(!nm_enrollment_monitors(value,1)); yyjson_mut_doc_free(doc);
    doc=yyjson_mut_doc_new(NULL); value=yyjson_mut_arr(doc); assert(nm_enrollment_monitors(value,50)); yyjson_mut_doc_free(doc);
    const char *large="[{\"ID\":2147483648},{\"ID\":9007199254740993},{\"ID\":18446744073709551615}]";
    doc=nm_json_read(large,strlen(large));
    value=yyjson_mut_doc_get_root(doc);
    assert(!nm_enrollment_monitors(value,3));
    assert(yyjson_mut_get_uint(yyjson_mut_obj_get(yyjson_mut_arr_get(value,1),"ID"))==UINT64_C(9007199254740993));
    assert(yyjson_mut_get_uint(yyjson_mut_obj_get(yyjson_mut_arr_get(value,2),"ID"))==UINT64_MAX);
    char *serialized=yyjson_mut_val_write(value,0,NULL);
    assert(serialized && !strcmp(serialized,large));
    free(serialized);
    yyjson_mut_doc_free(doc);
    puts("Enrollment policy: authority isolation, canonical ownership and bounded monitor validation passed");
    return 0;
}
