#include "nm_json.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

static void nested(size_t depth, bool object, bool accepted)
{
    size_t unit=object ? 6 : 2, size=depth*unit+1;
    char *text=malloc(size+1), *cursor=text;
    assert(text);
    for (size_t i=0;i<depth;++i) {
        if (object) { memcpy(cursor,"{\"a\":",5); cursor+=5; }
        else *cursor++='[';
    }
    *cursor++='0';
    for (size_t i=0;i<depth;++i) *cursor++=object ? '}' : ']';
    *cursor=0;
    yyjson_mut_doc *doc=nm_json_read(text,size);
    assert((doc!=NULL)==accepted);
    yyjson_mut_doc_free(doc);
    free(text);
}

int main(void)
{
    nested(0,false,true);
    nested(64,false,true);
    nested(64,true,true);
    nested(65,false,false);
    nested(65,true,false);
    nested(32767,false,false); /* Fits the public 65536-byte command limit. */
    nested(65536,false,false);
    const char *valid[]={"{}","[]","null","\"\"",
        "{\"a\":[{\"b\":\"escaped \\\" [ { } ]\"}]}",
        "{\"\\\\\":\"literal \\\\u0000\"}",
        "{\"unicode\":\"\\u00e9\\uD83D\\uDE00\"}"};
    for (size_t i=0;i<sizeof(valid)/sizeof(valid[0]);++i) {
        yyjson_mut_doc *doc=nm_json_read(valid[i],strlen(valid[i]));
        assert(doc); yyjson_mut_doc_free(doc);
    }
    const char *invalid[]={"{]","[}","[]garbage","{\"a\":1,}",
        "\"\\u0000\"","{\"key\\u0000suffix\":1}",
        "{\"nested\":[{\"key\":\"prefix\\u0000suffix\"}]}",
        "{\"auth_key\":\"key\\u0000ignored\"}"};
    for (size_t i=0;i<sizeof(invalid)/sizeof(invalid[0]);++i)
        assert(!nm_json_read(invalid[i],strlen(invalid[i])));
    char braces[1004]; braces[0]='"';
    memset(braces+1,'[',1000); braces[1001]='"'; braces[1002]=0;
    yyjson_mut_doc *doc=nm_json_read(braces,1002);
    assert(doc && yyjson_mut_get_len(yyjson_mut_doc_get_root(doc))==1000);
    yyjson_mut_doc_free(doc);
    assert(!nm_json_read(NULL,0));
    assert(!nm_json_read("",0));
    puts("JSON input: depth 64 boundary, escaped delimiters, embedded NUL and grammar checks passed");
    return 0;
}
