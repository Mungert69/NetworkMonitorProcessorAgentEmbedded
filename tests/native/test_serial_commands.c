#include "serial_commands.h"
#include "reregister_config.h"
#include "wifi_setup_input.h"
#include <assert.h>
#include <stdio.h>

static nm_serial_action line(nm_serial_parser *p,const char *text,int64_t now)
{
    nm_serial_action result=NM_SERIAL_NONE;
    for (;*text;++text) {
        nm_serial_action current=nm_serial_feed(p,(unsigned char)*text,now);
        if (current!=NM_SERIAL_NONE) result=current;
    }
    return result;
}
int main(void)
{
    nm_serial_parser p={0};
    assert(line(&p,"confirm reregister\n",0)==NM_SERIAL_INVALID);
    assert(line(&p,"reregister\r\n",10)==NM_SERIAL_PROMPT);
    assert(line(&p,"confirm reregister\r\n",11)==NM_SERIAL_CONFIRM);
    assert(line(&p,"confirm reregister\n",12)==NM_SERIAL_INVALID);
    assert(line(&p,"reregister\n",20)==NM_SERIAL_PROMPT);
    assert(line(&p,"cancel\n",21)==NM_SERIAL_CANCEL);
    assert(line(&p,"confirm reregister\n",22)==NM_SERIAL_INVALID);
    assert(line(&p,"reregister\n",30)==NM_SERIAL_PROMPT);
    assert(line(&p,"confirm reregister\n",30000030)==NM_SERIAL_INVALID);
    assert(line(&p,"reregister\n",40)==NM_SERIAL_PROMPT);
    for (int i=0;i<10000;++i) nm_serial_feed(&p,'x',41);
    assert(line(&p,"\n",42)==NM_SERIAL_INVALID);
    assert(line(&p,"confirm reregister\n",43)==NM_SERIAL_INVALID);
    assert(line(&p,"reregister\n",50)==NM_SERIAL_PROMPT);
    nm_serial_feed(&p,0,51);
    assert(line(&p,"confirm reregister\n",52)==NM_SERIAL_INVALID);
    assert(line(&p,"help\n",53)==NM_SERIAL_HELP);
    assert(line(&p,"stop\n",54)==NM_SERIAL_STOP);
    assert(line(&p,"start\n",55)==NM_SERIAL_START);
    assert(line(&p,"stop 10m\n",56)==NM_SERIAL_INVALID);
    assert(line(&p,"stopped\n",57)==NM_SERIAL_INVALID);
    assert(line(&p,"start\n",58)==NM_SERIAL_START);
    assert(line(&p,"factory-reset\n",59)==NM_SERIAL_FACTORY_PROMPT);
    assert(line(&p,"stop\n",59)==NM_SERIAL_STOP);
    assert(line(&p,"confirm factory-reset\n",59)==NM_SERIAL_INVALID);
    assert(line(&p,"factory-reset\n",60)==NM_SERIAL_FACTORY_PROMPT);
    assert(line(&p,"confirm reregister\n",61)==NM_SERIAL_INVALID);
    assert(line(&p,"reregister\n",62)==NM_SERIAL_PROMPT);
    assert(line(&p,"confirm factory-reset\n",63)==NM_SERIAL_INVALID);
    assert(line(&p,"factory-reset\n",64)==NM_SERIAL_FACTORY_PROMPT);
    assert(line(&p,"confirm factory-reset\n",65)==NM_SERIAL_FACTORY_CONFIRM);
    assert(line(&p,"confirm factory-reset\n",66)==NM_SERIAL_INVALID);
    assert(line(&p,"factory-reset\n",70)==NM_SERIAL_FACTORY_PROMPT);
    assert(line(&p,"confirm factory-reset\n",30000070)==NM_SERIAL_INVALID);
    const char *json="{\"AuthDevice\":false,\"wifi_ssid\":\"test\",\"wifi_password\":\"password\",\"AppName\":\"Lab\",\"DeviceName\":\"esp32.mac\",\"mqtt_password\":\"old-token\",\"mqtt_username\":\"old-user\",\"app_id\":\"old-app\",\"auth_key\":\"old-key\",\"MonitorLocation\":\"old-location\",\"max_monitors\":50}";
    yyjson_mut_doc *doc=nm_json_read(json,strlen(json));
    yyjson_mut_val *config=yyjson_mut_doc_get_root(doc);
    assert(yyjson_mut_obj_add_uint(doc,config,"MaxTaskQueueSize",8));
    assert(yyjson_mut_obj_add_uint(doc,config,"MaxOutstandingEndpointOperations",1));
    assert(nm_reregister_config(doc,config));
    assert(yyjson_mut_get_uint(yyjson_mut_obj_get(config,"MaxTaskQueueSize"))==8);
    assert(yyjson_mut_get_uint(yyjson_mut_obj_get(config,"MaxOutstandingEndpointOperations"))==1);
    assert(yyjson_mut_is_true(yyjson_mut_obj_get(config,"AuthDevice")));
    const char *removed[]={"mqtt_password","mqtt_username","app_id","auth_key","MonitorLocation"};
    for (unsigned i=0;i<5;++i) assert(!yyjson_mut_obj_get(config,removed[i]));
    const char *kept[]={"wifi_ssid","wifi_password","AppName","DeviceName","max_monitors"};
    for (unsigned i=0;i<5;++i) assert(yyjson_mut_obj_get(config,kept[i]));
    assert(nm_reregister_config(doc,config)); /* safe to retry after power loss */
    yyjson_mut_obj_add_strcpy(doc,config,"LoadServer","fixture.invalid");
    yyjson_mut_doc *fresh_doc=nm_factory_config(config);
    yyjson_mut_val *fresh=yyjson_mut_doc_get_root(fresh_doc);
    assert(yyjson_mut_get_uint(yyjson_mut_obj_get(fresh,"MaxTaskQueueSize"))==4);
    assert(yyjson_mut_get_uint(yyjson_mut_obj_get(fresh,"MaxOutstandingEndpointOperations"))==4);
    assert(fresh && yyjson_mut_is_true(yyjson_mut_obj_get(fresh,"WiFiSetup")));
    assert(yyjson_mut_is_true(yyjson_mut_obj_get(fresh,"AuthDevice")));
    assert(yyjson_mut_is_true(yyjson_mut_obj_get(fresh,"IsQuantumCapable")));
    const char *factory_removed[]={"wifi_ssid","wifi_password","AppName","DeviceName","mqtt_password","auth_key"};
    for (unsigned i=0;i<6;++i) assert(!yyjson_mut_obj_get(fresh,factory_removed[i]));
    assert(!strcmp(yyjson_mut_get_str(yyjson_mut_obj_get(fresh,"LoadServer")),"fixture.invalid"));
    yyjson_mut_doc_free(fresh_doc);
    yyjson_mut_doc_free(doc);
    assert(!nm_reregister_config(NULL,NULL));
    nm_wifi_input input={0};
    assert(nm_wifi_input_feed(&input,'a')==0);
    assert(nm_wifi_input_feed(&input,'\r')==1);
    assert(!strcmp(input.text,"a"));
    assert(nm_wifi_input_feed(&input,'\n')==0);
    for (int i=0;i<10000;++i) nm_wifi_input_feed(&input,'x');
    assert(nm_wifi_input_feed(&input,'\n')==-1);
    assert(nm_wifi_input_feed(&input,'\n')==0);
    assert(!nm_wifi_input_valid(input.text,false));
    /* Some console drivers turn CRLF into two LF characters. Neither an
     * extra terminator nor an empty submission should reject an untyped password. */
    assert(nm_wifi_input_feed(&input,'\r')==0);
    assert(nm_wifi_input_feed(&input,'\n')==0);
    assert(nm_wifi_input_feed(&input,'s')==0);
    assert(nm_wifi_input_feed(&input,'\n')==1);
    assert(nm_wifi_input_feed(&input,'\n')==0);
    assert(nm_wifi_input_feed(&input,'\n')==0);
    assert(nm_wifi_input_feed(&input,'a')==0);
    assert(nm_wifi_input_feed(&input,8)==0);
    assert(nm_wifi_input_feed(&input,'b')==0);
    assert(nm_wifi_input_feed(&input,'\n')==1);
    assert(!strcmp(input.text,"b"));
    assert(!nm_wifi_input_valid("short",true));
    assert(nm_wifi_input_valid("password",true));
    assert(!nm_wifi_input_valid("123456789012345678901234567890123",false));
    char password[65]; memset(password,'x',64); password[64]=0;
    assert(!nm_wifi_input_valid(password,true));
    password[63]=0; assert(nm_wifi_input_valid(password,true));
    assert(nm_wifi_input_feed(&input,0)==0);
    assert(nm_wifi_input_feed(&input,'\n')==-1);
    puts("Serial command and re-registration config tests passed");
    return 0;
}
