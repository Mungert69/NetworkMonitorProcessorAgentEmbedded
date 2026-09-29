#include "nm_esp.h"
#include "wifi_setup_input.h"
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static void wipe(void *value,size_t size)
{
    volatile unsigned char *p=value;
    while (size--) *p++=0;
}
static void read_setting(nm_wifi_input *input,bool password)
{
    puts(password ? "Wi-Fi password (8-63 bytes; input hidden):" : "Wi-Fi SSID (1-32 bytes):");
    fflush(stdout);
    for (;;) {
        int c=getchar();
        if (c==EOF) { clearerr(stdin); vTaskDelay(pdMS_TO_TICKS(25)); continue; }
        int result=nm_wifi_input_feed(input,(unsigned char)c);
        if (!result) continue;
        if (result>0 && nm_wifi_input_valid(input->text,password)) return;
        wipe(input->text,sizeof(input->text));
        puts(password ? "Invalid password length/input; enter 8-63 bytes:" : "Invalid SSID/input; enter 1-32 bytes:");
    }
}

bool nm_esp_serial_wifi_setup(nm_esp_config *config)
{
    puts("Serial Wi-Fi setup: enter your 2.4 GHz network. Firmware does not echo input.");
    puts("Power interruption returns here. Browser authorization follows Wi-Fi connection.");
    nm_wifi_input input={0};
    yyjson_mut_doc *doc=nm_json_clone(config->root);
    yyjson_mut_val *root=yyjson_mut_doc_get_root(doc);
    if (!root) return false;
    read_setting(&input,false);
    bool ok=nm_json_put_str(doc,root,"wifi_ssid",input.text);
    wipe(input.text,sizeof(input.text));
    if (ok) {
        read_setting(&input,true);
        ok=nm_json_put_str(doc,root,"wifi_password",input.text);
    }
    wipe(&input,sizeof(input));
    nm_esp_config next={.doc=doc};
    /* WiFiSetup stays true on disk until connection succeeds. */
    ok=ok && nm_esp_config_bind(&next,root) && nm_esp_config_save(&next);
    if (!ok) { yyjson_mut_doc_free(doc); return false; }
    yyjson_mut_doc_free(config->doc); *config=next;
    puts("Wi-Fi settings saved. Connecting...");
    return true;
}

bool nm_esp_wifi_setup_complete(nm_esp_config *config)
{
    yyjson_mut_val *flag=yyjson_mut_obj_get(config->root,"WiFiSetup");
    if (!yyjson_mut_is_true(flag)) return false;
    yyjson_mut_set_bool(flag,false);
    bool ok=nm_esp_config_bind(config,config->root) && nm_esp_config_save(config);
    if (ok) puts("Wi-Fi setup complete. Starting browser authorization.");
    return ok;
}
