#ifndef NM_ENROLLMENT_POLICY_H
#define NM_ENROLLMENT_POLICY_H
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "nm_json.h"

/* Keep decisions independent of the HTTPS/MQTT adapters for host-side tests. */
static inline bool nm_enrollment_endpoint(const char *authority, const char *url)
{
    return authority && strlen(authority)>8 && !strncmp(authority,"https://",8) &&
        !strpbrk(authority+8,"/@?#\\") && url &&
        !strncmp(authority,url,strlen(authority)) && url[strlen(authority)]=='/';
}
static inline bool nm_enrollment_owner(const char *owner)
{
    if (!owner || strlen(owner)!=36) return false;
    for (size_t i=0;i<36;++i) {
        bool dash=i==8 || i==13 || i==18 || i==23;
        if (dash ? owner[i]!='-' : !((owner[i]>='0'&&owner[i]<='9') ||
                                     (owner[i]>='a'&&owner[i]<='f'))) return false;
    }
    return true;
}
typedef struct {
    char app_id[256];
    char location[256];
    char machine[129];
} nm_enrollment_names;

/* AuthService.PollForTokenAsync convention, with the Wi-Fi MAC replacing
 * Environment.MachineName. No changes to already enrolled identities on boot. */
static inline bool nm_enrollment_build_names(const char *owner,const char *email,
    const char *app_name,const char *device_name,const uint8_t mac[6],nm_enrollment_names *out)
{
    if (!out || !mac || !nm_enrollment_owner(owner)) return false;
    if (!email) email="";
    if (!app_name) app_name="";
    if (strlen(email)>255 || strlen(app_name)>128) return false;
    if (device_name) {
        if (!*device_name || strlen(device_name)>=sizeof(out->machine)) return false;
        memcpy(out->machine,device_name,strlen(device_name)+1);
    } else {
        snprintf(out->machine,sizeof(out->machine),"esp32.%02x%02x%02x%02x%02x%02x",
            mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    }
    for (char *p=out->machine;*p;++p) if (*p=='-') *p='.';
    const char *separator=*app_name ? "-" : "";
    int n=snprintf(out->location,sizeof(out->location),"%s-%s%s%s",email,app_name,separator,out->machine);
    /* Backend registration caps Location at 255; never silently truncate it. */
    if (n<0 || (size_t)n>=sizeof(out->location)) return false;
    char full[320];
    n=snprintf(full,sizeof(full),"%s-%s%s%s",owner,app_name,separator,out->machine);
    if (n<0 || (size_t)n>=sizeof(full)) return false;
    size_t length=strlen(full);
    if (length>255) {
        length=255;
        /* Keep UTF-8 intact at the byte-size limit. */
        while (length && ((unsigned char)full[length]&0xc0)==0x80) --length;
    }
    memcpy(out->app_id,full,length); out->app_id[length]=0;
    return true;
}
static inline bool nm_enrollment_monitors(yyjson_mut_val *monitors,unsigned maximum)
{
    if (!yyjson_mut_is_arr(monitors) || yyjson_mut_arr_size(monitors)>maximum) return false;
    size_t index, count;
    yyjson_mut_val *monitor;
    yyjson_mut_arr_foreach(monitors,index,count,monitor) {
        yyjson_mut_val *id=yyjson_mut_obj_get(monitor,"ID");
        if (!yyjson_mut_is_obj(monitor) || !yyjson_mut_is_uint(id) ||
            yyjson_mut_get_uint(id)>INT32_MAX) return false;
    }
    return true;
}
#endif
