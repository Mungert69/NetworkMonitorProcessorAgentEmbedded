#include "enrollment_internal.h"
#include "esp_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *TAG = "nm_enrollment";
bool nm_esp_enroll(nm_esp_config *config)
{
    yyjson_mut_doc *doc = nm_json_clone(config->root);
    yyjson_mut_val *root = yyjson_mut_doc_get_root(doc);
    if (!root)
        return false;
    char *token = nm_enrollment_authorize(root);
    bool ok = token && nm_enrollment_identity(doc, root, token);
    free(token);
    const char *load = nm_enrollment_string(root, "LoadServer");
    if (!load)
        load = "loadserver.readyforquantum.com";
    char url[768];
    yyjson_mut_doc *discovery_doc = NULL;
    yyjson_mut_val *discovery = NULL;
    if (ok && strlen(load) < 256 && !strpbrk(load, "/@?#\\")) {
        snprintf(url, sizeof(url), "https://%s/Load/GetRabbitServerApi/%s", load,
                 nm_enrollment_string(root, "mqtt_username"));
        int status = 0;
        discovery_doc = nm_enrollment_request(url, NULL, &status);
        discovery = yyjson_mut_doc_get_root(discovery_doc);
        yyjson_mut_val *data = yyjson_mut_obj_get(discovery, "data");
        if (!data)
            data = yyjson_mut_obj_get(discovery, "Data");
        yyjson_mut_val *success = yyjson_mut_obj_get(discovery, "success");
        if (!success)
            success = yyjson_mut_obj_get(discovery, "Success");
        const char *host = nm_enrollment_string(data, "rabbitHostName");
        if (!host)
            host = nm_enrollment_string(data, "RabbitHostName");
        ok = status == 200 && yyjson_mut_is_true(success) && host && *host && strlen(host) < 240 &&
             !strpbrk(host, "/:@?#\\");
        if (ok) {
            snprintf(url, sizeof(url), "mqtts://%s:8883", host);
            ok = nm_json_put_str(doc, root, "broker_uri", url) &&
                 nm_json_put_str(doc, root, "RabbitHost", host) &&
                 nm_json_put_str(doc, root, "source", "https://readyforquantum.com") &&
                 nm_json_put_str(doc, root, "auth_key", "pending-enrollment") &&
                 nm_json_put(doc, root, "AuthDevice", yyjson_mut_bool(doc, false));
        }
    } else
        ok = false;
    yyjson_mut_doc_free(discovery_doc);
    nm_esp_config next = {.doc = doc};
    ok = ok && nm_esp_config_bind(&next, root) && nm_enrollment_register(&next) &&
         nm_esp_config_bind(&next, root) && nm_esp_config_save(&next);
    if (ok) {
        yyjson_mut_doc_free(config->doc);
        *config = next;
        ESP_LOGI(TAG, "Signed AuthKey verified; enrollment persisted, starting monitoring");
    } else
        yyjson_mut_doc_free(doc);
    return ok;
}
