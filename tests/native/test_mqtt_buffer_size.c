#include "processor_mqtt_buffer.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    const char *client_id = "u_84ab1c49-e8f2-4bb0-b347-06a3713c4798_p_0123456789abcdef";
    const char *username = "84ab1c49-e8f2-4bb0-b347-06a3713c4798";
    char *password = malloc(65537);
    assert(password);

    memset(password, 'x', 4639);
    password[4639] = '\0';
    assert(nm_mqtt_out_size(client_id, username, password) == NM_MQTT_OUT_MIN);

    memset(password, 'x', 24576);
    password[24576] = '\0';
    assert(nm_mqtt_out_size(client_id, username, password) ==
           (int)(NM_MQTT_CONNECT_OVERHEAD + strlen(client_id) +
                 strlen(username) + 24576));

    memset(password, 'x', 65536);
    password[65536] = '\0';
    assert(nm_mqtt_out_size(client_id, username, password) == 0);
    assert(nm_mqtt_out_size(client_id, NULL, password) == 0);
    free(password);
    return 0;
}
