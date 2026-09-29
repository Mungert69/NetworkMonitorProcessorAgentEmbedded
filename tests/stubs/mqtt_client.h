#ifndef NM_TEST_MQTT_CLIENT_H
#define NM_TEST_MQTT_CLIENT_H
typedef struct nm_test_mqtt_client *esp_mqtt_client_handle_t;
typedef const char *esp_event_base_t;
int esp_mqtt_client_publish(esp_mqtt_client_handle_t client, const char *topic,
                            const char *data, int len, int qos, int retain);
#endif
