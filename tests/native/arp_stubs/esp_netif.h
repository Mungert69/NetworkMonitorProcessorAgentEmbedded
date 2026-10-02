#ifndef NM_ARP_TEST_ESP_NETIF_H
#define NM_ARP_TEST_ESP_NETIF_H
#include "idf_stub.h"
#include "lwip/netif.h"
typedef struct netif esp_netif_t;
typedef esp_err_t (*esp_netif_callback_fn)(void *);
esp_err_t esp_netif_tcpip_exec(esp_netif_callback_fn, void *);
esp_netif_t *esp_netif_get_handle_from_ifkey(const char *);
#endif
