#ifndef NM_ARP_TEST_NETIF_H
#define NM_ARP_TEST_NETIF_H
#include <arpa/inet.h>
#include <stdint.h>
typedef struct { uint32_t addr; } ip4_addr_t;
struct netif {
    ip4_addr_t ip_addr, netmask;
    uint8_t hwaddr[6], hwaddr_len, flags;
    int up, link_up;
};
#define NETIF_FLAG_ETHARP 2
#define netif_is_up(n) ((n)->up)
#define netif_is_link_up(n) ((n)->link_up)
#define netif_ip4_addr(n) (&(n)->ip_addr)
#define netif_ip4_netmask(n) (&(n)->netmask)
#define ip4_addr_cmp(a,b) ((a)->addr == (b)->addr)
#define ip4_addr_netcmp(a,b,m) (((a)->addr & (m)->addr) == ((b)->addr & (m)->addr))
#define ip4_addr_ismulticast(a) ((ntohl((a)->addr) & 0xf0000000U) == 0xe0000000U)
#define ip4_addr_isany_val(a) ((a).addr == 0)
#define lwip_htonl htonl
#define lwip_ntohl ntohl
#endif
