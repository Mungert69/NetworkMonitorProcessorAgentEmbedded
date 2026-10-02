#ifndef NM_ARP_TEST_ETHARP_H
#define NM_ARP_TEST_ETHARP_H
#include "netif.h"
typedef int err_t;
#define ERR_OK 0
#define ERR_MEM -1
#define ERR_BUF -2
#define ERR_IF -12
err_t etharp_request(struct netif *, const ip4_addr_t *);
#endif
