#ifndef NM_ARP_TEST_PBUF_H
#define NM_ARP_TEST_PBUF_H
#include <stdint.h>
struct pbuf { void *payload; uint16_t len; };
uint16_t pbuf_copy_partial(const struct pbuf *, void *, uint16_t, uint16_t);
#endif
