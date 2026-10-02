#ifndef NM_NMAP_ARP_H
#define NM_NMAP_ARP_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

typedef enum {
    NM_ARP_REPLY,
    NM_ARP_OFF_LINK,
    NM_ARP_TIMEOUT,
    NM_ARP_CANCELLED,
    NM_ARP_LOCAL_FAILURE,
    NM_ARP_ERROR
} nm_nmap_arp_state;

typedef struct {
    nm_nmap_arp_state state;
    uint8_t mac[6];
    bool local_interface;
} nm_nmap_arp_result;

/* IPv4 address is host-order. One bounded observer is shared by all callers;
 * FIFO admission waits within the same total timeout, with cancellation.
 * Admission expiry is local/inconclusive, not a host-down ARP timeout.
 * No caller/packet pointers survive completion.
 * Only a fresh ARP reply addressed to this STA, or the STA itself, proves up.
 * Core callbacks never wait for network I/O. The caller waits outside lwIP.
 */
nm_nmap_arp_result nm_nmap_arp_probe(uint32_t ipv4, unsigned timeout_ms,
                                     const atomic_bool *cancellation);

#endif
