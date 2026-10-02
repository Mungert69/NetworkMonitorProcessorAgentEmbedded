#include "nmap_arp.h"
#include "endpoint_internal.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include <stdbool.h>
#include <string.h>

/* active/netif/target/mac are accessed only by the TCP/IP core, except mac
 * which the owner reads after received's release/acquire publication.
 * The observer is permanent: packet processing never borrows a probe stack.
 */
static struct {
    atomic_flag busy;
    atomic_bool received;
    bool active;
    struct netif *netif;
    ip4_addr_t target;
    uint8_t mac[6];
} observer = {.busy = ATOMIC_FLAG_INIT};

typedef struct {
    uint32_t ipv4;
    nm_nmap_arp_state state;
} arp_start;

/* ethernet_input has already removed the Ethernet header. Wrap only this
 * narrow lwIP entry: preserve its ownership and always call the real handler.
 * An ARP-cache lookup cannot distinguish old entries from this scan's replies.
 */
void __real_etharp_input(struct pbuf *packet, struct netif *netif);
void __wrap_etharp_input(struct pbuf *packet, struct netif *netif)
{
    uint8_t arp[28];
    if (observer.active && netif == observer.netif &&
        !atomic_load_explicit(&observer.received, memory_order_relaxed) && packet &&
        packet->len >= sizeof(arp) &&
        pbuf_copy_partial(packet, arp, sizeof(arp), 0) == sizeof(arp) && arp[0] == 0 &&
        arp[1] == 1 && arp[2] == 8 && arp[3] == 0 && arp[4] == 6 && arp[5] == 4 && arp[6] == 0 &&
        arp[7] == 2 && !(arp[8] & 1) && memcmp(arp + 14, &observer.target.addr, 4) == 0 &&
        memcmp(arp + 18, netif->hwaddr, 6) == 0 &&
        memcmp(arp + 24, &netif_ip4_addr(netif)->addr, 4) == 0) {
        static const uint8_t zero_mac[6];
        if (memcmp(arp + 8, zero_mac, 6) != 0) {
            memcpy(observer.mac, arp + 8, 6);
            atomic_store_explicit(&observer.received, true, memory_order_release);
        }
    }
    __real_etharp_input(packet, netif);
}

static esp_err_t start_probe(void *argument)
{
    arp_start *start = argument;
    observer.active = false;
    observer.netif = NULL;
    start->state = NM_ARP_LOCAL_FAILURE;
    esp_netif_t *sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    struct netif *netif = sta ? esp_netif_get_netif_impl(sta) : NULL;
    if (!netif || !netif_is_up(netif) || !netif_is_link_up(netif) ||
        !(netif->flags & NETIF_FLAG_ETHARP) || netif->hwaddr_len != 6)
        return ESP_OK;
    start->state = NM_ARP_OFF_LINK;
    ip4_addr_t target = {.addr = lwip_htonl(start->ipv4)};
    if (!start->ipv4 || start->ipv4 == UINT32_MAX || ip4_addr_ismulticast(&target) ||
        ip4_addr_isany_val(*netif_ip4_addr(netif)) ||
        !ip4_addr_netcmp(&target, netif_ip4_addr(netif), netif_ip4_netmask(netif)))
        return ESP_OK;
    uint32_t mask = lwip_ntohl(netif_ip4_netmask(netif)->addr);
    if (mask < UINT32_C(0xfffffffe) && (!(start->ipv4 & ~mask) || (start->ipv4 & ~mask) == ~mask))
        return ESP_OK; /* subnet network/broadcast, not an individual host */

    observer.netif = netif;
    observer.target = target;
    atomic_store_explicit(&observer.received, false, memory_order_relaxed);
    if (ip4_addr_cmp(&target, netif_ip4_addr(netif))) {
        memcpy(observer.mac, netif->hwaddr, 6);
        atomic_store_explicit(&observer.received, true, memory_order_release);
        start->state = NM_ARP_REPLY;
        return ESP_OK;
    }
    observer.active = true;
    err_t error = etharp_request(netif, &target);
    start->state = error == ERR_OK                        ? NM_ARP_TIMEOUT
                   : error == ERR_MEM || error == ERR_BUF ? NM_ARP_LOCAL_FAILURE
                                                          : NM_ARP_ERROR;
    if (error != ERR_OK)
        observer.active = false;
    return ESP_OK;
}

static esp_err_t stop_probe(void *unused)
{
    (void)unused;
    observer.active = false;
    observer.netif = NULL;
    return ESP_OK;
}

nm_nmap_arp_result nm_nmap_arp_probe(uint32_t ipv4, unsigned timeout_ms,
                                     const atomic_bool *cancellation)
{
    nm_nmap_arp_result result = {.state = NM_ARP_TIMEOUT};
    if (cancellation && atomic_load(cancellation)) {
        result.state = NM_ARP_CANCELLED;
        return result;
    }
    if (!timeout_ms)
        return result;
    if (atomic_flag_test_and_set_explicit(&observer.busy, memory_order_acquire)) {
        result.state = NM_ARP_LOCAL_FAILURE;
        return result;
    }
    int64_t started = esp_timer_get_time();
    arp_start start = {.ipv4 = ipv4};
    esp_err_t error = esp_netif_tcpip_exec(start_probe, &start);
    result.state = error == ESP_OK ? start.state : NM_ARP_LOCAL_FAILURE;
    result.local_interface = result.state == NM_ARP_REPLY;
    if (result.state == NM_ARP_TIMEOUT || result.state == NM_ARP_REPLY) {
        for (;;) {
            if (cancellation && atomic_load(cancellation)) {
                result.state = NM_ARP_CANCELLED;
                break;
            }
            unsigned remaining = nm_endpoint_remaining(started, timeout_ms);
            if (!remaining) {
                result.state = NM_ARP_TIMEOUT;
                break;
            }
            if (atomic_load_explicit(&observer.received, memory_order_acquire)) {
                result.state = NM_ARP_REPLY;
                memcpy(result.mac, observer.mac, sizeof(result.mac));
                break;
            }
            vTaskDelay(nm_endpoint_wait_ticks(remaining > 10 ? 10 : remaining));
        }
    }
    /* This synchronous short callback completes before releasing admission.
     * It never waits for a packet; SDK callback dispatch latency counts in the
     * total budget. No netif input pointer or shared ARP cache is changed.
     */
    if (esp_netif_tcpip_exec(stop_probe, NULL) != ESP_OK)
        result.state = NM_ARP_LOCAL_FAILURE;
    atomic_flag_clear_explicit(&observer.busy, memory_order_release);
    return result;
}
