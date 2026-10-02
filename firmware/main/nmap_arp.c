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
#ifdef ESP_PLATFORM
#include "esp_log.h"
#endif

typedef struct arp_waiter {
    struct arp_waiter *next;
} arp_waiter;

/* Intrusive FIFO: nodes belong to waiting callers and are unlinked before
 * return. The lock protects only a few pointer operations, never SDK calls. */
static atomic_flag admission_lock = ATOMIC_FLAG_INIT;
static arp_waiter *wait_head, *wait_tail;
static bool owned;

static void lock_admission(void)
{
    while (atomic_flag_test_and_set_explicit(&admission_lock, memory_order_acquire))
        vTaskDelay(nm_endpoint_wait_ticks(1));
}

static void unlock_admission(void)
{
    atomic_flag_clear_explicit(&admission_lock, memory_order_release);
}

static void unlink_waiter(arp_waiter *waiter)
{
    arp_waiter *previous = NULL;
    for (arp_waiter *item = wait_head; item; item = item->next) {
        if (item == waiter) {
            if (previous)
                previous->next = item->next;
            else
                wait_head = item->next;
            if (wait_tail == item)
                wait_tail = previous;
            return;
        }
        previous = item;
    }
}

static nm_nmap_arp_state acquire_observer(int64_t started, unsigned timeout,
                                          const atomic_bool *cancellation)
{
    arp_waiter waiter = {0};
    lock_admission();
    bool queued = owned || wait_head;
    if (wait_tail)
        wait_tail->next = &waiter;
    else
        wait_head = &waiter;
    wait_tail = &waiter;
    unlock_admission();
    for (;;) {
        lock_admission();
        bool cancelled = cancellation && atomic_load(cancellation);
        unsigned remaining = nm_endpoint_remaining(started, timeout);
        bool admitted = !cancelled && remaining && !owned && wait_head == &waiter;
        if (cancelled || !remaining || admitted) {
            unlink_waiter(&waiter);
            if (admitted)
                owned = true;
            unlock_admission();
#ifdef ESP_PLATFORM
            if (queued)
                ESP_LOGI("nm_nmap_arp",
                         "FIFO wait completed: admitted=%d cancelled=%d wait_ms=%lld", admitted,
                         cancelled, (long long)((esp_timer_get_time() - started) / 1000));
#else
            (void)queued;
#endif
            return cancelled ? NM_ARP_CANCELLED : admitted ? NM_ARP_REPLY : NM_ARP_LOCAL_FAILURE;
        }
        unlock_admission();
        vTaskDelay(nm_endpoint_wait_ticks(remaining > 10 ? 10 : remaining));
    }
}

/* active/netif/target/mac are accessed only by the TCP/IP core, except mac
 * which the owner reads after received's release/acquire publication.
 * The observer is permanent: packet processing never borrows a probe stack.
 */
static struct {
    atomic_bool received;
    bool active;
    struct netif *netif;
    ip4_addr_t target;
    uint8_t mac[6];
} observer;

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
    int64_t started = esp_timer_get_time();
    result.state = acquire_observer(started, timeout_ms, cancellation);
    if (result.state != NM_ARP_REPLY)
        return result;
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
    lock_admission();
    owned = false;
    unlock_admission();
    return result;
}
