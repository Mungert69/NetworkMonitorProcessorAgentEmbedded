#include "nmap_arp.h"
#include "esp_netif.h"
#include "lwip/etharp.h"
#include "lwip/pbuf.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

void __wrap_etharp_input(struct pbuf *, struct netif *);
static struct netif sta;
static bool in_core, send_reply, bad_packet, exec_failure;
static int send_error;
static unsigned requests, forwarded, delays;
static int64_t now;
static atomic_bool *cancel_at_delay;
static uint8_t frame[28];

static void feed(struct netif *netif, uint16_t size)
{
    struct pbuf packet = {.payload = frame, .len = size};
    bool previous = in_core;
    in_core = true;
    __wrap_etharp_input(&packet, netif);
    in_core = previous;
}

esp_err_t esp_netif_tcpip_exec(esp_netif_callback_fn callback, void *context)
{
    assert(!in_core); /* Caller waits outside core; callbacks do not wait. */
    if (exec_failure) {
        exec_failure = false;
        return ESP_ERR_NO_MEM;
    }
    in_core = true;
    esp_err_t result = callback(context);
    in_core = false;
    return result;
}
esp_netif_t *esp_netif_get_handle_from_ifkey(const char *key)
{
    assert(in_core && !strcmp(key, "WIFI_STA_DEF"));
    return &sta;
}
void *esp_netif_get_netif_impl(esp_netif_t *netif)
{
    assert(in_core);
    return netif;
}
err_t etharp_request(struct netif *netif, const ip4_addr_t *target)
{
    assert(in_core && netif == &sta);
    ++requests;
    memset(frame, 0, sizeof(frame));
    frame[1] = 1;
    frame[2] = 8;
    frame[4] = 6;
    frame[5] = 4;
    frame[7] = 2;
    const uint8_t sender[6] = {2, 3, 4, 5, 6, 7};
    memcpy(frame + 8, sender, 6);
    memcpy(frame + 14, &target->addr, 4);
    memcpy(frame + 18, sta.hwaddr, 6);
    memcpy(frame + 24, &sta.ip_addr.addr, 4);
    if (bad_packet)
        frame[7] = 1; /* A request cannot satisfy an outstanding probe. */
    return send_error;
}
uint16_t pbuf_copy_partial(const struct pbuf *packet, void *output, uint16_t size, uint16_t offset)
{
    assert(in_core);
    if (offset > packet->len)
        return 0;
    if (size > packet->len - offset)
        size = packet->len - offset;
    memcpy(output, (uint8_t *)packet->payload + offset, size);
    return size;
}
void __real_etharp_input(struct pbuf *packet, struct netif *netif)
{
    assert(in_core && packet && netif);
    ++forwarded; /* All frames, including invalid/unmatched ones, reach lwIP. */
}
int64_t esp_timer_get_time(void)
{
    return now;
}
unsigned nm_endpoint_remaining(int64_t started, unsigned timeout)
{
    unsigned elapsed = (unsigned)((now - started) / 1000);
    return elapsed < timeout ? timeout - elapsed : 0;
}
TickType_t nm_endpoint_wait_ticks(unsigned milliseconds)
{
    return milliseconds;
}
void vTaskDelay(TickType_t ticks)
{
    assert(!in_core);
    now += (int64_t)ticks * 1000;
    ++delays;
    if (cancel_at_delay)
        atomic_store(cancel_at_delay, true);
    if (send_reply)
        feed(&sta, sizeof(frame));
}
static void reset(void)
{
    sta = (struct netif){.ip_addr = {.addr = htonl(UINT32_C(0xc0a80109))},
                         .netmask = {.addr = htonl(UINT32_C(0xffffff00))},
                         .hwaddr = {2, 10, 11, 12, 13, 14},
                         .hwaddr_len = 6,
                         .flags = NETIF_FLAG_ETHARP,
                         .up = 1,
                         .link_up = 1};
    send_reply = true;
    bad_packet = exec_failure = false;
    send_error = 0;
    requests = forwarded = delays = 0;
    cancel_at_delay = NULL;
    now = 0;
}
int main(void)
{
    const uint32_t target = UINT32_C(0xc0a8012a);
    reset();
    nm_nmap_arp_result result = nm_nmap_arp_probe(target, 100, NULL);
    const uint8_t expected[6] = {2, 3, 4, 5, 6, 7};
    assert(result.state == NM_ARP_REPLY && !result.local_interface);
    assert(!memcmp(result.mac, expected, 6) && requests == 1 && forwarded == 1);

    /* Cached/late traffic from an earlier probe is not scan evidence. */
    feed(&sta, sizeof(frame));
    send_reply = false;
    result = nm_nmap_arp_probe(target, 30, NULL);
    assert(result.state == NM_ARP_TIMEOUT && now == 40000);
    feed(&sta, sizeof(frame));
    result = nm_nmap_arp_probe(target, 30, NULL);
    assert(result.state == NM_ARP_TIMEOUT);

    reset();
    bad_packet = true;
    result = nm_nmap_arp_probe(target, 30, NULL);
    assert(result.state == NM_ARP_TIMEOUT && forwarded == 3);
    bad_packet = false;
    result = nm_nmap_arp_probe(target, 30, NULL);
    assert(result.state == NM_ARP_REPLY);

    reset();
    result = nm_nmap_arp_probe(UINT32_C(0xc0a80109), 30, NULL);
    assert(result.state == NM_ARP_REPLY && result.local_interface && !requests && !delays);
    assert(!memcmp(result.mac, sta.hwaddr, 6));
    result = nm_nmap_arp_probe(UINT32_C(0xc0a8022a), 30, NULL);
    assert(result.state == NM_ARP_OFF_LINK && !requests);
    result = nm_nmap_arp_probe(UINT32_C(0xc0a801ff), 30, NULL);
    assert(result.state == NM_ARP_OFF_LINK && !requests);

    reset();
    send_error = ERR_MEM;
    assert(nm_nmap_arp_probe(target, 30, NULL).state == NM_ARP_LOCAL_FAILURE);
    send_error = ERR_IF;
    assert(nm_nmap_arp_probe(target, 30, NULL).state == NM_ARP_ERROR);
    send_error = ERR_OK;
    sta.link_up = 0;
    assert(nm_nmap_arp_probe(target, 30, NULL).state == NM_ARP_LOCAL_FAILURE);
    sta.link_up = 1;
    exec_failure = true;
    assert(nm_nmap_arp_probe(target, 30, NULL).state == NM_ARP_LOCAL_FAILURE);
    assert(nm_nmap_arp_probe(target, 30, NULL).state == NM_ARP_REPLY);

    reset();
    atomic_bool cancelled = true;
    assert(nm_nmap_arp_probe(target, 30, &cancelled).state == NM_ARP_CANCELLED && !requests);
    atomic_store(&cancelled, false);
    cancel_at_delay = &cancelled;
    assert(nm_nmap_arp_probe(target, 30000, &cancelled).state == NM_ARP_CANCELLED);
    assert(now <= 10000);
    cancel_at_delay = NULL;
    atomic_store(&cancelled, false);
    assert(nm_nmap_arp_probe(target, 30, &cancelled).state == NM_ARP_REPLY);
    puts("NMAP_ARP_LIFETIME_PASS");
    return 0;
}
