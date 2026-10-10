#include "ble_buffer.h"
#include "nm_memory.h"
#include <ctype.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#ifdef ESP_PLATFORM
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_timer.h"
#include "esp_log.h"
static StaticSemaphore_t mutex_storage;
static SemaphoreHandle_t mutex;
static void lock(void)
{
    xSemaphoreTake(mutex, portMAX_DELAY);
}
static void unlock(void)
{
    xSemaphoreGive(mutex);
}
#else
#include <pthread.h>
#include <time.h>
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static void lock(void)
{
    pthread_mutex_lock(&mutex);
}
static void unlock(void)
{
    pthread_mutex_unlock(&mutex);
}
#endif

/* Immutable payload shared by consecutive identical receptions for one address.
 * references counts stored reception records, not snapshot references. Keeping
 * reception metadata separate preserves exact window/eviction/RSSI semantics. */
typedef struct payload {
    atomic_uint references;
    char address[NM_BLE_ADDRESS_TEXT_SIZE];
    uint16_t length;
    uint8_t bytes[];
} payload;
typedef struct packet {
    atomic_uint references;
    struct packet *next;
    int64_t received_us;
    uint64_t sequence, capture_id;
    payload *content;
    int8_t rssi;
} packet;
typedef struct address_history {
    struct address_history *next;
    char address[NM_BLE_ADDRESS_TEXT_SIZE];
    uint64_t retention_ms;
    packet *head, *tail;
} address_history;
struct nm_ble_snapshot {
    atomic_uint references;
    size_t count;
    int64_t captured_us;
    uint64_t last_sequence, previous_sequence;
    bool incomplete;
    packet *items[];
};
static address_history *history;
static nm_ble_snapshot *published;
static uint64_t next_sequence;
static bool available, gaps, rule_failure, publication_failed, loss_valid;
static int64_t loss_us;
static uint64_t dropped;
static atomic_size_t owned_bytes, owned_packets, owned_snapshots, owned_payloads;

bool nm_ble_buffer_init(void)
{
#ifdef ESP_PLATFORM
    /* Called at boot before starting NimBLE/processor tasks. */
    if (!mutex)
        mutex = xSemaphoreCreateMutexStatic(&mutex_storage);
    return mutex != NULL;
#else
    return true;
#endif
}
int64_t nm_ble_buffer_now_us(void)
{
#ifdef ESP_PLATFORM
    return esp_timer_get_time();
#else
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000000 + t.tv_nsec / 1000;
#endif
}
static bool normalize(const char *input, char out[NM_BLE_ADDRESS_TEXT_SIZE])
{
    size_t digits = 0, used = 0;
    if (!input)
        return false;
    for (; *input; ++input) {
        if (*input == ':' || *input == '-')
            continue;
        if (!isxdigit((unsigned char)*input) || digits == 12)
            return false;
        if (digits && !(digits % 2))
            out[used++] = ':';
        out[used++] = (char)toupper((unsigned char)*input);
        ++digits;
    }
    out[used] = 0;
    return digits == 12;
}
static address_history *find_address(const char *address)
{
    for (address_history *h = history; h; h = h->next)
        if (!strcmp(h->address, address))
            return h;
    address_history *h = nm_bulk_calloc(1, sizeof(*h));
    if (!h)
        return NULL;
    atomic_fetch_add(&owned_bytes, sizeof(*h));
    strcpy(h->address, address);
    h->next = history;
    history = h;
    return h;
}
static void packet_release(packet *p)
{
    if (atomic_fetch_sub(&p->references, 1) == 1) {
        payload *content = p->content;
        if (atomic_fetch_sub(&content->references, 1) == 1) {
            atomic_fetch_sub(&owned_bytes, sizeof(*content) + content->length);
            atomic_fetch_sub(&owned_payloads, 1);
            free(content);
        }
        atomic_fetch_sub(&owned_bytes, sizeof(*p));
        atomic_fetch_sub(&owned_packets, 1);
        free(p);
    }
}
void nm_ble_snapshot_release(nm_ble_snapshot *s)
{
    if (!s || atomic_fetch_sub(&s->references, 1) != 1)
        return;
    for (size_t i = 0; i < s->count; ++i)
        packet_release(s->items[i]);
    atomic_fetch_sub(&owned_bytes, sizeof(*s) + s->count * sizeof(packet *));
    atomic_fetch_sub(&owned_snapshots, 1);
    free(s);
}
void nm_ble_buffer_set_available(bool value)
{
    lock();
    available = value;
    unlock();
}
bool nm_ble_buffer_available(void)
{
    lock();
    bool value = available && !publication_failed;
    unlock();
    return value;
}
void nm_ble_buffer_rules_begin(void)
{
    lock();
    for (address_history *h = history; h; h = h->next)
        h->retention_ms = 0;
    rule_failure = false;
    unlock();
}
bool nm_ble_buffer_protect(const char *input, uint64_t window_ms)
{
    char address[NM_BLE_ADDRESS_TEXT_SIZE];
    if (!normalize(input, address) || window_ms > INT64_MAX / 2000)
        return false;
    lock();
    address_history *h = find_address(address);
    if (!h)
        rule_failure = gaps = true;
    else if (h->retention_ms < window_ms * 2)
        h->retention_ms = window_ms * 2;
    unlock();
    return h != NULL;
}
bool nm_ble_buffer_receive(const nm_ble_advertisement *input, int64_t now)
{
    if (!input || !input->data_length || input->data_length > NM_BLE_ADVERTISEMENT_MAX)
        return false;
    char address[NM_BLE_ADDRESS_TEXT_SIZE];
    if (!normalize(input->address, address))
        return false;
    lock();
    address_history *h = find_address(address);
    /* Anchor to the last retained reception, not the last seen repeat: an
     * unchanged advertiser must still contribute at least once per second.
     * Comparing only the tail preserves rapid A -> B -> A changes. */
    if (h && h->tail && now >= h->tail->received_us &&
        now - h->tail->received_us < INT64_C(1000000) &&
        h->tail->content->length == input->data_length &&
        !memcmp(h->tail->content->bytes, input->data, input->data_length)) {
        unlock();
        return true; /* Deliberate suppression, not capture/allocation failure. */
    }
    packet *p = h ? nm_bulk_malloc(sizeof(*p)) : NULL;
    if (!p) {
        gaps = loss_valid = true;
        loss_us = now;
        ++dropped;
        unlock();
        return false;
    }
    payload *content = h->tail ? h->tail->content : NULL;
    if (content && content->length == input->data_length &&
        !memcmp(content->bytes, input->data, input->data_length) &&
        atomic_load(&content->references) < UINT_MAX) {
        atomic_fetch_add(&content->references, 1);
    } else {
        content = nm_bulk_malloc(sizeof(*content) + input->data_length);
        if (!content) {
            free(p);
            gaps = loss_valid = true;
            loss_us = now;
            ++dropped;
            unlock();
            return false;
        }
        atomic_init(&content->references, 1);
        strcpy(content->address, address);
        content->length = (uint16_t)input->data_length;
        memcpy(content->bytes, input->data, content->length);
        atomic_fetch_add(&owned_bytes, sizeof(*content) + content->length);
        atomic_fetch_add(&owned_payloads, 1);
    }
    atomic_fetch_add(&owned_bytes, sizeof(*p));
    atomic_fetch_add(&owned_packets, 1);
    atomic_init(&p->references, 1);
    p->next = NULL;
    p->received_us = now;
    p->sequence = ++next_sequence;
    p->capture_id = input->capture_id ? input->capture_id : p->sequence;
    p->rssi = input->rssi;
    p->content = content;
    if (h->tail)
        h->tail->next = p;
    else
        h->head = p;
    h->tail = p;
    unlock();
    return true;
}
static int compare_packets(const void *a, const void *b)
{
    uint64_t x = (*(packet *const *)a)->sequence, y = (*(packet *const *)b)->sequence;
    return (x > y) - (x < y);
}
bool nm_ble_buffer_complete_cycle(int64_t now)
{
    lock();
#ifdef ESP_PLATFORM
    /* Copy counters under the existing publication lock; log only after unlock.
     * Diagnostic allocation failure must not alter capture/publication/eviction. */
    typedef struct {
        char address[NM_BLE_ADDRESS_TEXT_SIZE];
        uint64_t retention_ms, oldest_before_ms, oldest_after_ms;
        uint64_t first_capture, last_capture, first_sequence, last_sequence;
        int64_t first_us, last_us;
        size_t before, after, evicted, received, distinct_payloads;
    } address_diagnostic;
    size_t address_count = 0;
    for (address_history *h = history; h; h = h->next)
        ++address_count;
    address_diagnostic *diagnostics = nm_bulk_calloc(address_count, sizeof(*diagnostics));
    size_t diagnostic_count = 0;
#endif
    size_t count = 0;
    for (address_history *h = history; h; h = h->next)
        for (packet *p = h->head; p; p = p->next)
            ++count;
    nm_ble_snapshot *s = count <= (SIZE_MAX - sizeof(*s)) / sizeof(packet *)
                             ? nm_bulk_malloc(sizeof(*s) + count * sizeof(packet *))
                             : NULL;
    if (!s) {
        publication_failed = true;
#ifdef ESP_PLATFORM
        free(diagnostics);
#endif
        unlock();
        return false;
    } /* No eviction on failed publication. */
    atomic_fetch_add(&owned_bytes, sizeof(*s) + count * sizeof(packet *));
    atomic_fetch_add(&owned_snapshots, 1);
    uint64_t longest = 0;
    for (address_history *h = history; h; h = h->next)
        if (h->retention_ms > longest)
            longest = h->retention_ms;
    if (loss_valid && now >= loss_us && (uint64_t)(now - loss_us) > longest * 1000)
        loss_valid = false;
    publication_failed = false;
    atomic_init(&s->references, 1);
    s->count = 0;
    s->captured_us = now;
    s->previous_sequence = published ? published->last_sequence : 0;
    s->last_sequence = next_sequence;
    s->incomplete = gaps || rule_failure || loss_valid;
    for (address_history *h = history; h; h = h->next)
        for (packet *p = h->head; p; p = p->next) {
            atomic_fetch_add(&p->references, 1);
            s->items[s->count++] = p;
        }
    qsort(s->items, s->count, sizeof(packet *), compare_packets);
    nm_ble_snapshot *old = published;
    published = s;
    /* Publish first. Snapshots retain packets independently of the live store. */
    for (address_history **entry = &history; *entry;) {
        address_history *h = *entry;
#ifdef ESP_PLATFORM
        address_diagnostic *d = diagnostics ? &diagnostics[diagnostic_count++] : NULL;
        if (d) {
            strcpy(d->address, h->address);
            d->retention_ms = h->retention_ms;
            packet *previous_new = NULL;
            for (packet *p = h->head; p; p = p->next) {
                ++d->before;
                if (now >= p->received_us) {
                    uint64_t age = (uint64_t)(now - p->received_us) / 1000;
                    if (age > d->oldest_before_ms)
                        d->oldest_before_ms = age;
                }
                if (p->sequence > s->previous_sequence) {
                    if (!d->received) {
                        d->first_capture = p->capture_id;
                        d->first_sequence = p->sequence;
                        d->first_us = p->received_us;
                    }
                    d->last_capture = p->capture_id;
                    d->last_sequence = p->sequence;
                    d->last_us = p->received_us;
                    ++d->received;
                    /* Consecutive payload changes, not global deduplication. */
                    if (!previous_new || previous_new->content->length != p->content->length ||
                        memcmp(previous_new->content->bytes, p->content->bytes, p->content->length))
                        ++d->distinct_payloads;
                    previous_new = p;
                }
            }
        }
#endif
        for (packet **link = &h->head; *link;) {
            packet *p = *link;
            bool expired =
                now >= p->received_us && (uint64_t)(now - p->received_us) > h->retention_ms * 1000;
            if (!rule_failure && (!h->retention_ms || expired)) {
                *link = p->next;
#ifdef ESP_PLATFORM
                if (d)
                    ++d->evicted;
#endif
                packet_release(p);
            } else {
#ifdef ESP_PLATFORM
                if (d) {
                    ++d->after;
                    if (now >= p->received_us) {
                        uint64_t age = (uint64_t)(now - p->received_us) / 1000;
                        if (age > d->oldest_after_ms)
                            d->oldest_after_ms = age;
                    }
                }
#endif
                link = &p->next;
            }
        }
        h->tail = h->head;
        while (h->tail && h->tail->next)
            h->tail = h->tail->next;
        if (!h->head && !h->retention_ms) {
            *entry = h->next;
            atomic_fetch_sub(&owned_bytes, sizeof(*h));
            free(h);
        } else
            entry = &h->next;
    }
    gaps = false;
#ifdef ESP_PLATFORM
    bool eviction_skipped = rule_failure;
    size_t duplicate_ids = 0;
    for (size_t i = 1; i < s->count; ++i)
        if (s->items[i]->capture_id <= s->items[i - 1]->capture_id)
            ++duplicate_ids;
    uint64_t cutoff_sequence = s->previous_sequence, last_sequence = s->last_sequence;
#endif
    unlock();
    nm_ble_snapshot_release(old);
#ifdef ESP_PLATFORM
    size_t live = 0, evicted = 0, received = 0;
    for (size_t i = 0; i < diagnostic_count; ++i) {
        const address_diagnostic *d = &diagnostics[i];
        live += d->after;
        evicted += d->evicted;
        received += d->received;
        ESP_LOGD("nm_ble_buffer",
                 "address=%s retention_ms=%llu new=%u payload_runs=%u "
                 "before=%u live=%u evicted=%u oldest_before_ms=%llu oldest_live_ms=%llu",
                 d->address, (unsigned long long)d->retention_ms, (unsigned)d->received,
                 (unsigned)d->distinct_payloads, (unsigned)d->before, (unsigned)d->after,
                 (unsigned)d->evicted, (unsigned long long)d->oldest_before_ms,
                 (unsigned long long)d->oldest_after_ms);
        ESP_LOGD("nm_ble_buffer",
                 "capture_range address=%s new=%u callback_first=%llu "
                 "callback_last=%llu sequence_first=%llu sequence_last=%llu "
                 "arrival_first_us=%lld arrival_last_us=%lld",
                 d->address, (unsigned)d->received, (unsigned long long)d->first_capture,
                 (unsigned long long)d->last_capture, (unsigned long long)d->first_sequence,
                 (unsigned long long)d->last_sequence, (long long)d->first_us,
                 (long long)d->last_us);
    }
    if (diagnostics)
        ESP_LOGD("nm_ble_buffer",
                 "cycle new=%u snapshot_packets=%u live_after_eviction=%u evicted=%u "
                 "eviction_skipped=%d duplicate_capture_ids=%u previous_sequence=%llu "
                 "last_sequence=%llu",
                 (unsigned)received, (unsigned)count, (unsigned)live, (unsigned)evicted,
                 eviction_skipped, (unsigned)duplicate_ids, (unsigned long long)cutoff_sequence,
                 (unsigned long long)last_sequence);
    else
        ESP_LOGW("nm_ble_buffer", "per-address diagnostic allocation unavailable");
    free(diagnostics);
#endif
    return true;
}
nm_ble_snapshot *nm_ble_buffer_acquire(void)
{
    lock();
    nm_ble_snapshot *s = published;
    if (s)
        atomic_fetch_add(&s->references, 1);
    unlock();
    return s;
}
size_t nm_ble_snapshot_count(const nm_ble_snapshot *s)
{
    return s ? s->count : 0;
}
int64_t nm_ble_snapshot_time(const nm_ble_snapshot *s)
{
    return s ? s->captured_us : 0;
}
uint64_t nm_ble_snapshot_previous(const nm_ble_snapshot *s)
{
    return s ? s->previous_sequence : 0;
}
bool nm_ble_snapshot_incomplete(const nm_ble_snapshot *s)
{
    return s && s->incomplete;
}
bool nm_ble_snapshot_read(const nm_ble_snapshot *s, size_t i, nm_ble_advertisement *out,
                          int64_t *received, uint64_t *sequence)
{
    if (!s || i >= s->count || !out)
        return false;
    packet *p = s->items[i];
    memset(out, 0, sizeof(*out));
    strcpy(out->address, p->content->address);
    out->rssi = p->rssi;
    out->capture_id = p->capture_id;
    out->data_length = p->content->length;
    memcpy(out->data, p->content->bytes, p->content->length);
    if (received)
        *received = p->received_us;
    if (sequence)
        *sequence = p->sequence;
    return true;
}
nm_ble_buffer_stats nm_ble_buffer_get_stats(void)
{
    lock();
    nm_ble_buffer_stats stats = {atomic_load(&owned_bytes), atomic_load(&owned_packets),
                                 atomic_load(&owned_snapshots), dropped,
                                 atomic_load(&owned_payloads)};
    unlock();
    return stats;
}
void nm_ble_buffer_reset(void)
{
    lock();
    nm_ble_snapshot *old = published;
    published = NULL;
    while (history) {
        address_history *h = history;
        history = h->next;
        while (h->head) {
            packet *p = h->head;
            h->head = p->next;
            packet_release(p);
        }
        atomic_fetch_sub(&owned_bytes, sizeof(*h));
        free(h);
    }
    next_sequence = 0;
    available = gaps = rule_failure = publication_failed = loss_valid = false;
    dropped = 0;
    unlock();
    nm_ble_snapshot_release(old);
}
