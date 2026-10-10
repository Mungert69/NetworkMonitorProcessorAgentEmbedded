/* Production service with allocator failures and concurrent callback/readers. */
#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
static int fail_after = -1;
static void *test_malloc(size_t size)
{
    if (fail_after == 0)
        return NULL;
    if (fail_after > 0)
        --fail_after;
    return malloc(size);
}
static void *test_calloc(size_t count, size_t size)
{
    if (fail_after == 0)
        return NULL;
    if (fail_after > 0)
        --fail_after;
    return calloc(count, size);
}
#define malloc test_malloc
#define calloc test_calloc
#include "../../firmware/main/ble_buffer.c"
#undef malloc
#undef calloc
static nm_ble_advertisement advertisement(const char *address)
{
    nm_ble_advertisement p = {.rssi = -50, .data_length = 3, .data = {2, 1, 6}};
    strcpy(p.address, address);
    return p;
}
static void clean(void)
{
    fail_after = -1;
    nm_ble_buffer_reset();
    nm_ble_buffer_stats s = nm_ble_buffer_get_stats();
    assert(s.bytes == 0 && s.packets == 0 && s.snapshots == 0 && s.payloads == 0);
}
static void capture_identity_survives_publication(void)
{
    nm_ble_advertisement p = advertisement("AA:BB:CC:DD:EE:FF");
    nm_ble_buffer_rules_begin();
    assert(nm_ble_buffer_protect(p.address, 70000));
    p.capture_id = 100;
    assert(nm_ble_buffer_receive(&p, 1000000));
    p.capture_id = 101; /* Identical bytes, different discovery callback. */
    assert(nm_ble_buffer_receive(&p, 2000000));
    assert(nm_ble_buffer_complete_cycle(2000000));
    nm_ble_snapshot *first = nm_ble_buffer_acquire();
    nm_ble_advertisement out;
    int64_t received;
    uint64_t sequence;
    assert(nm_ble_snapshot_read(first, 0, &out, &received, &sequence));
    assert(out.capture_id == 100 && received == 1000000 && sequence == 1);
    assert(nm_ble_snapshot_read(first, 1, &out, &received, &sequence));
    assert(out.capture_id == 101 && received == 2000000 && sequence == 2);
    p.capture_id = 102;
    assert(nm_ble_buffer_receive(&p, 3000000));
    assert(nm_ble_buffer_complete_cycle(4000000));
    nm_ble_snapshot *second = nm_ble_buffer_acquire();
    assert(nm_ble_snapshot_count(second) == 3);
    size_t newly_emitted = 0;
    for (size_t i = 0; i < nm_ble_snapshot_count(second); ++i) {
        assert(nm_ble_snapshot_read(second, i, &out, &received, &sequence));
        if (sequence > nm_ble_snapshot_previous(second)) {
            ++newly_emitted;
            assert(out.capture_id == 102 && received == 3000000 && sequence == 3);
        }
    }
    assert(newly_emitted == 1); /* Retention does not make older IDs new again. */
    nm_ble_snapshot_release(first);
    nm_ble_snapshot_release(second);
    clean();
}
static void repeat_filter_boundaries(void)
{
    nm_ble_advertisement p = advertisement("AA:BB:CC:DD:EE:FF");
    assert(nm_ble_buffer_protect(p.address, 70000));
    assert(nm_ble_buffer_receive(&p, 0));
    size_t original_bytes = nm_ble_buffer_get_stats().bytes;
    fail_after = 0; /* Suppression must succeed without any allocation. */
    p.rssi = -80;   /* RSSI differences do not make a new payload. */
    assert(nm_ble_buffer_receive(&p, 999999));
    assert(nm_ble_buffer_get_stats().packets == 1);
    assert(nm_ble_buffer_get_stats().bytes == original_bytes);
    assert(nm_ble_buffer_get_stats().dropped == 0);
    fail_after = -1;
    assert(nm_ble_buffer_receive(&p, 1000000)); /* Inclusive acceptance boundary. */
    assert(nm_ble_buffer_get_stats().packets == 2);
    assert(nm_ble_buffer_complete_cycle(1000000));
    nm_ble_snapshot *old = nm_ble_buffer_acquire();
    assert(nm_ble_buffer_receive(&p, 1500000)); /* Publication doesn't reset anchor. */
    assert(nm_ble_buffer_get_stats().packets == 2);
    p.data[2] = 7;
    assert(nm_ble_buffer_receive(&p, 1500001));
    p.data[2] = 6;
    assert(nm_ble_buffer_receive(&p, 1500002)); /* A -> B -> A, all changes kept. */
    p.data_length = 2;
    assert(nm_ble_buffer_receive(&p, 1500003)); /* Changed length. */
    strcpy(p.address, "11:22:33:44:55:66");
    assert(nm_ble_buffer_receive(&p, 1500004)); /* Separate address. */
    assert(nm_ble_buffer_get_stats().packets == 6);
    assert(nm_ble_snapshot_count(old) == 2);
    assert(nm_ble_buffer_complete_cycle(2000000));
    nm_ble_snapshot *s = nm_ble_buffer_acquire();
    assert(nm_ble_snapshot_count(s) == 6 && !nm_ble_snapshot_incomplete(s));
    nm_ble_snapshot_release(s);
    nm_ble_snapshot_release(old);
    clean();
}
static void repeated_payload_storage(void)
{
    nm_ble_advertisement p = advertisement("AA:BB:CC:DD:EE:FF");
    p.data_length = 200;
    nm_ble_buffer_rules_begin();
    assert(nm_ble_buffer_protect(p.address, 70000));
    for (int i = 0; i < 100; ++i) {
        p.rssi = (int8_t)(-i);
        assert(nm_ble_buffer_receive(&p, i * 1000000LL));
    }
    nm_ble_buffer_stats stats = nm_ble_buffer_get_stats();
    assert(stats.packets == 100 && stats.payloads == 1);
    assert(atomic_load(&history->head->content->references) == 100);
    assert(stats.bytes < 100 * (sizeof(packet) + p.data_length));
    assert(nm_ble_buffer_complete_cycle(100000000));
    nm_ble_snapshot *old = nm_ble_buffer_acquire();
    p.data[2] = 7;
    assert(nm_ble_buffer_receive(&p, 101000000));
    assert(nm_ble_buffer_get_stats().payloads == 2);
    assert(nm_ble_buffer_complete_cycle(200000000));
    /* Partial eviction of the repeated run retains exact timestamps/RSSI. */
    nm_ble_advertisement out;
    int64_t timestamp;
    assert(nm_ble_snapshot_read(old, 0, &out, &timestamp, NULL));
    assert(timestamp == 0 && out.rssi == 0 && out.data[2] == 6);
    assert(nm_ble_snapshot_read(old, 99, &out, &timestamp, NULL));
    assert(timestamp == 99000000 && out.rssi == -99 && out.data[2] == 6);
    nm_ble_buffer_reset();
    assert(nm_ble_snapshot_read(old, 50, &out, &timestamp, NULL));
    assert(timestamp == 50000000 && out.data[2] == 6);
    nm_ble_snapshot_release(old);
    clean();
}
static void lifetime_and_eviction(void)
{
    nm_ble_advertisement p = advertisement("AA:BB:CC:DD:EE:FF");
    nm_ble_buffer_rules_begin();
    assert(nm_ble_buffer_protect("aa-bb-cc-dd-ee-ff", 70000));
    assert(nm_ble_buffer_receive(&p, 0));
    p = advertisement("11:22:33:44:55:66");
    assert(nm_ble_buffer_receive(&p, 1000000));
    assert(nm_ble_buffer_complete_cycle(60000000));
    nm_ble_snapshot *first = nm_ble_buffer_acquire();
    assert(nm_ble_snapshot_count(first) == 2);
    assert(nm_ble_buffer_complete_cycle(140000000));
    nm_ble_snapshot *boundary = nm_ble_buffer_acquire();
    assert(nm_ble_snapshot_count(boundary) == 1);
    assert(nm_ble_buffer_complete_cycle(140000001)); /* snapshot BEFORE eviction */
    assert(nm_ble_buffer_complete_cycle(150000000));
    nm_ble_snapshot *empty = nm_ble_buffer_acquire();
    assert(nm_ble_snapshot_count(empty) == 0);
    nm_ble_snapshot_release(empty);
    nm_ble_buffer_reset();
    nm_ble_advertisement copy;
    uint64_t sequence;
    int64_t timestamp;
    assert(nm_ble_snapshot_read(first, 0, &copy, &timestamp, &sequence));
    assert(timestamp == 0 && sequence == 1 && !strcmp(copy.address, "AA:BB:CC:DD:EE:FF"));
    assert(nm_ble_snapshot_read(first, 1, &copy, NULL, NULL));
    assert(!nm_ble_snapshot_read(first, 2, &copy, NULL, NULL));
    nm_ble_snapshot_release(first);
    nm_ble_snapshot_release(boundary);
    clean();
}
static void long_windows_and_rules(void)
{
    nm_ble_advertisement p = advertisement("AA:BB:CC:DD:EE:FF");
    nm_ble_buffer_rules_begin();
    assert(nm_ble_buffer_protect(p.address, 86400000));
    assert(nm_ble_buffer_protect(p.address, 70000)); /* max, not last rule */
    assert(nm_ble_buffer_receive(&p, 0));
    assert(nm_ble_buffer_complete_cycle(INT64_C(172800000000)));
    assert(nm_ble_buffer_complete_cycle(INT64_C(172800000001)));
    nm_ble_snapshot *s = nm_ble_buffer_acquire();
    assert(nm_ble_snapshot_count(s) == 1);
    nm_ble_snapshot_release(s);
    assert(nm_ble_buffer_complete_cycle(INT64_C(172800000002)));
    s = nm_ble_buffer_acquire();
    assert(nm_ble_snapshot_count(s) == 0);
    nm_ble_snapshot_release(s);
    clean();
}
static void failures(void)
{
    nm_ble_advertisement p = advertisement("AA:BB:CC:DD:EE:FF");
    nm_ble_buffer_set_available(true);
    assert(nm_ble_buffer_receive(&p, 0));
    fail_after = 0;
    assert(!nm_ble_buffer_complete_cycle(100));
    assert(!nm_ble_buffer_available());
    fail_after = -1;
    assert(nm_ble_buffer_complete_cycle(200));
    assert(nm_ble_buffer_available());
    nm_ble_snapshot *s = nm_ble_buffer_acquire();
    assert(nm_ble_snapshot_count(s) == 1); /* failed publication did NOT evict */
    nm_ble_snapshot_release(s);
    clean();
    nm_ble_buffer_rules_begin();
    assert(nm_ble_buffer_protect(p.address, 70000));
    assert(nm_ble_buffer_receive(&p, 0));
    fail_after = 0;
    assert(!nm_ble_buffer_receive(&p, 1000000));
    fail_after = -1;
    assert(nm_ble_buffer_complete_cycle(1000));
    s = nm_ble_buffer_acquire();
    assert(nm_ble_snapshot_incomplete(s));
    nm_ble_snapshot_release(s);
    assert(nm_ble_buffer_complete_cycle(1000000));
    s = nm_ble_buffer_acquire();
    assert(nm_ble_snapshot_incomplete(s));
    nm_ble_snapshot_release(s);
    assert(nm_ble_buffer_complete_cycle(141000001));
    s = nm_ble_buffer_acquire();
    assert(!nm_ble_snapshot_incomplete(s));
    nm_ble_snapshot_release(s);
    clean();
    /* Partial packet allocation: address allocation fails, no leak. */
    fail_after = 1;
    assert(!nm_ble_buffer_receive(&p, 0));
    clean();
    /* Incomplete rules preserve all history, including otherwise unprotected. */
    assert(nm_ble_buffer_receive(&p, 0));
    nm_ble_buffer_rules_begin();
    fail_after = 0;
    assert(!nm_ble_buffer_protect("11:22:33:44:55:66", 70000));
    fail_after = -1;
    assert(nm_ble_buffer_complete_cycle(100));
    assert(nm_ble_buffer_complete_cycle(200));
    s = nm_ble_buffer_acquire();
    assert(nm_ble_snapshot_count(s) == 1);
    nm_ble_snapshot_release(s);
    clean();
}
static void *producer(void *unused)
{
    (void)unused;
    nm_ble_advertisement p = advertisement("AA:BB:CC:DD:EE:FF");
    for (int i = 0; i < 3000; ++i)
        assert(nm_ble_buffer_receive(&p, i));
    return NULL;
}
static void concurrent(void)
{
    pthread_t thread;
    assert(!pthread_create(&thread, NULL, producer, NULL));
    for (int i = 0; i < 100; ++i) {
        assert(nm_ble_buffer_complete_cycle(4000));
        nm_ble_snapshot *s = nm_ble_buffer_acquire();
        nm_ble_advertisement copy;
        for (size_t j = 0; j < nm_ble_snapshot_count(s); ++j)
            assert(nm_ble_snapshot_read(s, j, &copy, NULL, NULL) && copy.data[2] == 6);
        nm_ble_snapshot_release(s);
    }
    assert(!pthread_join(thread, NULL));
    clean();
}
int main(void)
{
    assert(nm_ble_buffer_init());
    assert(!nm_ble_buffer_acquire());
    capture_identity_survives_publication();
    repeat_filter_boundaries();
    repeated_payload_storage();
    lifetime_and_eviction();
    long_windows_and_rules();
    failures();
    concurrent();
    puts("BLE buffer ownership, eviction, failure and concurrency tests passed");
}
