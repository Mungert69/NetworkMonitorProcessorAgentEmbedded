#include "ble_cmd_processor.h"
#include "ble_buffer.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static nm_ble_command parse(const char *text, bool listen)
{
    nm_ble_command r;
    const char *error;
    assert(nm_ble_cmd_parse(text, listen, &r, &error) && !error);
    return r;
}
static nm_cmd_result run(const char *text, bool listen)
{
    nm_ble_command r = parse(text, listen);
    return nm_ble_cmd_run(&r, NULL);
}
static void check(nm_cmd_result r, bool success, const char *contains)
{
    if (r.success != success || !r.output || !strstr(r.output, contains)) {
        fprintf(stderr, "unexpected result: %d %s\n", r.success, r.output ? r.output : "NULL");
        abort();
    }
    free(r.output);
}
int main(void)
{
    nm_ble_command r;
    const char *error;
    const char *bad[] = {"",
                         "--address nope",
                         "--address AABBCCDDEEFF --bad 1",
                         "--address AABBCCDDEEFF --nonce_len 0",
                         "--address AABBCCDDEEFF --tag_len 17",
                         "--address AABBCCDDEEFF --nonce_at middle",
                         "--address AABBCCDDEEFF --key short",
                         "--address AABBCCDDEEFF --payload bogus",
                         "--address AABBCCDDEEFF --raw_payload A",
                         "--address AABBCCDDEEFF --service_uuid bad",
                         "--address AABBCCDDEEFF --metric_scale nan",
                         "--address AABBCCDDEEFF --format unknown",
                         "--address 'AABBCCDDEEFF",
                         "--address AABBCCDDEEFF --manufacturer_id 65536",
                         "--address AABBCCDDEEFF --payload"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i)
        assert(!nm_ble_cmd_parse(bad[i], false, &r, &error));
    assert(!nm_ble_cmd_parse("--address AABBCCDDEEFF", true, &r, &error));
    r = parse("--address=aa-bb-cc-dd-ee-ff --format RAW --nonce_at END", false);
    assert(!strcmp(r.address, "AA:BB:CC:DD:EE:FF") && r.nonce_at_end);
    check(run("--raw_payload 0102 --max_captures 1 --format ignored --key ignored", true), true,
          "BLE listen captured 1 advertisement(s).");
    check(run("--address AABBCCDDEEFF --raw_payload 0x0102", false), true, "Decrypted: 0102");
    /* BTHome v2: temperature=25C. Direct payload bypasses default pv_power metric. */
    check(run("--address AABBCCDDEEFF --format bthome --raw_payload 4002C409", false), true, "25");
    check(run("--address AABBCCDDEEFF --key 00000000000000000000000000000000 "
              "--raw_payload "
              "0000000000000000000000000388DACE60B6A392F328C2B971B2FE78AB6E47D42CEC13BDF53A67B21257"
              "BDDF",
              false),
          true, "Decrypted: 00000000000000000000000000000000");
    check(run("--address AABBCCDDEEFF --key 00000000000000000000000000000000 "
              "--raw_payload "
              "0000000000000000000000000388DACE60B6A392F328C2B971B2FE78AB6E47D42CEC13BDF53A67B21257"
              "BDDE",
              false),
          true, "Error: Decryption failed");
    atomic_bool cancel = true;
    r = parse("--raw_payload 0102", true);
    check(nm_ble_cmd_run(&r, &cancel), false, "canceled");
    nm_ble_buffer_reset();
    check(run("", true), false, "unavailable");
    nm_ble_buffer_set_available(true);
    int64_t now = nm_ble_buffer_now_us();
    assert(nm_ble_buffer_complete_cycle(now));
    check(run("", true), true, "captured 0 advertisement(s)");
    /* All retained advertisements, including those older than previous sequence. */
    assert(nm_ble_buffer_protect("AA:BB:CC:DD:EE:FF", 120000));
    nm_ble_advertisement item = {.address = "AA:BB:CC:DD:EE:FF",
                                 .data = {7, 0x16, 0xD2, 0xFC, 0x40, 0x02, 0xC4, 0x09},
                                 .data_length = 8};
    assert(nm_ble_buffer_receive(&item, now - 2000000));
    assert(nm_ble_buffer_complete_cycle(now - 1000000));
    item.data[6] = 0x8C;
    item.data[7] = 0x0A; /* 27C */
    assert(nm_ble_buffer_receive(&item, now));
    assert(nm_ble_buffer_complete_cycle(now));
    check(run("--max_captures 1", true), true, "captured 2 advertisement(s)");
    check(run("--address AABBCCDDEEFF --format bthome --metric temperature", false), true,
          "Window average: temperature=26 (2 readings)");
    check(run("--address AABBCCDDEEFF --format bthome --metric missing", false), false,
          "No usable");
    check(run("--address 112233445566", false), false, "No usable");
    check(run("--service_uuid fcd2 --payload service", true), true, "Payload (service): 4002C409");
    /* Finite report: no silent success when the 256-line/48KiB report limit hits. */
    for (unsigned i = 0; i < 90; ++i) {
        item.data[6] = i;
        assert(nm_ble_buffer_receive(&item, now + i + 1));
    }
    assert(nm_ble_buffer_complete_cycle(now + 100));
    check(run("", true), false, "resource limit");
    nm_ble_buffer_reset();
    puts("BLE commands: schema, raw, decoder, snapshots, averages, cancellation and report limits "
         "passed");
}
