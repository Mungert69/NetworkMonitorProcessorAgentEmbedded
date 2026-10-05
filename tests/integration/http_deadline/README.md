# Standalone HTTP deadline integration tests

This is a separate, unsigned test application. It runs the production
`firmware/main/http_deadline.c` with ESP-IDF 6.1's real HTTP parser, TCP and TLS
transports in esp-emu. It never loads processor credentials or contacts a broker.
It also runs the production eight-worker probe pool and DNS/ICMP/HTTP endpoints
with PSRAM-backed stacks and application context. The test uses 8 MiB PSRAM and
the test's 32-socket ceiling; production currently reserves 64 sockets.
Regenerate the ignored `sdkconfig` when changing defaults; ESP-IDF preserves
previously generated values.
The test component keeps C assertions enabled in IDF Release builds.

Build from the repository root:

```sh
bash tests/integration/build-http-deadline.sh
```

The build generates a temporary test certificate/private key in the ignored
`build-http-deadline` directory. Only this test application trusts that
certificate. Production firmware continues to use the normal certificate bundle.
The test clock is set to build time to validate the test certificates.

Run with exclusive use of the emulator TAP (stop any other emulator using it).
Set up the TAP with `sudo tools/setup-tap.sh` if necessary. On a host with an
input firewall, allow only the test guest to the five test ports temporarily:

```sh
sudo iptables -I INPUT 1 -i nm-esp-tap -s 192.168.4.2 -d 192.168.4.1 \
  -p tcp -m multiport --dports 18080,18443,18444,18445,18446 -j ACCEPT
python3 tests/integration/test_http_deadline.py
sudo iptables -D INPUT -i nm-esp-tap -s 192.168.4.2 -d 192.168.4.1 \
  -p tcp -m multiport --dports 18080,18443,18444,18445,18446 -j ACCEPT
```

Remove the temporary rule even if a test fails. The Python runner closes its
servers and emulator, and keeps serial output in
`build-http-deadline/integration.log`.

Also repeat with network latency, not only localhost-speed connections. With
exclusive use of the test TAP and its normal default qdisc (no custom traffic
rules to preserve), add a 20 ms delay before running the Python test and remove
it afterwards, including on failure:

```sh
sudo tc qdisc replace dev nm-esp-tap root netem delay 20ms
python3 tests/integration/test_http_deadline.py
sudo tc qdisc del dev nm-esp-tap root
```

The deadline transport passes the remaining connection budget to the initial
connect rather than repeatedly using short connect timeouts. This design avoids
an async-connect `select()` edge case observed in the earlier ESP-IDF 5.5.5
implementation; the current IDF 6.1 behavior is covered by this real-stack test.
TLS handshake retries still check the same overall deadline. A native
regression case also models a 25 ms connect.

Cases cover successful HTTP/HTTPS, response stalls, slow headers, fixed-length
and chunked body drips, redirects sharing one deadline, stalled TLS handshakes,
hostname verification, untrusted certificate rejection, SNI preservation,
HTTP-to-HTTPS upgrades, HTTPS downgrade rejection and stalled TCP connections.
The stall address 192.168.4.99 must be unused on this isolated test TAP. Timeout
cases use 1,200 ms and assert bounded completion (with emulator scheduling
tolerance). Repeated runs check heap integrity and bounded retained allocation.
This is not a physical-board performance benchmark or an exhaustive leak proof.

The fixture resolver maps test hostnames to a numeric local address. Bounded
production DNS worker lifetime/late completion is covered by
`native-endpoint_execution`; deadline budget consumption, isolated request
ownership and connect/DNS failure paths are covered by `native-http_deadline`.
Both run with the normal ASan/UBSan host suite.

After the deadline and expiry cases, `probe_memory.c` tests the actual production pool:

- Assertions verify probe stacks, owned inputs and DNS-helper stacks are in PSRAM.
- Four deliberately blocked DNS helpers outlive 150 ms callers. The callers
  finish and the internal main task commits NVS while those helpers remain live.
  Another DNS request gets an inconclusive admission result. Releasing the
  helpers lets the permanent reaper reclaim their stacks and operation slots.
- Three 50-probe mixed HTTP/HTTPS/DNS/ICMP cycles run with eight workers, including
  an unreachable ICMP target. Synthetic raw NVS writes deliberately overlap
  active probes and late helpers, a stronger overlap than normal once-per-cycle
  monitoring saves. The separate PSRAM/model/NVS test exercises the production
  compressed snapshot path.
- Heap integrity, pool destruction and stack high-water checks run on ESP-IDF.

Test-only linker wrappers map `deadline.test` to the local server and hold
`late.test` DNS completion; production task/lifetime and endpoint code is not
replaced. TLS still verifies the test certificate. This does not test MQTT,
backend acknowledgements, OTA installation or physical flash/cache behaviour.
The runner stops on an assertion/panic and requires both PASS markers; it does
not count a reboot or emulator timeout as success.
Allow up to ten minutes on a slow host. The host-side TLS safety timeout is
120 seconds of wall time; firmware request deadlines remain unchanged in guest
monotonic time. This avoids the host closing a connection while emulated TLS
computation is still within the device's timeout.

The current combined run passed on shivbot: all 44 deadline cases, late-DNS
admission and cleanup, and three 50-probe cycles with eight workers. The cycles
performed 570/570/573 overlapping synthetic NVS commits and retained at least
108,720 bytes of internal heap, with heap integrity and pool teardown passing.
See `docs/monitoring-parity.md` for historical measurements and remaining limits.

Do not flash this test image onto an enrolled device or publish it as an OTA
artifact. It contains a test-only trust anchor and no processor application.

Verified on shivbot with esp-emu 0.44.0: 44 HTTP/HTTPS cases passed; the
1,200 ms timeout cases completed at 1,200–1,201 ms of guest monotonic time.
The repeated workload retained 1,388 bytes relative to the post-warmup heap
baseline (within the 4 KiB tolerance); heap-integrity checks passed. Native
deadline and endpoint lifetime tests also passed under ASan/UBSan.

The 44-case suite also passed with 20 ms TAP egress delay after the delayed-connect
fix: deadline cases completed at 1,200–1,202 ms and the retained heap difference
was 1,056 bytes. Temporary delay and firewall rules were removed afterwards.

The HTTPS advance-expiry cases use a trusted 30-day certificate and a trusted
leaf expiring in two days (port 18446). The latter succeeds with the ordinary
transport policy, fails with HTTPS's seven-day policy, and returns
`HttpRequestException` through the production endpoint. With that policy enabled,
wrong-hostname and untrusted certificates still fail. Native tests check the
exact midnight boundary and calendar rollover. The suite requires the additional
`HTTPS_EXPIRY_POLICY_PASS` marker. Certificate keys remain in the ignored test
build directory. This workload does not execute Nmap or quantum endpoints;
test-only linker wrappers assert if dispatch unexpectedly reaches them.
