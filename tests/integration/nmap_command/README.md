# Live ESP32 Nmap argument harness

This harness sends real, .NET-signed `Nmap` commands through the local dev
RabbitMQ command exchange to the enrolled ESP32. It checks each response from
the device against one known open TCP service. The harness creates and removes
only its own expiring result queue; it does not write backend data or alter the
board. Use a dev board and a test host you are authorized to scan.
Wait for `ESP32_S3_MQTT_READY` in its serial log before starting the harness;
commands published before subscriptions are active can be lost.

The fixture config must be current for the enrolled board because it contains
its current AuthKey. Keep it, the generated signed messages, and logs outside
the repository. The private ML-DSA key signs the .NET-compatible command
envelope. The runner reads the dev RabbitMQ password from the local `data`
container without printing it.

Run from the repository root. Example, using the test listener on `192.168.1.238:45678`:

```sh
umask 077
nmap_test_dir=$(mktemp -d /tmp/nmap-live.XXXXXX)
dotnet run --project tests/integration/nmap_command/dotnet/NmapFixtures.csproj -- \
  /path/to/current-board-config.json "$nmap_test_dir/fixtures" \
  /path/to/authkey-signing-ml-dsa-65-private.pem \
  192.168.1.238 45678 [optional-dns-name]
python3 -m venv "$nmap_test_dir/venv"
"$nmap_test_dir/venv/bin/pip" install -r tests/integration/quantum_command/requirements.txt
"$nmap_test_dir/venv/bin/python" tests/integration/nmap_command/run_live.py \
  --config /path/to/current-board-config.json --fixtures "$nmap_test_dir/fixtures"
```

The test service must be listening throughout the run. The optional DNS name
must resolve to the same service host; without it the `--system-dns` scenario
is omitted. The runner expects ordinary probes and MQTT command subscriptions
to remain active and reports each command case as it finishes.

Cases exercise a default single-target scan, `-sT`, explicit TCP ports, comma
lists, ranges, `-Pn`, `--open`, `--reason`, `-v`, `-F`, `-sV`, and `--system-dns`. For an IPv4
test target, the harness also sends `-sn` against that target's `/24` and checks
the bounded-sweep summary, then confirms a `/23` is rejected before probing.
It also checks fresh local ARP/MAC discovery, off-link `-PR` rejection,
conflicting options, empty tokens, and cancellation of an in-flight sweep.
Service-name cases check the precise port rows for LDAP, submission over TLS,
secure MQTT, the first/last registry entries and the dynamic-port unknown fallback.
The known listener's expected label comes from the service file; TCP port 45678
is registered as `eba`, even though our fixture listener is not that protocol.
Passing an option case means its current command path completes; it does not
imply full Nmap semantics for every accepted flag:

- TCP connect is the only scan type. `-sT` names the existing default.
- `-Pn` skips discovery and assumes the target is up; the embedded default scan
  uses fresh ARP replies for local IPv4 and TCP outcomes otherwise. It does
  not run Nmap's full ping probe set. `-PR` requires local IPv4 ARP discovery.
- `--open` suppresses closed/filtered port rows; without it, scanned TCP states
  are reported.
- `--reason` reports the connect outcome (`connect`, `conn-refused`, etc.) as a
  bounded reason column. `-v`/`-vv` append a scan summary; they do not implement
  Nmap's live progress display.
- `--system-dns` is accepted; hostname resolution already uses the system
  resolver.
- `-F` chooses a smaller project-owned eight-port set when `-p` is absent;
  explicit ports take precedence.
- `-sV` prints a static port-name hint, not an active service/version probe.
- CIDR discovery is IPv4-only, limited to /24 through /32 (up to 254 usable
  hosts), sequential, and uses fresh ARP replies for local IPv4, ICMP off-link,
  a shared deadline and at most 200 ms per target. Cached MAC entries alone
  are not treated as replies. It is not an unrestricted subnet scanner.

The fixture generator uses the original `NetworkMonitorLib` message model and
signer. The MQTT runner preserves the signed JSON bytes; reserializing the
fixture would invalidate its ML-DSA signature.

### Scheduled-monitor contention

Keep an assigned Nmap monitor enabled against the test host. Capture a **fresh**
private serial log, then start the harness so the roughly 50-second `/24` sweep
overlaps a scheduled monitoring cycle (normally start around 20 seconds after
boot). Add `--serial-log /private/current-run.log --monitor-id YOUR_MONITOR_ID`.
The runner then also requires an actual positive-duration successful FIFO wait,
a successful scheduled Nmap probe and a backend application acknowledgement,
and rejects the previous ARP-unavailable/busy failure. If no overlap happened,
the assertion fails: retime the run rather than treating absence of contention
as proof. The host admission test separately exercises FIFO order, cancellation
of a middle waiter, admission expiry and removal/reuse using production code.
