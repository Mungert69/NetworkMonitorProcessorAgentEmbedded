# Embedded command processor implementation notes

## Authoritative names

Use the sibling `NetworkMonitorLib/Objects/Connection/CommandProcessors` sources
and `NetworkMonitorProcessorAgent/Services/RabbitListener.cs` as the reference.

| .NET class | Registered processor type |
|---|---|
| `QuantumCertCmdProcessor` | `QuantumCert` |
| `QuantumConnectCmdProcessor` | `QuantumConnect` |
| `QuantumInfoCmdProcessor` | `QuantumInfo` |
| `QuantumPortScannerCmdProcessor` | `QuantumPortScanner` |
| `OpensslCmdProcessor` | `Openssl` |
| `NmapCmdProcessor` | `Nmap` |

There is no generic `QuantumCmdProcessor`. The first embedded command module is
`quantum_cert_cmd_processor.c/.h`. Its .NET-equivalent
`CmdName` is `quantum-cert`, distinct from registered `Type=QuantumCert` and
the monitoring endpoint name `quantumcert`. Do not substitute the command name
for the registered type in `ProcessorScanDataObj`.

The existing operations are `processorCommand`, `cancelCommand`,
`getCmdProcessorHelp` and `getCmdProcessorList`. Keep these names and the existing
signed command/AuthKey gates. Execution must run outside the MQTT callback and
monitoring state must remain processor-task-owned.

## Current progress

### Six implemented command processors

`QuantumConnect` now has a separate typed parser/worker policy in
`quantum_connect_cmd_processor.*`. `openssl_runner.*` is the process-like TLS
adapter: it maps standardized OpenSSL group names to the compiled wolfSSL
groups, without exposing wolfSSL handles. Unsupported/draft algorithm names
fail explicitly rather than silently negotiating a default group. Both quantum
command modules use this boundary. `cmd_arguments.*` owns shared bounded CLI
tokenization/numeric parsing, independently of command policy.

The device tests an explicit list of at most 16 algorithms sequentially, within
one command budget. Omitted algorithms offer the six compiled standardized PQ
groups in one handshake, not .NET's larger OpenSSL/OQS catalog. Results use the
.NET success-filtering and no-supported-algorithm report structure.

`cmd_processor_catalog.*` dispatches typed requests to six independent command
policies. It has no MQTT, JSON or provider-library dependencies. `cmd_output.*`
owns bounded PSRAM diagnostic text; overflow returns a short failed result,
never a permanently unpublishable result. Ordinary TLS reports remain capped at
8192 bytes; OpenSSL reports requesting PEM chains and Nmap reports allow 32768
bytes. The shared formatter also enforces a 256-line limit.

`QuantumPortScanner` accepts up to 20 explicit TCP ports. Without a port list,
it uses the project-owned TCP runner's structured open-port result, not parsed
human-readable stdout. Discovery and subsequent quantum handshakes share the
request deadline. It accepts only the documented discovery options, not arbitrary
Nmap arguments. `Nmap` accepts TCP connect scans, common ports or up to 64
explicit ports/ranges, `-sT`, `-Pn`, `-PR`, `-F`, `--open`, `--reason`, `-v`/`-vv`, `--system-dns`, `-sV`,
and `-sn` host discovery. `-sn` supports one hostname/IP or bounded IPv4 CIDR
from `/24` through `/32` (maximum 254 usable targets), sequentially with a
shared command deadline and 200 ms per-target ceiling. Local IPv4 uses fresh
ARP replies; off-link targets use ICMP. `-PR` restricts discovery to local IPv4.
`-F` selects a smaller
project-owned eight-port set when no explicit ports are given; explicit `-p`
takes precedence. `-Pn` skips discovery and assumes the target is up; without
it, reachability uses local ARP and TCP results (the complete Nmap ping-probe
set is not implemented). `--open` suppresses closed/filtered rows. `-sV` reports
built-in IANA TCP service-name hints, **not active version detection**. The
5,889-entry data file is embedded read-only and can be refreshed with
`python3 tools/update-service-hints.py`. No NSE, UDP, raw
SYN, OS fingerprinting, IPv6 CIDR or Nmap source/data is included.

`Openssl` provides TLS 1.3 and explicit TLS 1.2 AES-GCM `s_client` diagnostics,
group/cipher selection, SNI/ALPN, verification identities and presented PEM-chain
export, plus `version`, group/cipher listing and help. Typed requests pass through
`openssl_runner` to wolfSSL; unsupported options/subcommands fail explicitly.
See the [full compatibility report](openssl-adapter.md) for supported switches,
API mappings, limits, deliberate differences and reproducible tests.

`QuantumInfo` embeds the 75 records from the .NET algorithm metadata catalog
and supports exact/partial searches and common Kyber/Dilithium aliases. The
catalog is information, not a promise that every listed algorithm is compiled.
A tooling test compares the embedded records with the .NET source catalog.

Validation commands are in the integration README. Native sanitizer tests and
real host TLS interoperability tests complement, rather than replace, physical
board command/MQTT tests and manual frontend tests.

2026-10-02 validation: 27 sanitizer-enabled CTest groups passed; 54 real
wolfSSL/OpenSSL host interoperability cases passed. The spare dev board
`14:c1:9f:42:99:90` passed 23 signed MQTT command checks across all six types,
including default discovery, trusted classical TLS, port ranges, invalid
arguments, cancellation and rejected signature tampering. Ordinary monitoring
and Data's application acknowledgements continued during these checks. The
signed normal 0.3.0 application was flashed without replacing the bootloader
or monitoring partition. These checks do not exercise a real frontend LLM
session; the user performs that next, after normal capability re-registration.

`processor_cmd.c` owns bounded command admission, a single independent
16 KiB PSRAM worker, cooperative cancellation and reply publication. Its worker
receives only a typed private request and writes only its result. The processor
task alone owns the cloned `ProcessorScanDataObj` response and publishes it.
Other commands are rejected as busy while a job/result is outstanding; this is
the embedded capacity adaptation, not .NET's unbounded pending command queue.
Immediate duplicate requests are acknowledged without rerunning an active or
most-recently-completed command. This is a bounded QoS duplicate guard, not a
durable replay cache.

`quantum_cert_cmd_processor.c` parses the .NET argument keys/defaults and calls
`tls_inspection.*` in certificate-observation mode. `quantum_tls.c` is the
wolfSSL backend; no shell, process, new library or arbitrary binary execution is
introduced. Cancellation is polled during DNS admission/waits and TCP/TLS socket
waits. Crypto calls are not forcibly preempted. A cancelled DNS caller releases
only its reference; the bounded helper retains its slot until actual completion.

`cmd_processor_message.c` preserves correlation/unknown fields, applies .NET
CR/LF empty-line removal, pagination and escaped-string output semantics.
`LineLimit=-1` uses `CmdReturnDataLineLimit` (default 100), `-2` returns all output;
zero/other negative limits are rejected rather than dividing by zero. The
certificate command honors the lesser of its argument timeout and the request's
`TimeoutSeconds` (default 600). Invalid ranges, malformed quotes, >253-byte
hostnames and >4096-byte arguments are rejected. Diagnostics are bounded.
Unlike .NET's odd negative Page calculation with `LineLimit=-2`, embedded Page
is normalized to 1 for unpaginated output.

Existing signed `processorCommand`, `cancelCommand`, `getCmdProcessorHelp` and
`getCmdProcessorList` routes require AuthKey and the configured signature scheme.
Results and acknowledgements use existing fixed MQTT scan routes, never an
arbitrary topic supplied through CallingService. Publication failures retain
one completed result for retry; retry does not reexecute the command or grow
the JSON arena. `SendMessage=false` suppresses the completed execution result,
not its acknowledgement (matching .NET). No command writes NVS/model data.

All six types are absent from compiled/template DisabledCommands. Existing
enrolled configurations with explicit restrictions remain restricted: update
that configuration intentionally, then re-register
to refresh backend capability reporting. Firmware does not silently remove
user-configured restrictions. Both outbound scan routes require new OAuth
publication scopes; see [backend integration](backend-integration.md).

The .NET help advertises a positional target, but its required-argument schema
check occurs before that fallback and rejects positional-only input. The port
follows the actual parser behavior: use `--target`, not just the hostname.

Run `python3 tests/tooling/test_cmd_processor_contract.py` with both sibling
.NET checkouts to compare names, argument keys and defaults (443 and 59000 ms).
These tests also run under the normal tooling/CTest target. Missing reference
checkouts produce explicit skips, not a claim of parity. They are drift checks,
not execution or hardware tests.

`native-quantum_cert_cmd` exercises the actual parser/message/runtime code with
a pthread-backed task boundary: ownership, ack/results, cancellation, busy and
duplicate requests, partial task startup, failed publication retry and nested
metadata/uint64 preservation. Real TLS tests remain under `tests/integration/quantum`.
Board tests are under `tests/integration/quantum_command`; their fixtures use the
original .NET model and production ML-DSA signer. See its README for scope.
