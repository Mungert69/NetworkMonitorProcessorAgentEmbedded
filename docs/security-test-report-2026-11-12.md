# Processor agent security test report

Date: 2026-11-12

## Purpose and threat model

This review tests whether attacker-controlled network or BLE input can exploit
typical C memory-safety errors in the ESP32-S3 processor agent, gain runtime
control, and then use the processor as an attack point inside its network.

The review assumes the deployed processor uses its normal authenticated and
TLS-protected configuration. Public firmware images, the absence of secure boot,
and physical device lockdown are accepted deployment constraints and are outside
this report's findings. Signed OTA remains relevant to update authenticity, but
does not by itself contain an attacker who has already achieved arbitrary runtime
code execution.

## Executive summary

No reproducible memory corruption, undefined behaviour, crash, or working exploit
was found in the exercised camera, RTSP, JPEG/RTP, BLE, or existing native-test
paths. The fuzz campaigns processed approximately 19.5 million inputs or sessions
under AddressSanitizer and UndefinedBehaviorSanitizer.

The review did identify unbounded ownership growth in the passive BLE history as
an avoidable denial-of-service risk. The implementation now rejects capture before
allocation when accepting it could exceed a 1 MiB BLE-owned memory budget. It also
reserves enough budget for the next immutable snapshot so that reaching the limit
does not prevent publication, eviction, and recovery. Production compilation now
uses strong stack-protector instrumentation. Heap poisoning remains disabled in
production because its diagnostic value does not justify its runtime and memory
cost there.

These results reduce confidence in the tested attack paths as practical takeover
routes, but they do not prove the firmware is free of exploitable defects. Hardware,
radio-driver, ESP-IDF, TLS-library, and authenticated command-envelope testing
remain important boundaries or follow-up work.

## Deployment and configuration review

The initial review followed the actual production configuration and deployment
assumptions rather than evaluating optional insecure configurations. It confirmed:

- application MQTT traffic is protected by TLS certificate and hostname checks;
- command processing retains signature and AuthKey gates;
- registration uses OAuth-authenticated MQTT and a verified AuthKey response;
- OTA installation uses signed images;
- ESP-IDF memory protection, privilege/lock settings, and FreeRTOS stack-overflow
  checking were already enabled in the production configuration;
- heap poisoning was not enabled; and
- the listener's broad address exposure is intentional, so address filtering was
  not proposed as a mitigation.

No unsigned command fallback, insecure production test mode, or obvious bypass of
the reviewed authentication gates was found during this level of review.

## BLE buffer capacity and recovery tests

The BLE buffer was reviewed because a nearby attacker can generate a large number
of advertisements without first passing the application command-authentication
boundary. Before hardening, retained packet histories and immutable snapshots had
no configured aggregate capacity limit.

The implemented policy is a fixed 1 MiB limit for memory owned by BLE history and
snapshots. Admission computes the complete incremental allocation before allocating
the address history, packet, or payload. It also accounts for the snapshot needed
to publish the accepted history. When the admission check fails, existing history
is preserved, the capture is marked incomplete, and the packet is rejected.

Native tests cover:

- maximum-size, distinct BLE payloads until the budget is reached;
- rapidly rotating source addresses until the budget is reached;
- rejection before exceeding the byte limit;
- publication of the retained data with the incomplete-capture indication;
- eviction and reclamation over subsequent cycles;
- recovery and acceptance of new data after memory drains;
- payload sharing, snapshot lifetime, allocation failures, and concurrent access
  already covered by the surrounding BLE buffer tests.

The tests show that a stalled snapshot consumer can keep referenced memory alive,
but cannot cause new BLE captures to grow ownership beyond the limit. Once readers
release snapshots and normal cycles evict expired history, the buffer reclaims
memory and resumes admission.

## Sanitizer-enabled native test suite

The complete host suite was configured with:

```sh
cmake -S . -B build-tests -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer'
cmake --build build-tests
ASAN_OPTIONS=detect_leaks=0 ctest --test-dir build-tests --output-on-failure
```

Result: 44 of 44 tests passed with AddressSanitizer and
UndefinedBehaviorSanitizer enabled.

LeakSanitizer was disabled because leak detection is not usable under the
container/ptrace environment used for this run. Address and undefined-behaviour
detection remained enabled. This means the result does not make a fresh claim
about memory leaks.

## Camera XML fuzzing

The production camera XML parsing path was exercised with malformed, truncated,
nested, and mutated XML inputs under AddressSanitizer and
UndefinedBehaviorSanitizer.

Result: approximately 5.5 million inputs completed without a target sanitizer
failure or reproducible crash.

## RTP/JPEG fuzzing

The production RTP/JPEG handling path was exercised across packet framing,
truncation, lengths, marker boundaries, JPEG assembly, and mutated byte content.

Result: exactly 11,489,984 cases completed without a target sanitizer failure or
reproducible crash.

## BLE parser and decoder fuzzing

Production BLE payload parsing and decoder paths were exercised with malformed,
truncated, boundary-length, and mutated advertisements.

Result: exactly 125,560 cases completed without a target sanitizer failure or
reproducible crash.

## RTSP session fuzzing

A temporary host harness included the production `camera_rtsp.c` implementation
and production command-argument parsing. Deterministic transport adapters replaced
real socket waits, allowing the parser and session state machine to receive
mutated responses at high volume. The exercised boundaries included:

- RTSP URL parsing;
- headers and parameter parsing;
- framed responses and content lengths;
- authentication challenge and authenticated request construction;
- DESCRIBE and SDP processing;
- SETUP, PLAY, and session-header transitions; and
- interleaved RTP packet framing.

The JPEG decoder was stubbed in this campaign because its production path had
already received the separate 11,489,984-case fuzz run above.

Results:

- broad session campaign: 1,568,104 mutated sessions;
- focused campaign after correcting the seed SDP length to reach deeper SETUP and
  PLAY states: 797,598 mutated sessions;
- combined: 2,365,702 sessions, with no target sanitizer failure, undefined
  behaviour report, reproducible crash, or demonstrated exploit.

## Firmware build and hardening verification

The production configuration now selects strong compiler stack protection. The
generated compile commands were checked for `-fstack-protector-strong`.

The complete firmware built, linked, and signed successfully as version 0.5.3.
The signed image was 2,490,368 bytes (`0x261000`), leaving approximately 60% of
the 6 MiB application slot free. No firmware was flashed or deployed as part of
this work.

`git diff --check` also passed after the implementation and test changes.

## Findings and disposition

### BLE history could grow without an aggregate byte limit

Impact: a nearby transmitter could attempt to exhaust PSRAM through sustained,
distinct BLE observations, causing availability loss rather than a demonstrated
code-execution primitive.

Disposition: fixed by pre-allocation accounting, a 1 MiB BLE-owned memory limit,
snapshot reservation, explicit incomplete-capture reporting, and recovery tests.

### Production lacked compiler stack-protector instrumentation

Impact: a stack overwrite in protected functions would have had fewer opportunities
to be detected before corrupting control data. This was defence-in-depth; testing
did not demonstrate such an overwrite.

Disposition: production now uses strong stack protection. Existing ESP-IDF memory
and FreeRTOS stack-overflow protections remain enabled.

### No code-execution exploit demonstrated in exercised parsers

The tested camera, RTSP, RTP/JPEG, and BLE paths did not produce a usable crash or
memory-safety violation. This is a test result, not a guarantee that all inputs,
build optimizations, concurrency schedules, or dependency internals are safe.

## Limitations

- Fuzz harnesses and corpora were temporary files under `/tmp`; they were not added
  to the repository. The commands, case counts, and results are recorded here, but
  the exact campaigns are not currently reproducible from a clean checkout.
- Host sanitizers do not instrument ESP-IDF, radio firmware, ROM, or all third-party
  library internals, and do not reproduce ESP32-S3 memory layout or timing.
- No physical-board fault injection, RF stress, long-duration soak, Wi-Fi driver
  fuzzing, or hardware stack-canary trip was performed.
- No firmware was installed, and OTA rollback or on-device recovery was not tested.
- The campaigns were mutation-based and bounded; they do not exhaust the input
  space or prove exploit absence.
- Heap poisoning was intentionally not enabled in the production image. It can
  still be useful in a dedicated diagnostic build when investigating a suspected
  heap corruption.

## Recommended next tests

The next highest-value application-controlled boundary is the authenticated MQTT
command envelope and JSON routing path. Testing should retain real signature and
AuthKey policy while exercising duplicate fields, deep nesting, malformed signed
objects, numeric limits, length arithmetic, and queue-transfer ownership. Useful
subsequent work includes allocation-failure injection through command execution,
long-duration concurrent BLE/camera/MQTT stress, and an on-device diagnostic build
that confirms stack-protector failure handling without weakening the production
security policy.
