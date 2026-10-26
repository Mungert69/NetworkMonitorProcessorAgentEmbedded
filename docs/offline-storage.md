# Offline monitoring and pending-reading storage

This is an ESP32-specific extension, not a claim that .NET uses the same storage
or disconnected runtime behaviour. Existing backend messages, numeric types,
monitoring counters, scheduling and application acknowledgement matching remain
the contracts described in [monitoring parity](monitoring-parity.md).

## What stays in memory

`MonitorIPs` configuration, active `MonitorPingInfos`, status, scheduler state and
sequence counters remain the processor task's working model. `PingInfos` are a
separate collection, as in .NET's `MonitorPingCollection`; they are not a growing
child list inside every active parent record.

Pending `PingInfos` use immutable logical blocks of at most 64 readings (normally
about 10–12 KiB encoded JSON, with a 32 KiB byte ceiling). RAM contains a
bounded delivery window and new results from the current cycle. There are at
most eight window pages (512 readings) plus one cycle's results (at most 150).
`max_pending_ping_infos` now sizes the delivery window rather than limiting the
entire backlog: divide by 64, round down, and clamp to 1–8 pages. The existing
configuration validation range is unchanged. The template value 500 selects
seven pages; sparse pages may contain fewer than 64 readings.

The batcher sends only readings in the retained delivery window. Newly produced
readings are stored at cycle completion and become eligible for publication on
the next cycle. This adds one poll interval to individual-reading delivery;
current parent statistics and status alerts are still published in the current
cycle. The ordering keeps every published pending reading resident until its
backend acknowledgement, including acknowledgements arriving after a save.

Backend `removePingInfos` acknowledgements immediately remove matching readings
from that window in RAM, with the resulting masks committed at cycle completion.
MQTT acceptance/PUBACK does not acknowledge them. Parent records for removed
monitors remain available while stored readings/reconciliation need them. A
removed-monitor acknowledgement retires its parent and residual readings, with
bounded persisted cutoffs preventing a re-added monitor ID from reviving old data.

## Backing storage and boot

At processor startup, mount the SD card without formatting it. Successful mount
selects SD; otherwise select NVS. The selection is fixed until reboot. Runtime
card removal or write failure pauses new probes; it does not silently change
stores or erase the backlog.

The default SPI2 wiring matches the RobinNet recorder's documented plain board:

| Signal | GPIO |
|---|---:|
| CS | 10 |
| SCK | 12 |
| MOSI | 11 |
| MISO | 13 |

Optional root configuration integers `SdCsGpio`, `SdSckGpio`, `SdMosiGpio` and
`SdMisoGpio` override these defaults. Pins must be distinct and valid for the
actual board. Use the recorder's documented 3.3 V supply and shared ground.
The card must already have a filesystem accepted by the configured FAT driver.
Mount failure never authorizes formatting.

SD files live under `/sdcard/networkmonitor/<SHA256-of-AppID>/`, with an epoch
directory and groups of 1,024 segment files. Each append-only `.seg` file packs
up to 32 logical blocks, normally a few hundred KiB, with an upper bound just
over 1 MiB including framing. NVS stores logical blocks directly as blobs and
manages their physical 4 KiB flash pages; block sizes need not equal flash pages.
Blocks in a live segment are read by bounded header scans, not whole-file loads.
Only an uncommitted suffix may be truncated for retry. Acknowledged blocks free
a segment once it has no live readings; partial segments can temporarily retain
acknowledged bytes. The independent `monitor_batch.*` module combines readings
into wire-sized publications regardless of segment/block boundaries. Existing
recordings and files elsewhere on the card are untouched. The NVS fallback uses
a separate `nmpings` namespace
in the existing 2 MiB `nmdata` partition, with 64 logical ring slots plus one correction scratch slot (up to 4,096 readings
when every page is full). Free-space checks can stop it sooner. No partition or
release version changes are needed.

The existing monitoring root snapshot stays in NVS so configuration is available
even if the card changes. It includes parent records, scheduler/counters and a
private version-1 `PingBacklog` cursor with bounded acknowledgement masks and
removed-monitor cutoffs. Cutoffs prevent re-adding a monitor ID from resurrecting
its old readings outside the RAM window. Its
`ProcessorData.PingInfos` array is empty: SD-backed readings are not duplicated
in NVS. Credentials and OTA state retain their existing storage.

On first upgrade to paged storage, or when boot selects a different backing store,
discard the previous pending readings. This is the explicitly accepted transition
policy: **there is no backlog migration**. Preserve `MonitorIPs`, parents,
statistics, scheduler history and the advancing sequence. The first successful
root commit records the new selection/epoch, preventing stale readings from
reappearing after a reboot. Unreferenced page files/keys are reclaimed in bounded
passes after successful commits. A card that mounts successfully but has missing
or corrupt pages for the committed epoch fails closed; it is not treated as an
empty card.

The root snapshot commit also checkpoints the local UTC clock in NVS
(`ClockUtc` in the root snapshot). Offline boot restores this approximate value; the network/time
task independently retries Wi-Fi and NTP. Collection continues before first NTP
synchronization, but sending waits for Wi-Fi and an NTP reply during this boot.
Previously stored readings and parents survive reboot. Before sending, the first
successful NTP reply triggers the timestamp correction described below.
See [startup and retries](guide.md#boot-router-recovery-and-rgb-indicator).

## Cycle commit and recovery

1. Load a bounded working window; check storage headroom before accepting probes.
2. Run scheduled probes even when MQTT is disconnected. Workers still perform
   endpoint I/O only; the processor owns all model and storage mutations.
3. Attempt publication when connected, servicing commands at the existing safe
   checkpoints. Offline cycles skip publication.
4. After all accepted jobs drain, append new immutable blocks and commit one NVS
   root snapshot with the updated queue cursor and acknowledgement masks.
5. Only after that root commit succeeds, release newly stored readings from RAM
   and reclaim pages no longer referenced by the durable root.

Failed page writes or root saves retain RAM data and the previous durable root.
Pause further probes and retry persistence on the next cycle. Acknowledgements
are not written individually. Power loss can lose results since the last cycle
commit or replay acknowledgements not yet committed, as with the previous cycle
snapshot policy. Checksums, strict lengths, epoch/page identity and bounded JSON
decoding detect corrupt or misrouted pages; they are not a substitute for testing
SD/FAT power-loss behaviour on hardware.

Dataset reset discards the queue logically, then commits the new cursor at cycle
completion before old slots can be reused. Re-registration/factory reset retains
its existing explicit data-discard behaviour. Old firmware does not understand
the paged queue; do not expect it to deliver an existing paged backlog.

Backend unavailability does not bypass OTA health checks or clock requirements.
Initial provisioning/enrollment still needs Wi-Fi and NTP. Enrolled devices can
collect using a restored/provisional clock before connectivity returns. This is
not a battery-backed RTC.

## Timestamp correction

`ClockState` is optional, private, version-1 root metadata containing an inclusive
known-valid `DateSentInt` range, the active signed integer offset, target range
and remaining-original-block count. Old snapshots without it treat pending
readings as provisional, with a startup warning. The first NTP reply supplies a
stable offset against the boot's monotonic recording clock. In-flight cycles
finish on that provisional timeline; MQTT remains stopped. Between cycles, the
processor flushes unsaved results, corrects parent timestamps on a COW candidate,
and commits the correction marker. Fast cyan indicates the pause.

Correction rotates one original block to the tail at a time, filtering existing
acknowledgement masks/removed-host cutoffs and preserving IDs and extension fields.
Only pings outside the ORIGINAL known-valid range receive the offset. Updated
integer/string timestamps, checksums, target range and progress become durable
before the old block is reclaimed. This startup-only rewrite is an explicit
exception to one normal snapshot commit per cycle. It needs one spare block,
not a duplicate backlog. SD can temporarily retain an extra segment (up to 32
blocks) before old segment reclamation; its 8 MiB reserve covers that overhead.
NVS preserves its 64-block logical limit and uses a 65th
physical key for scratch; persisted split/first-slot fields keep legacy modulo-64
blocks readable while entering the new layout. SD retains append-only segments.

A failed read, allocation, write or root commit blocks sending and new probes;
retry never advances the cursor or applies an offset twice. Cleanup failure after
a commit only wastes space. After reboot mid-correction, collection stays paused
until a fresh NTP reply, then resumes the saved pass using its ORIGINAL offset.
No new samples can mix into that recovery pass. The final root contains the
corrected UTC checkpoint and expanded valid range before the send gate opens.
A reboot after final commit but before opening the gate is safe: the next boot
recognizes corrected pings as valid. After normal cycles the valid range extends
to the synchronized checkpoint. Boot uses at least that upper bound, also when
small backwards clock corrections occurred. Equality at the one-second boundary
is deliberately accepted without subsecond tracking.

Parent dates are shifted directly as agreed; existing parent dates/status/breach
times may already have been accurate. Multiple power losses before ANY successful
NTP reply still lose the distribution of powered-off time: the eventual common
offset is an accepted approximation for those older provisional samples. Range
membership does not reconstruct missing elapsed wall time. Normal NTP stops after
first synchronization each boot; long-running clock drift is accepted. OTA's
explicit fresh-NTP security check remains separate and never triggers another
history rewrite. Older firmware does not understand the NVS correction layout;
do not expect it to read a corrected NVS backlog after rollback.

## Capacity and logs

Before dispatch, reserve enough for the configured maximum cycle, conservatively
allowing 64 KiB per new SD page or 32 KiB in NVS capacity units. Keep an additional
8 MiB SD reserve or 256 KiB NVS reserve. NVS capacity units use 16 payload bytes
per available 32-byte entry, allowing for entry metadata and garbage collection;
they are not filesystem free bytes. NVS ring slots are an independent bound.
After a capacity pause, require another page of headroom before resuming.

Each cycle logs `backlog store=sd|nvs`, `pending`, `free_bytes`, `reserve_bytes`,
`paused`, and `estimated_seconds_until_full`. The first estimate is `unknown`.
Later estimates use recent committed encoded block bytes and framing, and the
smaller of available NVS space and remaining ring slots at the recent mean block size.
Filesystem rounding and workload changes make this an estimate; the dispatch
headroom check remains deliberately more conservative.
They estimate continued accumulation without backend acknowledgements, not a
guaranteed retention duration. Actual read/write/commit errors always take
precedence over a free-space estimate. A paused processor continues publication,
acknowledgement handling, persistence retry and page reclamation.

The root's existing 1 MiB decoded/512 KiB compressed limits, monitor count,
command bounds, endpoint concurrency and 128 KiB publication limits remain.
Increasing SD capacity does not increase those independent bounds. Snapshot and
MQTT compression remain Brotli quality zero; stored blocks use the existing yyjson
record codec without another application JSON library.

## Validation

`native-ping_backlog` exercises production paging with a 6,000-reading backlog,
bounded RAM, reboot, partial acknowledgements, storage failure/retry, capacity,
store switching, exact uint64/unknown fields, corrupt pages and allocation
failures. `native-ping_storage` exercises production SD/NVS adapters with filesystem
and NVS boundaries, including sync/truncate/commit failures, shared-segment prefix
protection, torn uncommitted suffix recovery and recycled-key cleanup.
`native-sd_backlog` combines the production queue and SD adapter: 3,500 readings
across 70 commits occupy three segment files, then survive reboot and drain;
injected root-commit and mid-segment sync failures preserve the committed prefix.
`native-state_adapter` covers disconnected cycles, saved configuration, reconnection
delivery and acknowledgements through the real state and publication functions.
`native-monitor_time` covers signed offsets, inclusive range boundaries, uint32
under/overflow, UTC calendar/leap/fraction handling, parent/status/breach dates,
null/absent fields, COW isolation and strict metadata. Correction tests cover a
full 64-block NVS queue and 100 SD blocks, root failure before every rotation,
reboot after every committed step, per-allocation failures, physical NVS legacy
layout conversion/wrap, SD fsync/root failures and first-sync send gating.
These host tests do not establish physical SD behaviour, flash timing or live
backend delivery; record those results separately when actually exercised.

Physical ESP32-S3 validation (2026-10-26): the signed application was flashed
into the existing active slot with configuration/enrollment retained. The card
mounted with the default recorder wiring and reported approximately 8.0 GB free.
With only this board's broker temporarily made unreachable, committed pending
readings increased from 7 to 14, 21 and 28; after an offline reboot they increased
to 35 and 42. Logs showed successful cycles, no capacity pause and a calculated
retention estimate. The exact original configuration was restored and MQTT
reconnected. The backend then acknowledged all 42 queued offline readings,
reducing pending from 49 to 7 (the newest cycle). This is an application
flash/reboot test, not an OTA rollback test
or a power-interruption-during-SD-write test. Synthetic emulator serial and
factory-reset integration tests also passed with the matching firmware/ELF.

Timestamp-correction hardware validation (2026-10-26): the signed 2,363,392-byte
application was written to the board's confirmed active OTA slot, with enrollment,
configuration and existing SD backlog retained. Flash verification succeeded.
The first NTP reply reported a zero-second offset on this boot; the processor
committed the correction before starting MQTT. A monitoring cycle completed with
SD storage active and no capacity pause. A backend `removePingInfos`
acknowledgement reduced pending readings from 21 to 7. Some monitored endpoints
reported failures; the cycle itself and delivery succeeded.

The matching sanitizer-enabled host suite passed all 43 tests with the pinned
quality-zero Brotli encoder. Tooling ran 53 tests (one skipped); both serial
emulator reset/setup checks passed. The firmware built without compiler warnings,
its application signature verified, and 62% of the 6 MiB OTA slot remained free.
The .NET fixture generator was not rerun because the reference sources were
unchanged, as requested. Nonzero-offset correction, interrupted rewrites and
failure recovery are covered by host tests; they were not fault-injected on the
physical board in this validation. This direct USB app update does not validate
HTTPS OTA or rollback.
