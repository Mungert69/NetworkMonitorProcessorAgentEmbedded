# Dataset date fault report

Two independent defects cause host monitoring data to be returned incorrectly by the
host data API. One is in this repository (the ESP32 agent publishes a stale
`MonitorPingInfo.DateEnded`). The other is in the shared query model used by the
API service. Both affect date-range queries; either alone is enough to make a
correct request return the wrong rows.

Findings are ordered: the agent-side defect first, because it is the root cause
of the "no data returned" symptom and the one that requires a firmware change.

---

## Summary

| # | Component | Defect | Effect |
|---|---|---|---|
| 1 | This repository (ESP32 agent) | `MonitorPingInfo.DateEnded` is initialized with a new record but never refreshed by probes or publication | Recent date-range queries can return no rows; after a reset, dataset intervals can be inverted |
| 2 | `NetworkMonitorLib` (shared query model) | `MonitorPingInfoQuery.DateEnd` getter silently replaces a requested end bound with `start + 6h` | Every narrow-window query is widened by six hours at the tail, and the caller is told the widened bound was what it asked for |

Defect 1 additionally causes the API to disagree with the chart for the same host
and window: the chart shows readings that the API cannot return.

---

## Defect 1 — ESP32 agent never refreshes `DateEnded`

### Where

`firmware/main/monitor_model.c`:

```c
170:    TRY(MSTR(info, DateStarted, when) && MSTR(info, DateEnded, when) && MSTR(info, Status, "") && ...
```

```c
332:            TRY(MSTR(info, DateStarted, when));   /* dataset reset */
```

Before the fix, `DateEnded` was assigned in one place in the firmware:

- `fill()` (line 170) — writes `DateStarted` and `DateEnded` to the same value
  when creating a fresh record. An imported or swapped record can carry its
  existing `DateEnded` instead.

The dataset-reset path (line 332) updates `DateStarted` only.

No probe or publication path assigned it before the fix. The current search is:

```sh
rg -n 'DateEnded' firmware/main tests/reference tests/native
```

Before the fix, a fresh record's `DateEnded` stayed at creation time while
`DateStarted` advanced on dataset reset. Imported records retained their
supplied end date.

### Divergence from the reference implementation

The authoritative behaviour is the C#/.NET processor at
`~/code/NetworkMonitorProcessorAgent`, not this repository. It refreshes
`DateEnded` on every publish:

`~/code/NetworkMonitorProcessorAgent/Services/PublishRepo.cs:98`

```csharp
monitorPingInfos.ForEach(f =>
{
    f.DateEnded = DateTime.UtcNow;
    ...
```

and the dataset reset only advances the start of the interval:

`~/code/NetworkMonitorProcessorAgent/Services/MonitorPingCollection.cs:39`

```csharp
private void Zero(MonitorPingInfo monitorPingInfo)
{
    monitorPingInfo.DateStarted = DateTime.UtcNow;
```

The reference advances the interval's end at publication. Before the fix,
this repository kept the end date from record creation or import; after a
later reset, the interval could become inverted.

### How it reaches the API

The service ingests the published value verbatim:

`~/code/NetworkMonitorData/Data/ServiceDataBuilder.cs:102`

```csharp
monitorPingInfo.DateEnded = p.DateEnded;
```

The API's date-range filter then requires the dataset to overlap the requested
window:

`~/code/NetworkMonitorService/Services/MonitorService.cs:812-826`

```csharp
if (sentData.DateStart != null && sentData.DateEnd != null)
{
    query = query.Where(m => m.DateStarted <= sentData.DateEnd && m.DateEnded >= sentData.DateStart);
}
```

When `DateEnded` predates the requested window, `m.DateEnded >= DateStart`
is false for that dataset, so the query excludes it even if it has samples
inside the window.

### Why the chart disagrees with the API

The Data chart reader exempts live dataset 0 from its `DateEnded` candidate
filter. The Service chart reader selects all unarchived datasets as candidates.
Both then filter readings by per-sample timestamps. For example, the Data reader
uses:

`~/code/NetworkMonitorData/Data/ChartRangeReader.cs:34-44`

```csharp
var availableIds = datasets.Where(m => !m.IsArchived && m.DateStarted < query.End.UtcDateTime &&
    (m.DataSetID == 0 || !m.DateEnded.HasValue || m.DateEnded >= query.Start.UtcDateTime)).Select(m => m.ID).ToArray();
...
var readings = context.PingInfos.AsNoTracking()
    .Where(p => availableIds.Contains(p.MonitorPingInfoID) && p.DateSentInt >= start && p.DateSentInt < end)
```

Each `PingInfo` carries its own `DateSentInt` (an absolute per-sample timestamp,
written by this agent in `nm_model_probe`). Thus the live dataset's chart can
show readings that the host data API excludes for the same window. The Data
reader can still exclude older datasets with stale dates; the Service reader
does not use dataset dates to select unarchived candidate IDs.

`ChartRangeReader.cs:35` also carries a comment naming this exact hazard —
`// Dataset 0 is still collecting; DateEnded can retain the previous dataset's
end.` — and works around it for the live dataset. The API path has no such
allowance.

### Observed symptoms

- A range query over a recent window for a host served by this agent returns
  zero rows, while the chart for the same host and window returns readings.
- The dataset interval reported for the live dataset is inverted: it ends before
  it starts.
- A query with only an end bound still returns rows, because the filter
  degenerates to `m.DateStarted <= DateEnd || m.DateEnded <= DateEnd`, which the
  stale value satisfies. The rows returned are unrelated to the window.

### Firmware fix implemented

Refresh `DateEnded` in the live model before publication so the published
value and the subsequent cycle snapshot agree. This repository now uses the
publication-time rule, matching the .NET processor:

`nm_model_publication_date` sets `DateEnded` to the current UTC time for each
record in a disposable copy-on-write candidate. `state.c` commits that
candidate before taking the publication snapshot and attempts one cycle save
after publication. The refresh also runs on empty and paused cycles.

An alternative would advance `DateEnded` when `nm_model_probe` accepts a sample.
That would be a deliberate difference from .NET publication timing and would
need a separate rule for empty and paused cycles.

Either way:

- The record must be edited copy-on-write before its `DateEnded` is replaced:
  `nm_record_string` requires `r->references == 1`
  (`firmware/main/monitor_record.c:246`). Use `nm_records_edit` to obtain an
  exclusively-owned record. The established idiom is `edit_info` /
  `nm_records_edit` at `firmware/main/monitor_model.c:42-45` and `:210`.
- The change is in publication orchestration, so the host-only
  `tests/reference/monitor_core.c` regression implementation does not need a
  fake publication step. The production state adapter checks a stale imported
  date, the published value, the cycle save, an empty cycle and a reset.
- Update `docs/monitoring-parity.md`, whose contract table covers
  "Configuration and dataset reset" (`MonitorPingCollection.FillPingInfo`,
  `Zero`; `MonitorPingProcessor.Init`). The `DateEnded` refresh rule belongs
  there next to the reset contract, since the two together define the dataset
  interval.

`nm_esp_state_save` persists `s->core` after publication (`state.c`), so a
refresh applied only to a temporary publication snapshot would not be durable.
The live model must be updated through the existing candidate/COW ownership
rules before that snapshot is taken.

---

## Defect 2 — `MonitorPingInfoQuery.DateEnd` silently rewrites the end bound

### Where

`~/code/NetworkMonitorLib/Objects/MonitorPingInfoQuery.cs:108-125`

```csharp
public DateTime? DateEnd
{
    get
    {
        if (DateStart != null && (_dateEnd == null || _dateEnd < DateStart.Value.AddHours(6)))
        {
            return DateStart.Value.AddHours(6);
        }
        else
        {
            return _dateEnd;
        }
    }
    set
    {
        _dateEnd = value;
    }
}
```

The getter is not a plain accessor. Whenever the requested end is null, or less
than six hours after the requested start, it returns `start + 6h` and discards
what the caller asked for.

### Effect

Two consumers read this property, and both see the rewritten value:

1. The database filter. `~/code/NetworkMonitorService/Services/MonitorService.cs:812-826`
   uses `sentData.DateEnd` in the `Where` clause, so a request for
   `14:00`–`15:00` is filtered as `14:00`–`20:00`.
2. The `appliedFilters` echo. `~/code/NetworkMonitorService/Services/MonitorService.cs:815-816`
   reports the rewritten bound back to the caller, so the caller is told it
   requested `20:00`.

The echo misreports the submitted bound; it displays the bound the filter
actually used. A caller comparing the echo with its original request can
detect the widening.

### Verification

Confirmed with a temporary xunit test against the real type (the test file was
created, run, and deleted; no production code was modified):

| Request | `DateEnd` returned |
|---|---|
| `DateStart = 13:30`, `DateEnd = 14:30` | `19:30` — the requested `14:30` is discarded |
| `DateStart = 13:30` only | `19:30` — an end bound is invented |
| `DateStart = 00:00`, `DateEnd = 23:59:59` | `23:59:59` — preserved, because it is more than six hours after the start |

The rule therefore applies to every window shorter than six hours, and never
applies to longer ones.

### Not a timezone bug

The symptom presents as a time offset, so a timezone fault is the natural first
hypothesis. It is not one, and the distinction is worth stating precisely
because it determines the fix:

- A timezone offset moves **both** bounds by the same amount, and the amount
  varies with the client's zone and with daylight-saving.
- This rule moves **only the end bound**, always by exactly six hours,
  regardless of zone, season or request.

The asymmetry is the discriminator. It also rules out the start bound: the start
bound is converted to UTC correctly and passes through unchanged.

Separately, the six hours is not arbitrary — it matches the dataset rollover
granularity described to the API's own tool prompt ("Each data set represents
data for a time range, typically 6 hours"). The widening is presumably intended
so that a short request still selects the dataset containing it. The defect is
that it is applied by rewriting the caller's bound rather than by widening the
*selection*, and that the rewrite is then reported back as the request.

### Recommended fix

Separate the two concerns that are currently conflated in the getter:

- The **selection** may be widened to dataset granularity.
- The **reported and applied end bound** must be the one the caller asked for.

Concretely:

1. Stop the property getter from rewriting the stored value. Make `DateEnd` a
   plain accessor. Any widening becomes an explicit, named operation applied
   where the filter is built.
2. At the filter site
   (`~/code/NetworkMonitorService/Services/MonitorService.cs:812-826`), decide
   explicitly whether to widen. If the six-hour rule is still wanted, apply it
   to candidate selection only and record both the requested and effective
   selection bounds explicitly. First verify that widening is needed for an
   interval-overlap predicate; a valid enclosing dataset already overlaps a
   narrow requested window.
3. Apply the same treatment to the `date_start`-only path, where the getter
   currently invents an end bound.

Note that this is a change in a shared library (`NetworkMonitorLib`), so it
affects every consumer of `MonitorPingInfoQuery`, not only the service. The
`DateStart` doc comment in that type already states "All timestamps are UTC",
which is inconsistent with the service treating these as client-local and
converting them — worth reconciling in the same change.

---

## Additional issues in the same filter

Found while tracing the above. They are latent rather than active, and are
listed for completeness because they sit in the code being changed.

`~/code/NetworkMonitorService/Services/MonitorService.cs:812-826`:

```csharp
if (sentData.DateStart != null && sentData.DateEnd != null)
{
    query = query.Where(m => m.DateStarted <= sentData.DateEnd && m.DateEnded >= sentData.DateStart);
}
else if (sentData.DateStart != null)
{
    query = query.Where(m => m.DateEnded >= sentData.DateStart || m.DateStarted >= sentData.DateStart);
}
else if (sentData.DateEnd != null)
{
    query = query.Where(m => m.DateStarted <= sentData.DateEnd || m.DateEnded <= sentData.DateEnd);
}
```

- The `date_start`-only branch is unreachable with the current getter: a
  non-null start makes `DateEnd` non-null. Once the getter is fixed, its
  interval-overlap condition should be `m.DateEnded >= DateStart` for
  well-formed datasets. Its existing `||` also admits an inverted interval
  whose start is later than the bound but whose end is earlier.
- The `date_end`-only branch should use `m.DateStarted <= DateEnd` for
  well-formed datasets. Its current `|| m.DateEnded <= DateEnd` can admit an
  inverted dataset that starts after the bound. It does not make every
  past dataset a false match: a well-formed past dataset already satisfies
  `DateStarted <= DateEnd` and legitimately overlaps the open-ended window.
- Replacing either `||` with `&&` is incorrect. It would exclude well-formed
  datasets that span the bound. Apply the same analysis if the root-level
  `~/code/MonitorService.cs` copy is ever reused.

---

## Structural observation: dataset dates are not the right filter key

Both defects interact with a limitation in the data model: the API filters host data on
*dataset envelope* dates (`MonitorPingInfo.DateStarted`/`DateEnded`), while the
readings themselves carry per-sample absolute timestamps
(`PingInfo.DateSentInt`).

Both chart paths filter readings by per-sample timestamps. The Data chart path
also uses dataset dates to choose candidates, with an exemption for live dataset
0; the Service chart path chooses all unarchived datasets. The host data API
selects dataset-level records by their envelope dates. These paths can therefore
disagree for the same host and window.

The API cannot return a true one-hour aggregate from `get_host_data` regardless
of these fixes, because that endpoint returns dataset-level accumulators
(`RoundTripTimeAverage`/`Minimum`/`Maximum` and the packet counters) rather
than per-sample values. A request for one hour returns the enclosing dataset's
totals — the "12 hours" span in the observed output is the dataset envelope, not
the requested window. Per-sample readings are available from
`GetHostResponseObjByDateRange*` and `GetChartRange*`.

An agent that stops publishing leaves `DateEnded` at its last legitimate
publication time. That alone does not hide samples that were published before
the stop: those samples should fall inside the recorded interval. Stale or
inverted dates can still hide valid readings if the envelope is wrong. The Data
chart reader tolerates this for live dataset 0; the Service chart reader selects
all unarchived candidate datasets. Considering per-sample selection for an API
that promises exact sample windows is a separate API design change.

---

## Repository note

`~/code/MonitorService.cs` is a root-level file in the code workspace that is
not referenced by any `.csproj` in the tree, and differs from
`~/code/NetworkMonitorService/Services/MonitorService.cs`. It contains a copy of
the same one-bound filter logic. It appears to be a
leftover from the pre-split layout. It is not compiled, so it is not a live
defect, but it will mislead anyone reading it as the source of truth. It should
be confirmed as disposable and removed.

---

## Change surface

Fixing Defect 1:

| Path | Change |
|---|---|
| `firmware/main/monitor_model.c` and/or `firmware/main/state.c` | Refresh `DateEnded` in the live model under copy-on-write rules before publication, according to the chosen contract |
| `tests/reference/monitor_core.c` | Update only if the refresh is implemented in the shared probe contract |
| `tests/native/test_monitor_core.c`, state adapter tests | Assert the chosen refresh rule, publication value, reset handling and durable cycle state |
| `docs/monitoring-parity.md` | Document the `DateEnded` refresh rule beside the dataset-reset contract |

Fixing Defect 2:

| Path | Change |
|---|---|
| `~/code/NetworkMonitorLib/Objects/MonitorPingInfoQuery.cs` | Make `DateEnd` a plain accessor; move widening to the query site |
| `~/code/NetworkMonitorService/Services/MonitorService.cs` | Filter using the requested bound; if widening is justified, report it separately; simplify one-bound overlap predicates without replacing `\|\|` with `&&` |
| `~/code/NetworkMonitorService/Services/Function/MonitorFunctionHandler.cs` | Confirm the client-local-to-UTC conversion still applies to both bounds once the getter is inert |

Validation for a C fix to Defect 1 uses the repository's required sanitizer-enabled
host test suite and firmware build, with pinned submodules:

```sh
git submodule update --init --recursive
cmake -S . -B build-tests -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer'
cmake --build build-tests
ctest --test-dir build-tests --output-on-failure
bash tests/dotnet/generate.sh --check
./tools/build-firmware.sh
```

The source-linked .NET oracle should still be checked when changing model or
serialization behavior; it does not test the .NET publisher's runtime path.

Defect 2 is in a separate repository (`NetworkMonitorLib`) and is validated by
the service's own test suite in `~/code/NetworkMonitorService`.

---

## Status

The firmware fix is implemented in this repository. All 35 native CTest targets
pass with address and undefined-behavior sanitizers when leak detection is
disabled; LeakSanitizer cannot run under the current ptrace environment. The
existing private OTA signing key is present, but the signed firmware build
cannot start because ESP-IDF Installation Manager (EIM) is not configured on
this machine.
`tests/dotnet/generate.sh --check` stops on existing `manifest.json` source
revision drift. Defect 2 remains in the sibling shared library and service.
The original getter finding was confirmed with a temporary xunit test, which
was removed. No device, emulator, or backend deployment has been performed.
