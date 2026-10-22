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
| 1 | This repository (ESP32 agent) | `MonitorPingInfo.DateEnded` is written once at host creation and never refreshed | Date-range queries against this agent's hosts return no rows; dataset intervals are inverted |
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

`DateEnded` is assigned in exactly two places in the entire firmware, both in
`monitor_model.c`:

- `fill()` (line 170) — writes `DateStarted` and `DateEnded` to the same value,
  and only when the host record is first created.
- the dataset-reset path (line 332) — updates `DateStarted` only.

There is no third assignment anywhere in `firmware/`. Confirmed by exhaustive
search across the whole repository:

```sh
grep -rn "DateEnded" --exclude-dir=.git .
```

which yields only:

```
firmware/main/monitor_model.c:170:    TRY(MSTR(info, DateStarted, when) && MSTR(info, DateEnded, when) && ...
firmware/main/monitor_model.h:45:      X(char *, DateEnded, STRING)       \
tests/reference/monitor_core.c:234:    TRY(text(c,info,"DateStarted",when) && text(c,info,"DateEnded",when));
```

So on this agent, `DateEnded` is frozen at the moment the host was first
enrolled. It is never advanced, while `DateStarted` advances on every dataset
rollover.

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

The reference therefore maintains a well-formed interval
`[dataset start, last publish]`. This repository maintains
`[dataset start, host enrolment time]`, which is stale and, after any rollover,
inverted.

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

With a `DateEnded` that predates the requested window, `m.DateEnded >= DateStart`
is false for every dataset, so the query returns nothing.

### Why the chart disagrees with the API

The chart readers deliberately do not select datasets by `DateEnded`. They select
by per-sample timestamps instead:

`~/code/NetworkMonitorData/Data/ChartRangeReader.cs:34-44`

```csharp
var availableIds = datasets.Where(m => !m.IsArchived && m.DateStarted < query.End.UtcDateTime &&
    (m.DataSetID == 0 || !m.DateEnded.HasValue || m.DateEnded >= query.Start.UtcDateTime)).Select(m => m.ID).ToArray();
...
var readings = context.PingInfos.AsNoTracking()
    .Where(p => availableIds.Contains(p.MonitorPingInfoID) && p.DateSentInt >= start && p.DateSentInt < end)
```

Each `PingInfo` carries its own `DateSentInt` (an absolute per-sample timestamp,
written by this agent at `firmware/main/monitor_model.c:559`), so the chart
resolves the window correctly while the API cannot. Same host, same window, two
different answers.

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

### Recommended fix

Refresh `DateEnded` so the live dataset's end tracks its most recent sample.
Two options, in order of preference:

**Option A — stamp at publish, in the sample path.** Set `DateEnded` to the
timestamp of the most recently published sample for that host, at the same point
the per-sample `DateSent`/`DateSentInt` are written
(`firmware/main/monitor_model.c:559`, in `nm_model_probe`). This makes the
dataset interval mean "contains exactly these samples", which is the strongest
guarantee for the API filter and is tighter than the reference implementation's
wall-clock stamp.

**Option B — exact parity.** Set `DateEnded = now` on every publish, as
`PublishRepo.cs:98` does. Simplest and provably matches the reference.

Either way:

- The record must be edited copy-on-write before its `DateEnded` is replaced:
  `nm_record_string` requires `r->references == 1`
  (`firmware/main/monitor_record.c:246`). Use `nm_records_edit` to obtain an
  exclusively-owned record. The established idiom is `edit_info` /
  `nm_records_edit` at `firmware/main/monitor_model.c:42-45` and `:210`.
- The same change must be applied to `tests/reference/monitor_core.c`, which is
  the parity oracle. `tests/native/test_monitor_core.c` is compiled twice — once
  against the reference and once against the production `monitor_model.c` via
  `tests/native/test_typed_core.c` and `tests/native/typed_core_adapter.h` — so
  both implementations must agree or the shared assertions diverge. The reference
  currently has the same frozen-`DateEnded` behaviour at
  `tests/reference/monitor_core.c:234` (fill) and `:333` (reset).
- Add a native assertion that a published dataset's `DateEnded` advances with
  its samples, and that `DateEnded` is never earlier than `DateStarted`.
- Update `docs/monitoring-parity.md`, whose contract table covers
  "Configuration and dataset reset" (`MonitorPingCollection.FillPingInfo`,
  `Zero`; `MonitorPingProcessor.Init`). The `DateEnded` refresh rule belongs
  there next to the reset contract, since the two together define the dataset
  interval.

Note that `nm_esp_state_save` persists `s->core` after publication
(`firmware/main/state.c:690`), so a refreshed `DateEnded` will also be durable
across restarts without a separate save.

---

## Defect 2 — `MonitorPingInfoQuery.DateEnd` silently rewrites the end bound

### Where

`~/code/NetworkMonitorLib/Objects/MonitorPingInfoQuery.cs:108-125`

```csharp
public DateTime? DateEnd
{
    get
    {
        if (DateStart != null && (_dateEnd == null || _dateEnd < DateTime.SpecifyKind(DateStart.Value, DateTimeKind.Utc).AddHours(6)))
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

The second effect is the more damaging of the two: the API misreports the
request it executed, so a caller comparing its own request against the echo
cannot detect the widening.

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
   to the query and record it in `appliedFilters` as a distinct, labelled fact
   (for example `date_end=2026-10-21T15:00:00 (widened to dataset granularity
   2026-10-21T20:00:00)`) rather than silently substituting the value.
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

- The `date_start`-only branch is unreachable. Because the getter returns a
  non-null value whenever `DateStart` is set, the first branch always matches
  and the `else if` never runs. Its `||` should be `&&` regardless.
- The `date_end`-only branch has the same `||`/`&&` inversion. `m.DateEnded <=
  sentData.DateEnd` is true for every dataset that ended at any point in the
  past, so this branch returns essentially the whole table rather than the
  datasets overlapping the requested bound.
- The same two branches exist with the same inversion in the parallel
  implementation at `~/code/MonitorService.cs:699-726` (a root-level file that
  is not part of any project in the tree — see "Repository note" below).

---

## Structural observation: dataset dates are not the right filter key

Both defects share a root cause in the data model: the API filters host data on
*dataset envelope* dates (`MonitorPingInfo.DateStarted`/`DateEnded`), while the
readings themselves carry per-sample absolute timestamps
(`PingInfo.DateSentInt`).

The chart path already resolves the window from per-sample timestamps and uses
dataset dates only to pick candidate datasets. The API path does the opposite,
which is why the two can disagree for the same host and window.

The API cannot return a true one-hour aggregate from `get_host_data` regardless
of these fixes, because that endpoint returns dataset-level accumulators
(`RoundTripTimeAverage`/`Minimum`/`Maximum` and the packet counters) rather
than per-sample values. A request for one hour returns the enclosing dataset's
totals — the "12 hours" span in the observed output is the dataset envelope, not
the requested window. Per-sample readings are available from
`GetHostResponseObjByDateRange*` and `GetChartRange*`.

Even with both fixes applied, an agent that stops publishing leaves a stale
`DateEnded` that will silently hide its data from range queries. The chart
readers already tolerate this for the live dataset
(`NetworkMonitorData/Data/ChartRangeReader.cs:35`). The two chart readers have
since diverged — `NetworkMonitorService/Services/ServiceChartRangeReader.cs:35`
no longer carries that tolerance, and the API range filter carries neither.
Reconciling them, and considering a per-sample filter for the API path, would
make the API robust to any agent that stops or delays publishing.

---

## Repository note

`~/code/MonitorService.cs` is a root-level file in the code workspace that is
not referenced by any `.csproj` in the tree, and differs from
`~/code/NetworkMonitorService/Services/MonitorService.cs`. It contains a copy of
the same filter logic with the same `||`/`&&` inversion. It appears to be a
leftover from the pre-split layout. It is not compiled, so it is not a live
defect, but it will mislead anyone reading it as the source of truth. It should
be confirmed as disposable and removed.

---

## Change surface

Fixing Defect 1:

| Path | Change |
|---|---|
| `firmware/main/monitor_model.c` | Refresh `DateEnded` alongside per-sample writes, copy-on-write via `nm_records_edit` |
| `tests/reference/monitor_core.c` | Same behaviour in the parity oracle, so the shared assertions hold for both implementations |
| `tests/native/test_monitor_core.c` | Assert `DateEnded` advances with samples and never precedes `DateStarted` |
| `docs/monitoring-parity.md` | Document the `DateEnded` refresh rule beside the dataset-reset contract |

Fixing Defect 2:

| Path | Change |
|---|---|
| `~/code/NetworkMonitorLib/Objects/MonitorPingInfoQuery.cs` | Make `DateEnd` a plain accessor; move widening to the query site |
| `~/code/NetworkMonitorService/Services/MonitorService.cs` | Apply the filter on the requested bound; report widening explicitly; correct the `\|\|`/`&&` inversions |
| `~/code/NetworkMonitorService/Services/Function/MonitorFunctionHandler.cs` | Confirm the client-local-to-UTC conversion still applies to both bounds once the getter is inert |

Validation for Defect 1 uses the repository's host test suite, which needs the
pinned submodules:

```sh
git submodule update --init --recursive
cmake -S . -B build-tests -DCMAKE_BUILD_TYPE=Debug
cmake --build build-tests
ctest --test-dir build-tests --output-on-failure
python3 -m unittest discover -s tests/tooling
```

The `tests/dotnet/generate.sh --check` oracle is unaffected by these changes: it
verifies the shared .NET model sources, which are not modified here.

Defect 2 is in a separate repository (`NetworkMonitorLib`) and is validated by
the service's own test suite in `~/code/NetworkMonitorService`.

---

## Status

No code was changed. The findings above were established by reading the
implementation, by an exhaustive search for `DateEnded` assignments, by
temporarily running a test against `MonitorPingInfoQuery.DateEnd` to confirm the
getter's behaviour, and by comparing this agent against the C#/.NET reference
implementation. The temporary test was removed after use.
