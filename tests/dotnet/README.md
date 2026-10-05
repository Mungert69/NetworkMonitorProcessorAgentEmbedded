# .NET JSON parity oracle

This package-free .NET 10 console project compiles **linked, unmodified source
files** from the sibling `NetworkMonitorLib` checkout. It does not copy models,
reference the full library project, or use mock model definitions. Only .NET SDK
framework assemblies are required; `NuGet.Config` clears all package feeds.

From the ESP32 repository root:

```sh
bash tests/dotnet/generate.sh
bash tests/dotnet/generate.sh --check
bash tests/dotnet/generate.sh --check-compatible
```

The first command rebuilds the oracle, runs its assertions and writes the JSON
under `tests/fixtures/dotnet`. The second rebuilds and runs the same assertions,
then compares all eight generated files byte-for-byte without changing them.
Both exit nonzero on assertion/build failure; `--check` also fails for missing or
changed fixtures. No test runner or NuGet test packages are necessary. Build
outputs stay in the ignored `tests/dotnet/JsonParity/{bin,obj}` directories.
Invoke with `bash`; executable permission is not required.

`--check-compatible` compares the seven generated wire-contract fixtures while
ignoring `manifest.json`. CI uses it with the current `NetworkMonitorLib` default
branch so serialization or model-behaviour drift fails without treating an
unrelated library commit as a contract change. Use strict `--check` when
regenerating fixtures at the manifest's recorded source revision.

The default layout is:

```text
parent/
  NetworkMonitorLib/Objects/PingInfo.cs
  NetworkMonitorProcessorAgentEmbedded/tests/dotnet/
```

Override the source location with `NETWORK_MONITOR_LIB_ROOT=/absolute/path`.
The script passes that same root to MSBuild and the provenance collector. Do
not run an old binary against a different source tree: use the script so model
changes cause recompilation. `dotnet` must select an installed .NET 10 SDK with
its framework reference packs; no SDK is downloaded. Git is used to record the
source revision. For exact regeneration, use the revision and source hashes in
the manifest and the recorded runtime version (initial SDK: 10.0.401).

## Oracle contract

All model serialization and deserialization uses actual `System.Text.Json`.
The profile is strict numeric handling, case-sensitive CLR property names,
default escaping, inclusion of null/default properties, and ignored unknown
properties. Output is indented with a final LF for review. No timestamps or
absolute paths are embedded in generated output.

`NetworkMonitorLib/Objects/JsonConfig.cs` declares the production source-generation
context with only `WriteIndented = false`; `Utils/JsonUtils.cs` uses that context
in `WriteJsonObjectToString` and `GetJsonObjectFromString`. This standalone oracle
uses reflection metadata for the linked subset and pretty printing. It does not
compile the production context, which registers many unrelated dependency-heavy
types, and does not prove parity for every transport entry point. In particular,
`GetJsonObjectFromStringNoCase` is a separate case-insensitive profile not tested
here. `ReadinessState` is included as an additional simple model, not a claim
that it is registered by the production context.

The generator asserts exact `ulong` recovery, `uint` recovery, the UTC 2022 epoch
calculation, representative serialize/deserialize round trips, and expected
acceptance/rejection of every deserialization probe. It records observed
normalized objects or `JsonException` paths; localized exception messages are
deliberately excluded. A model behavior change causes assertions or fixture
comparison to fail and should be reviewed before regeneration.

The manifest records the NetworkMonitorLib Git revision, working-tree status of
linked files, SHA-256 of each source file, runtime/serializer versions, options,
file list, and probe count. Source hashes identify the actual files compiled,
including any uncommitted model edits. Generator implementation and project links
are versioned alongside fixtures. No firmware, C tests or CMake wiring is part
of this scaffold.

## Extending

Add the real source file as another explicit `Compile Include`/`Link` in
`JsonParity.csproj`, include it in the provenance `sources` array, and construct
instances/probes in `Program.cs`. Link any needed real dependencies as well;
avoid placeholder types or copied declarations. Keep selected models free of
external package dependencies. Regenerate, run `--check`, and review the JSON
diff before committing the generator and fixtures together.

## Full-library endpoint oracle

`bash tests/dotnet/generate-endpoints.sh --check` separately builds EndpointParity,
which references the actual full sibling library and its cached dependencies.
Unlike the package-free JSON oracle above, it executes the real factory,
measurement catalogue and BLE decoders. It verifies the pinned
`tests/fixtures/endpoint-contracts.json` including source hashes. Run without
`--check` only after reviewing a deliberate contract change. The production C
`native-endpoint_contracts` target consumes its policies/readings/status names;
[the endpoint audit](../../docs/endpoint-parity-audit.md) describes scope and
remaining outcome differences. Build artifacts remain ignored; no network,
radio, broker, credentials or provisioned flash are needed.
