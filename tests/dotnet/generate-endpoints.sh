#!/usr/bin/env bash
set -euo pipefail
fixture_tool_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
fixture_lib_root="${NETWORK_MONITOR_LIB_ROOT:-$(cd -- "$fixture_tool_dir/../../../NetworkMonitorLib" && pwd)}"
export DOTNET_CLI_TELEMETRY_OPTOUT=1
dotnet restore "$fixture_tool_dir/EndpointParity/EndpointParity.csproj" \
    --configfile "$fixture_tool_dir/NuGet.Config" -p:NuGetAudit=false \
    "-p:NetworkMonitorLibRoot=$fixture_lib_root"
dotnet run --project "$fixture_tool_dir/EndpointParity/EndpointParity.csproj" \
    --no-restore "-p:NetworkMonitorLibRoot=$fixture_lib_root" -- \
    "$fixture_lib_root" "$fixture_tool_dir/../fixtures/endpoint-contracts.json" "$@"
