#!/usr/bin/env python3
"""Prepare a private, isolated mixed-endpoint load fixture from a test config.

The public CSV contains targets only. The config and source monitoring snapshot
are private inputs; generated files must remain under an ignored runtime folder.
"""

import argparse
import copy
import csv
import json
import os
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--hosts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--count", type=int, choices=(50, 150), default=150)
    args = parser.parse_args()
    os.umask(0o077)
    output = args.output.resolve(strict=True)
    if any(output.iterdir()):
        raise ValueError("Output directory must be empty; refusing to replace state")
    with args.hosts.open(newline="", encoding="utf-8") as source:
        rows = list(csv.DictReader(source))
    endpoints = ("icmp", "dns", "rawconnect", "http", "https", "httphtml")
    if len(rows) != 150 or len({row["host"] for row in rows}) != 150 or \
            any(sum(row["endpoint"] == endpoint for row in rows) != 25 for endpoint in endpoints):
        raise ValueError("Source fixture requires 25 distinct hosts per endpoint")
    quota = {endpoint: args.count // 6 + (index < args.count % 6)
             for index, endpoint in enumerate(endpoints)}
    selected = []
    for row in rows:
        endpoint = row["endpoint"]
        if quota[endpoint]:
            selected.append(row)
            quota[endpoint] -= 1
    rows = selected

    config = json.loads(args.config.read_text())
    config.update(max_monitors=args.count, max_pending_ping_infos=args.count * 10,
                  MaxTaskQueueSize=8, poll_seconds=30)
    snapshot = json.loads(args.snapshot.read_text())
    templates = snapshot["MonitorIPs"]
    info_templates = snapshot["ProcessorData"]["MonitorPingInfos"]
    if len(templates) != 3 or len(info_templates) != 3:
        raise ValueError("Expected three private monitor templates")
    monitors, infos = [], []
    for index, row in enumerate(rows):
        monitor_id = 1_500_000_000 + index
        endpoint, host = row["endpoint"], row["host"]
        port = 443 if endpoint in ("rawconnect", "https") else 80 if endpoint in ("http", "httphtml") else 0
        monitor = copy.deepcopy(templates[index % 3])
        info = copy.deepcopy(info_templates[index % 3])
        for item in (monitor, info, monitor.get("MonitorPingInfo")):
            if not isinstance(item, dict):
                continue
            item.update(ID=monitor_id, MonitorIPID=monitor_id,
                        MonitorPingInfoID=monitor_id, Address=host,
                        EndPointType=endpoint, Port=port, Timeout=3000,
                        Enabled=True, SkipCycles=0)
            if "Host" in item:
                item["Host"] = host
            if "PingInfos" in item:
                item["PingInfos"] = []
        monitors.append(monitor)
        infos.append(info)
    snapshot["MonitorIPs"] = monitors
    snapshot["ProcessorData"].update(MonitorPingInfos=infos, PingInfos=[], PiIDKey=1)
    (output / "config.json").write_text(json.dumps(config, separators=(",", ":")))
    (output / "monitoring.json").write_text(json.dumps(snapshot, separators=(",", ":")))
    # Seed raw JSON only for the initial NVS fixture. Production accepts this
    # legacy form on load and writes Brotli-compressed monitoring snapshots on
    # subsequent saves; psram_memory tests that production save/load path.
    with (output / "state.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(("key", "type", "encoding", "value"))
        writer.writerow(("networkmonitor", "namespace", "", ""))
        writer.writerow(("monitoring", "file", "binary",
                         os.path.relpath(output / "monitoring.json", Path.cwd())))
    for path in output.iterdir():
        path.chmod(0o600)
    print(f"Prepared {args.count} distinct hosts across all six endpoints; private config values hidden")
    print("Initial monitoring snapshot bytes:", (output / "monitoring.json").stat().st_size)


if __name__ == "__main__":
    main()
