#!/usr/bin/env python3
"""Generate the embedded TCP service-name hints from the IANA CSV registry."""

import argparse
import csv
from datetime import date
from pathlib import Path
import re
import urllib.request

SOURCE = (
    "https://www.iana.org/assignments/service-names-port-numbers/"
    "service-names-port-numbers.csv"
)
DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / "firmware/main/service-hints.csv"
SAFE_NAME = re.compile(r"^[a-zA-Z0-9-]{1,63}$")

# Prefer familiar labels where IANA has multiple TCP names registered to a port.
PREFERRED = {
    42: "nameserver",
    80: "http",
    443: "https",
    465: "submissions",
    631: "ipp",
    8080: "http-alt",
}


def registry_rows(source):
    with urllib.request.urlopen(source, timeout=30) as response:
        text = response.read().decode("utf-8-sig")
    selected = {}
    for row in csv.DictReader(text.splitlines()):
        service = (row.get("Service Name") or "").strip()
        port_text = (row.get("Port Number") or "").strip()
        if row.get("Transport Protocol", "").strip().lower() != "tcp":
            continue
        if not port_text.isascii() or not port_text.isdecimal():
            continue
        port = int(port_text)
        if not 1 <= port <= 49151 or not SAFE_NAME.fullmatch(service):
            continue
        selected.setdefault(port, []).append(service.lower())

    result = {}
    for port, names in selected.items():
        preferred = PREFERRED.get(port)
        result[port] = preferred if preferred in names else names[0]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    entries = registry_rows(SOURCE)
    lines = [
        f"# Generated {date.today().isoformat()} from the IANA TCP service registry.",
        "# Format: decimal-port,service-name; one TCP hint per assigned port.",
        "# Hints identify IANA registrations, not the service actually running.",
    ]
    lines.extend(f"{port},{name}" for port, name in sorted(entries.items()))
    args.output.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")
    print(f"Wrote {len(entries)} TCP hints to {args.output}")


if __name__ == "__main__":
    main()
