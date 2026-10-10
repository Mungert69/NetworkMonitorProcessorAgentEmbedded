#!/usr/bin/env python3
"""Print only BLE/resource diagnostics and compare raw capture-ID ranges.

Run with an interpreter providing pyserial (the ESP-IDF environment does).
Detailed diagnostics require a firmware build with DEBUG logging enabled.
Range overlap flags a possible replay; disjoint ranges prove no shared capture
IDs between those reports. Metric windows intentionally overlap.
"""
import argparse
import re
import time

import serial


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", default="/dev/ttyACM0")
    parser.add_argument("--seconds", type=float, default=240)
    args = parser.parse_args()
    if args.seconds <= 0:
        parser.error("--seconds must be positive")
    previous = {}
    with serial.Serial(args.port, 115200, timeout=1) as port:
        deadline = time.monotonic() + args.seconds
        while time.monotonic() < deadline:
            line = re.sub(r"\x1b\[[0-9;]*m", "", port.readline().decode("utf-8", "replace")).strip()
            selected = any(tag in line for tag in (
                "nm_ble_buffer:", "nm_ble_decode:", "nm_ble_raw:",
                "callback_repeat", "callback_totals", "BLE history", "resources internal_free"))
            if not selected:
                continue
            print(line, flush=True)
            if "nm_ble_raw:" not in line or "snapshot_us=" not in line:
                continue
            fields = dict(re.findall(r"(\w+)=(\d+)", line))
            if not int(fields.get("emitted", "0")):
                continue
            monitor = fields["monitor"]
            first_id = int(fields["first_capture_id"])
            last_id = int(fields["last_capture_id"])
            snapshot = int(fields["snapshot_us"])
            if monitor in previous:
                old_snapshot, old_last = previous[monitor]
                print(f"TRACE raw monitor={monitor} previous_last={old_last} "
                      f"current_first={first_id} current_last={last_id} "
                      f"range_overlap={int(first_id <= old_last)} "
                      f"snapshot_advanced={int(snapshot > old_snapshot)}", flush=True)
            previous[monitor] = (snapshot, last_id)


if __name__ == "__main__":
    main()
