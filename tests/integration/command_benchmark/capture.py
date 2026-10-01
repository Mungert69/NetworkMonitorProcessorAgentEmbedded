"""Capture two actual 50-host cycles and production signature timings."""
import argparse
import os
import pathlib
import time
import serial

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--port", required=True)
parser.add_argument("--output", type=pathlib.Path, required=True)
args = parser.parse_args()
os.umask(0o077)
with serial.Serial(args.port, 115200, timeout=1, exclusive=True) as port, args.output.open("wb") as log:
    port.dtr = False
    port.rts = True
    time.sleep(.1)
    port.rts = False
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        line = port.readline()
        log.write(line)
        log.flush()
        text = line.decode(errors="replace")
        if any(marker in text for marker in ("COMMAND_BENCHMARK", "resources", "MQTT_READY", "snapshot", "cycle failed", "Guru Meditation")):
            print(text.rstrip(), flush=True)
        if "ESP32_S3_MQTT_READY" in text:
            port.write(b"start\n")
        if "COMMAND_BENCHMARK_CYCLE_DONE cycle=2" in text:
            break
        if "Guru Meditation" in text or "COMMAND_BENCHMARK_FAILED" in text:
            raise SystemExit(1)
    else:
        raise SystemExit("Benchmark timed out")
