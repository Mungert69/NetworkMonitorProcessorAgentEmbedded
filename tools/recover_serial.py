#!/usr/bin/env python3
"""Recover an ESP32-S3 processor over USB with esptool (ROM download mode).

For a device whose application will not boot, or whose gated serial-update
command is not compiled in. It writes the signed application into ota_0 and
selects it with the initial otadata image, leaving nmconfig and nmdata intact.
The bootloader still verifies the app signature; a device normally awakens in
ROM download mode (hold BOOT, tap RESET) and esptool can auto-enter it here.

Prefer the signed OTA path for updating a working device; use this only to
recover one.
"""
import argparse
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from stage_firmware import describe

OTA_0_OFFSET = 0x20000
OTADATA_OFFSET = 0xF000
OTADATA_SIZE = 0x2000
IDF_RUNNER = pathlib.Path(__file__).resolve().with_name("idf-local.sh")


def write_flash_args(app_path, otadata_path, port):
    return ["python", "-m", "esptool", "--chip", "esp32s3", "-p", port, "write_flash",
            hex(OTADATA_OFFSET), otadata_path, hex(OTA_0_OFFSET), app_path]


def parse_mac(output):
    match = re.search(r"\bMAC:\s*([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\b", output)
    if not match:
        raise ValueError("could not read the device MAC address")
    return match.group(1).lower()


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True)
    parser.add_argument("--app", type=pathlib.Path,
                        default=root / "firmware/build/networkmonitor_processor_esp32.bin")
    parser.add_argument("--otadata", type=pathlib.Path,
                        default=root / "firmware/build/ota_data_initial.bin")
    parser.add_argument("--yes", action="store_true", help="skip the typed MAC confirmation")
    args = parser.parse_args()

    port = pathlib.Path(args.port).resolve()
    if not port.is_char_device() or not re.fullmatch(r"/dev/tty(ACM|USB)\d+", str(port)):
        print("Port must resolve to an existing /dev/ttyACM* or /dev/ttyUSB* device.",
              file=sys.stderr)
        return 2
    app, otadata = args.app.resolve(strict=True), args.otadata.resolve(strict=True)
    version, digest = describe(app.read_bytes())
    if otadata.stat().st_size != OTADATA_SIZE:
        print("otadata image is not the expected 8 KiB partition image.", file=sys.stderr)
        return 2

    print(f"Recovering {port} with signed app {version} ({digest[:12]}...); "
          "nmconfig and nmdata are preserved.")
    probe = subprocess.run([str(IDF_RUNNER), "python", "-m", "esptool", "--chip",
                            "esp32s3", "-p", str(port), "read_mac"],
                           capture_output=True, text=True)
    if probe.returncode != 0:
        print(probe.stdout + probe.stderr, file=sys.stderr)
        print("Could not read the device; ensure it is in ROM download mode.", file=sys.stderr)
        return 1
    mac = parse_mac(probe.stdout + probe.stderr)
    if not args.yes:
        reply = input(f"Type the device MAC {mac} to confirm: ")
        if reply.strip().lower() != mac:
            print("Confirmation did not match; no flash writes performed.", file=sys.stderr)
            return 2

    command = write_flash_args(str(app), str(otadata), str(port))
    if subprocess.run([str(IDF_RUNNER), *command]).returncode != 0:
        print("Recovery flash failed.", file=sys.stderr)
        return 1
    print("Recovery complete. The device boots ota_0 on the next reset.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
