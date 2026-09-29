#!/usr/bin/env python3
"""Read-only hardware preflight. Fails closed on unknown chip, flash, or eFuse state."""

import argparse
import json
import pathlib
import re
import subprocess
import tempfile


def command(*args: str) -> str:
    result = subprocess.run(args, check=True, capture_output=True, text=True)
    return result.stdout + result.stderr


def parse_identification(flash: str, mac_output: str) -> tuple[int, str]:
    size_match = re.search(r"Detected flash size:\s*(\d+)\s*MB", flash, re.I)
    mac_match = re.search(r"\bMAC:\s*([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b", mac_output, re.I)
    if not size_match or not mac_match:
        raise ValueError("could not positively identify flash size and MAC")
    return int(size_match.group(1)), mac_match.group(1).lower()


def raw_fuse(summary: dict, name: str) -> int:
    item = summary.get(name)
    if (not isinstance(item, dict) or item.get("readable") is not True
            or not isinstance(item.get("raw_value"), str)):
        raise ValueError(f"missing {name} eFuse status")
    return int(item["raw_value"], 16)


def security_state(summary: dict) -> None:
    for name in ("SECURE_BOOT_EN", "SPI_BOOT_CRYPT_CNT", "DIS_DOWNLOAD_MODE"):
        if raw_fuse(summary, name) != 0:
            raise ValueError(f"{name} is set; development provisioning refused")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--check-blank-state", action="store_true")
    args = parser.parse_args()
    prefix = ("python", "-m", "esptool", "--chip", "esp32s3", "-p", args.port)
    flash = command(*prefix, "flash_id")
    mac_output = command(*prefix, "read_mac")
    size, mac = parse_identification(flash, mac_output)
    if size != 16:
        raise ValueError(f"expected 16 MB flash, detected {size} MB")
    with tempfile.TemporaryDirectory(prefix="nm-chip-check-") as folder:
        efuses_path = pathlib.Path(folder) / "efuses.json"
        command("espefuse.py", "--chip", "esp32s3", "--port", args.port,
                "summary", "--format", "json", "--file", str(efuses_path))
        security_state(json.loads(efuses_path.read_text(encoding="utf-8")))
        if args.check_blank_state:
            state_path = pathlib.Path(folder) / "nmdata.bin"
            command(*prefix, "read_flash", "0xc20000", "0x200000", str(state_path))
            with state_path.open("rb") as stream:
                while chunk := stream.read(64 * 1024):
                    if any(byte != 0xFF for byte in chunk):
                        raise ValueError("nmdata is not blank; refusing to overwrite an existing device")
    args.output.write_text(json.dumps({"chip": "esp32s3", "flash_mb": size, "mac": mac}) + "\n",
                           encoding="utf-8")
    print(f"Preflight OK: ESP32-S3, 16 MB flash, MAC {mac}; development eFuses unset")


if __name__ == "__main__":
    main()
