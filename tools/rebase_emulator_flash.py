#!/usr/bin/env python3
"""Refresh emulator boot/app code while preserving dual-slot NVS config/state.

For development only. Deployed devices must use OTA instead of this operation.
"""

import argparse
import os
import pathlib
import tempfile

FLASH_SIZE = 16 * 1024 * 1024
PRESERVED = ((0x12000, 0x20000), (0xC20000, 0xE20000))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old-flash", type=pathlib.Path, required=True)
    parser.add_argument("--new-base", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--replace-config", action="store_true",
                        help="use newly provisioned nmconfig from new base; preserve monitor state")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists; refusing overwrite")
    old = args.old_flash.read_bytes()
    base = args.new_base.read_bytes()
    if len(old) != FLASH_SIZE or len(base) >= 0x620000 or \
            b"ota_0" not in old[0x8000:0x9000] or \
            b"ota_0" not in base[0x8000:0x9000]:
        parser.error("images do not match the dual-slot emulator layout")
    image = bytearray(b"\xFF" * FLASH_SIZE)
    image[:len(base)] = base
    for start, end in PRESERVED:
        if args.replace_config and start == 0x12000:
            continue
        image[start:end] = old[start:end]
    descriptor, temporary = tempfile.mkstemp(prefix=".nm-rebase-", dir=args.output.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(image)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, args.output)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print(f"Created refreshed emulator image at {args.output} (state hidden)")


if __name__ == "__main__":
    main()
