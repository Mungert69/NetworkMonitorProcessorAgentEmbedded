#!/usr/bin/env python3
"""One-time migration of the old emulator NVS state to the dual-slot layout.

Never changes the source image. This is *not* an OTA partition-table update.
"""

import argparse
import os
import pathlib
import tempfile

FLASH_SIZE = 16 * 1024 * 1024
STATE_SIZE = 2 * 1024 * 1024
OLD_STATE_OFFSET = 0x410000
NEW_STATE_OFFSET = 0xC20000


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old-flash", type=pathlib.Path, required=True)
    parser.add_argument("--new-base", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists; refusing overwrite")
    old = args.old_flash.read_bytes()
    base = args.new_base.read_bytes()
    if len(old) != FLASH_SIZE or len(base) > NEW_STATE_OFFSET or \
            b"nmdata" not in old[0x8000:0x9000] or \
            b"ota_0" not in base[0x8000:0x9000]:
        parser.error("flash images do not match the expected old/new layouts")
    state = old[OLD_STATE_OFFSET:OLD_STATE_OFFSET + STATE_SIZE]
    if all(byte == 0xFF for byte in state):
        parser.error("old state partition is empty")
    image = bytearray(b"\xFF" * FLASH_SIZE)
    image[:len(base)] = base
    image[NEW_STATE_OFFSET:NEW_STATE_OFFSET + STATE_SIZE] = state
    descriptor, temporary = tempfile.mkstemp(prefix=".nm-ota-flash-", dir=args.output.parent)
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
    print(f"Migrated emulator NVS to {args.output} (content hidden)")


if __name__ == "__main__":
    main()
