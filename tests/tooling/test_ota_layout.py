import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "tools"))

#!/usr/bin/env python3
"""Offline checks for the 16 MB dual-slot layout and state migration."""

import csv
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
FLASH = 16 * 1024 * 1024


class OtaLayoutTests(unittest.TestCase):
    def test_partitions_are_disjoint_and_fit(self):
        with (ROOT / "firmware/partitions.csv").open(newline="", encoding="utf-8") as stream:
            rows = list(csv.reader(line for line in stream if not line.startswith("#")))
        parts = {row[0].strip(): (int(row[3], 0), int(row[4], 0)) for row in rows}
        for name, (start, size) in parts.items():
            self.assertLess(start, FLASH, name)
            self.assertLessEqual(start + size, FLASH, name)
        ranges = sorted((start, start + size, name) for name, (start, size) in parts.items())
        for left, right in zip(ranges, ranges[1:]):
            self.assertLessEqual(left[1], right[0], (left[2], right[2]))
        self.assertEqual(parts["ota_0"][1], 6 * 1024 * 1024)
        self.assertEqual(parts["ota_1"][1], 6 * 1024 * 1024)
        self.assertEqual(parts["nmdata"][1], 2 * 1024 * 1024)
        self.assertEqual(parts["otadata"][1], 0x2000)

    def test_migration_copies_only_state(self):
        with tempfile.TemporaryDirectory() as folder:
            root = pathlib.Path(folder)
            old_path, base_path, new_path = (root / item for item in ("old", "base", "new"))
            old = bytearray(b"\xff" * FLASH)
            old[0x8000:0x8006] = b"nmdata"
            old[0x410000:0x410004] = b"TEST"
            old_path.write_bytes(old)
            base = bytearray(b"\xff" * 0x40000)
            base[0x8000:0x8005] = b"ota_0"
            base_path.write_bytes(base)
            subprocess.run((sys.executable, str(ROOT / "tools/migrate_emulator_flash.py"),
                            "--old-flash", str(old_path), "--new-base", str(base_path),
                            "--output", str(new_path)), check=True, capture_output=True)
            result = new_path.read_bytes()
            self.assertEqual(len(result), FLASH)
            self.assertEqual(result[0xC20000:0xC20004], b"TEST")
            self.assertEqual(result[0x8000:0x8005], b"ota_0")
            self.assertEqual(old_path.read_bytes(), old)
            self.assertEqual(new_path.stat().st_mode & 0o077, 0)

    def test_rebase_can_replace_config_without_losing_monitor_state(self):
        with tempfile.TemporaryDirectory() as folder:
            root = pathlib.Path(folder)
            old = bytearray(b"\xff" * FLASH)
            old[0x8000:0x8005] = b"ota_0"
            old[0x12000:0x12006] = b"OLDKEY"
            old[0xC20000:0xC20005] = b"STATE"
            base = bytearray(b"\xff" * 0x40000)
            base[0x8000:0x8005] = b"ota_0"
            base[0x12000:0x12006] = b"NEWKEY"
            (root / "old").write_bytes(old)
            (root / "base").write_bytes(base)
            subprocess.run((sys.executable, str(ROOT / "tools/rebase_emulator_flash.py"),
                            "--old-flash", str(root / "old"), "--new-base", str(root / "base"),
                            "--output", str(root / "new"), "--replace-config"),
                           check=True, capture_output=True)
            result = (root / "new").read_bytes()
            self.assertEqual(result[0x12000:0x12006], b"NEWKEY")
            self.assertEqual(result[0xC20000:0xC20005], b"STATE")
            self.assertEqual((root / "old").read_bytes(), old)
            self.assertEqual((root / "new").stat().st_mode & 0o077, 0)

    def test_rebase_preserves_config_and_state(self):
        with tempfile.TemporaryDirectory() as folder:
            root = pathlib.Path(folder)
            old_path, base_path, new_path = (root / item for item in ("old", "base", "new"))
            old = bytearray(b"\xff" * FLASH)
            old[0x8000:0x8005] = b"ota_0"
            old[0x12000:0x12006] = b"CONFIG"
            old[0xC20000:0xC20005] = b"STATE"
            old_path.write_bytes(old)
            base = bytearray(b"\xff" * 0x40000)
            base[0x8000:0x8005] = b"ota_0"
            base[0x20000:0x20003] = b"NEW"
            base_path.write_bytes(base)
            subprocess.run((sys.executable, str(ROOT / "tools/rebase_emulator_flash.py"),
                            "--old-flash", str(old_path), "--new-base", str(base_path),
                            "--output", str(new_path)), check=True, capture_output=True)
            result = new_path.read_bytes()
            self.assertEqual(result[0x12000:0x12006], b"CONFIG")
            self.assertEqual(result[0xC20000:0xC20005], b"STATE")
            self.assertEqual(result[0x20000:0x20003], b"NEW")
            self.assertEqual(old_path.read_bytes(), old)


if __name__ == "__main__":
    unittest.main()
