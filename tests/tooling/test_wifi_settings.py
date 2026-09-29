import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "tools"))

#!/usr/bin/env python3
"""Offline tests for private Wi-Fi provisioning input validation."""

import pathlib
import tempfile
import unittest

from wifi_settings import wifi_settings


class WifiSettingsTests(unittest.TestCase):
    def test_emulator_defaults(self):
        self.assertEqual(wifi_settings(None, None), ("myssid", "mypassword"))

    def test_physical_wifi_password_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "password"
            path.write_text("correct-horse-battery\n", encoding="utf-8")
            path.chmod(0o600)
            self.assertEqual(wifi_settings("Test-2G", path),
                             ("Test-2G", "correct-horse-battery"))

    def test_missing_or_public_password_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "password"
            path.write_text("abcdefgh", encoding="utf-8")
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                wifi_settings("Test-2G", path)
            with self.assertRaises(ValueError):
                wifi_settings("Test-2G", path.parent / "missing")
            with self.assertRaises(ValueError):
                wifi_settings("Test-2G", None)

    def test_length_limits(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "password"
            path.write_text("short", encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaises(ValueError):
                wifi_settings("Test-2G", path)
            path.write_text("abcdefgh", encoding="utf-8")
            with self.assertRaises(ValueError):
                wifi_settings("x" * 33, path)


if __name__ == "__main__":
    unittest.main()
