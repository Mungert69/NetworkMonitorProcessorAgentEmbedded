import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "tools"))

#!/usr/bin/env python3
"""Offline tests for the fail-closed physical-device preflight parser."""

import unittest

from device_preflight import parse_identification, security_state


class PreflightTests(unittest.TestCase):
    def test_identifies_expected_flash_and_mac(self):
        self.assertEqual(parse_identification("Detected flash size: 16MB", "MAC: aa:bb:cc:dd:ee:ff"),
                         (16, "aa:bb:cc:dd:ee:ff"))

    def test_unknown_identification_fails(self):
        with self.assertRaises(ValueError):
            parse_identification("Manufacturer: something", "MAC: aa:bb:cc:dd:ee:ff")

    def test_unset_security_fuses_pass(self):
        security_state({name: {"raw_value": "0x0", "readable": True} for name in
                        ("SECURE_BOOT_EN", "SPI_BOOT_CRYPT_CNT", "DIS_DOWNLOAD_MODE")})

    def test_set_or_missing_security_fuses_fail(self):
        base = {name: {"raw_value": "0x0", "readable": True} for name in
                ("SECURE_BOOT_EN", "SPI_BOOT_CRYPT_CNT", "DIS_DOWNLOAD_MODE")}
        for name in list(base):
            changed = dict(base)
            changed[name] = {"raw_value": "0x1", "readable": True}
            with self.assertRaises(ValueError):
                security_state(changed)
            changed[name] = {"raw_value": "0x0", "readable": False}
            with self.assertRaises(ValueError):
                security_state(changed)
            changed.pop(name)
            with self.assertRaises(ValueError):
                security_state(changed)


if __name__ == "__main__":
    unittest.main()
