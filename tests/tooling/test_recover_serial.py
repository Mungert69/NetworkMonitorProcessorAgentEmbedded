import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "tools"))

import struct
import unittest

import recover_serial
from stage_firmware import describe


def fixture(version="0.1.14", size=2048):
    content = bytearray(size)
    content[0] = 0xE9
    struct.pack_into("<I", content, 32, 0xABCD5432)
    content[48:48 + len(version)] = version.encode()
    return bytes(content)


class DescribeTests(unittest.TestCase):
    def test_reads_embedded_version_and_digest(self):
        version, digest = describe(fixture())
        self.assertEqual(version, "0.1.14")
        self.assertEqual(len(digest), 64)


class RecoverSerialTests(unittest.TestCase):
    def test_write_flash_selects_ota_0_and_otadata(self):
        args = recover_serial.write_flash_args("/work/app.bin", "/work/otadata.bin", "/dev/ttyACM0")
        self.assertIn(hex(0x20000), args)
        self.assertIn(hex(0xF000), args)
        self.assertIn("/work/app.bin", args)
        self.assertIn("/work/otadata.bin", args)
        self.assertEqual(args[args.index("/dev/ttyACM0") - 1], "-p")

    def test_parse_mac(self):
        output = "Chip is ESP32-S3\nMAC: aa:bb:cc:11:22:33\n"
        self.assertEqual(recover_serial.parse_mac(output), "aa:bb:cc:11:22:33")
        with self.assertRaises(ValueError):
            recover_serial.parse_mac("no mac here")


if __name__ == "__main__":
    unittest.main()
