import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "tools"))

import pathlib
import struct
import tempfile
import unittest
from stage_firmware import artifact_name, stage


def fixture(version="0.1.7"):
    content = bytearray(2048)
    content[0] = 0xe9
    struct.pack_into("<I", content, 32, 0xabcd5432)
    content[48:48+len(version)] = version.encode()
    return bytes(content)


class StageFirmwareTests(unittest.TestCase):
    def test_embedded_version_and_content_address(self):
        name = artifact_name(fixture())
        self.assertTrue(name.startswith("networkmonitor-esp32-s3-0.1.7-"))
        self.assertEqual(len(name.split("-")[-1]), 68)
        self.assertNotEqual(name, artifact_name(fixture("0.1.8")))

    def test_invalid_input(self):
        for content in (b"", b"x"*2048, fixture("01.2.3"), fixture("../bad"),
                        fixture("4294967296.0.0"), fixture()+b"x"*(6*1024*1024)):
            with self.assertRaises(ValueError):
                artifact_name(content)

    def test_stage_idempotent_but_never_overwrites_or_follows_symlink(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = pathlib.Path(folder)
            source = directory/"app.bin"
            source.write_bytes(fixture())
            destination = stage(source, directory)
            self.assertEqual(destination.read_bytes(), fixture())
            self.assertEqual(destination.stat().st_mode & 0o777, 0o644)
            self.assertEqual(stage(source,directory), destination)
            destination.write_bytes(b"wrong")
            with self.assertRaises(ValueError): stage(source,directory)
            destination.unlink()
            destination.symlink_to(source)
            with self.assertRaises(ValueError): stage(source,directory)


if __name__ == "__main__":
    unittest.main()
