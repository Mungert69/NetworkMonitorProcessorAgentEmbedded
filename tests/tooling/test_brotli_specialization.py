import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("specialize_brotli", ROOT / "tools/specialize_brotli.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class BrotliSpecializationTests(unittest.TestCase):
    def test_changed_dependency_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "changed"):
            module.specialize(b"different upstream source")

    def test_pinned_generation(self):
        path = ROOT / "firmware/managed_components/espressif__brotli/brotli/c/enc/encode.c"
        if not path.exists():
            self.skipTest("Build firmware to fetch managed Brotli source")
        result = module.specialize(path.read_bytes())
        self.assertNotIn("s->params.quality", result)
        self.assertNotIn("BrotliInitSharedEncoderDictionary(&params->dictionary)", result)
        self.assertIn("if (quality != 0) return BROTLI_FALSE;", result)
        self.assertIn("BrotliCompressFragmentFast(", result)
