import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / "tools/check-component-updates.py"
SPEC = importlib.util.spec_from_file_location("check_component_updates", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ComponentUpdateTests(unittest.TestCase):
    def test_version_order_is_numeric(self):
        self.assertGreater(MODULE.version_tuple("1.10.0"), MODULE.version_tuple("1.9.9"))

    def test_rejects_unexpected_version_strings(self):
        for value in ("1.2", "1.2.0-rc1", "1.2.0 && true"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                MODULE.version_tuple(value)

    def test_reads_exact_component_pin(self):
        manifest = 'dependencies:\n  espressif/brotli: "1.2.0"\n  espressif/mqtt: "1.1.0"\n'
        self.assertEqual(MODULE.current_pin(manifest, "brotli"), "1.2.0")
        self.assertEqual(MODULE.current_pin(manifest, "mqtt"), "1.1.0")
        with self.assertRaises(ValueError):
            MODULE.current_pin(manifest, "missing")


if __name__ == "__main__":
    unittest.main()
