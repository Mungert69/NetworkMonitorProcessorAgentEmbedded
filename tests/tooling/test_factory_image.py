import sys
import json
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

import unittest
from package_factory_image import public_live_config


class FactoryImageConfigTests(unittest.TestCase):
    def test_live_template_enables_interactive_wifi_without_device_secrets(self):
        with tempfile.TemporaryDirectory() as folder:
            template = Path(folder) / "live.json"
            template.write_text(
                '{"AuthDevice":true,"IsQuantumCapable":false,'
                '"LoadServer":"loadserver.readyforquantum.com"}',
                encoding="utf-8",
            )
            result = json.loads(public_live_config(template))
        self.assertTrue(result["AuthDevice"])
        self.assertFalse(result["IsQuantumCapable"])
        self.assertTrue(result["WiFiSetup"])
        self.assertEqual(result["wifi_ssid"], "")
        self.assertEqual(result["wifi_password"], "")
        self.assertNotIn("auth_key", result)
        self.assertNotIn("mqtt_password", result)

    def test_refuses_device_credentials_in_template(self):
        with tempfile.TemporaryDirectory() as folder:
            template = Path(folder) / "live.json"
            template.write_text(
                '{"AuthDevice":true,"IsQuantumCapable":false,'
                '"LoadServer":"example.test","mqtt_password":"secret"}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "credentials"):
                public_live_config(template)

    def test_quantum_capable_live_template(self):
        with tempfile.TemporaryDirectory() as folder:
            template = Path(folder) / "live.json"
            template.write_text('{"AuthDevice":true,"IsQuantumCapable":true,"LoadServer":"example.test"}')
            self.assertTrue(json.loads(public_live_config(template))["IsQuantumCapable"])

    def test_requires_live_oauth_identity_settings(self):
        with tempfile.TemporaryDirectory() as folder:
            template = Path(folder) / "live.json"
            template.write_text('{"AuthDevice":true}', encoding="utf-8")
            with self.assertRaises(ValueError):
                public_live_config(template)


if __name__ == "__main__":
    unittest.main()
