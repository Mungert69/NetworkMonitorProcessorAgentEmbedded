import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "tools"))

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from prepare_config import configuration as generate

TEMPLATES = pathlib.Path(__file__).resolve().parents[2] / "firmware/config"

def configuration(ssid, password, name=None, app_name=None, environment="live"):
    return generate(ssid, password, name, app_name, TEMPLATES / f"appsettings-{environment}.json")


class ConfigTests(unittest.TestCase):
    def test_environment_selects_discovery_without_changing_trust_or_auth(self):
        live = configuration("wifi", "password", environment="live")
        dev = configuration("wifi", "password", environment="dev")
        self.assertEqual(live["LoadServer"], "loadserver.readyforquantum.com")
        self.assertEqual(dev.pop("LoadServer"), "devloadserver.readyforquantum.com")
        live.pop("LoadServer")
        self.assertEqual(dev, live)
        with self.assertRaises(FileNotFoundError):
            configuration("wifi", "password", environment="invalid")

    def test_default_example_uses_native_enrollment(self):
        for environment in ("dev", "live"):
            template = json.loads((TEMPLATES / f"appsettings-{environment}.json").read_text())
            self.assertTrue(template["AuthDevice"])
            self.assertNotIn("wifi_password", template)

    def test_defaults_have_no_broker_credentials(self):
        config = configuration("wifi", "password")
        self.assertIs(config["AuthDevice"], True)
        self.assertIs(config["IsQuantumCapable"], False)
        self.assertNotIn("mqtt_password", config)
        self.assertNotIn("auth_key", config)
        self.assertNotIn("app_id", config)
        self.assertNotIn("DeviceName", config)  # hardware MAC provides stable default
        self.assertEqual(config["max_monitors"], 50)
        self.assertEqual(config["MaxTaskQueueSize"], 4)
        self.assertEqual(config["MaxOutstandingEndpointOperations"], 4)

    def test_selected_file_controls_endpoints(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "custom.json"
            path.write_text(json.dumps({"LoadServer": "custom.invalid", "AuthDevice": True,
                                        "MaxTaskQueueSize": 8,
                                        "MaxOutstandingEndpointOperations": 1}))
            self.assertEqual(generate("wifi", "password", config_path=path)["MaxTaskQueueSize"], 8)
            self.assertEqual(generate("wifi", "password", config_path=path)["MaxOutstandingEndpointOperations"], 1)
            self.assertEqual(generate("wifi", "password", config_path=path)["LoadServer"],
                             "custom.invalid")
        with self.assertRaises(ValueError):
            generate("wifi", "password")

    def test_name_limits(self):
        for name in ("", "x"*129, "bad\nname", "é"*65):
            with self.assertRaises(ValueError):
                configuration("wifi", "password", name)
        self.assertEqual(configuration("wifi", "password", "test") ["DeviceName"], "test")

    def test_app_name(self):
        config = configuration("wifi", "password", app_name="QSAX")
        self.assertEqual(config["AppName"], "QSAX")
        self.assertNotIn("DeviceName", config)
        for name in ("x"*129, "bad\nname"):
            with self.assertRaises(ValueError):
                configuration("wifi", "password", app_name=name)

    def test_private_output_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory)/"private.json"
            command = [sys.executable, str(TEMPLATES.parents[1] / "tools/prepare_config.py"),
                       "--config", str(TEMPLATES / "appsettings-dev.json"), "--output", str(path)]
            subprocess.run(command, check=True, capture_output=True)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            original = path.read_bytes()
            self.assertTrue(json.loads(original)["AuthDevice"])
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertEqual(path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
