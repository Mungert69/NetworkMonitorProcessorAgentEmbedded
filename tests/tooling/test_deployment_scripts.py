import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "tools"))

"""Deployment regression tests; no real Docker, broker or emulator is started."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import fcntl

ESP = Path(__file__).resolve().parents[2] / "tools"


class DeploymentTests(unittest.TestCase):
    def test_explicit_instance_required(self):
        result = subprocess.run(["bash", str(ESP / "run-emulator.sh")], capture_output=True)
        self.assertEqual(result.returncode, 2)

    def test_dev_live_state_isolation_and_persistence(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            emulator = root / "emulator"
            emulator.write_text("""#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
pathlib.Path(os.environ["CAPTURE"]).write_text(json.dumps(args))
if "--save-state" in args:
    path = pathlib.Path(args[args.index("--firmware") + 1])
    with path.open("ab") as output:
        output.write(b"-enrolled")
""")
            emulator.chmod(0o700)
            for name in ("dev", "live"):
                instance = root / name
                instance.mkdir()
                (instance / "merged-binary.bin").write_bytes(name.encode())
                env = dict(os.environ, ESP_EMU_BIN=str(emulator), CAPTURE=str(root / "args"))
                env.pop("NM_ESP_PERSIST", None)
                command = ["bash", str(ESP / "run-emulator.sh"), str(instance)]
                subprocess.run(command, env=env, check=True, capture_output=True)
                args = json.loads((root / "args").read_text())
                self.assertIn("--save-state", args)
                self.assertNotIn("--exit-on", args)
                runtime = instance / "runtime-flash.bin"
                self.assertEqual(runtime.read_bytes(), name.encode() + b"-enrolled")
                self.assertEqual(runtime.stat().st_mode & 0o777, 0o600)
                # A new build must not replace the enrolled instance.
                (instance / "merged-binary.bin").write_bytes(b"replacement")
                subprocess.run(command, env=env, check=True, capture_output=True)
                self.assertEqual(runtime.read_bytes(), name.encode() + b"-enrolled-enrolled")
                with (instance / ".lock").open("w") as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    blocked = subprocess.run(command, env=env, capture_output=True)
                    self.assertNotEqual(blocked.returncode, 0)
                self.assertEqual(runtime.read_bytes(), name.encode() + b"-enrolled-enrolled")

    def test_provision_refuses_existing_instance(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            config = root / "config.json"
            config.write_text("{}")
            instance = root / "existing"
            instance.mkdir()
            state = instance / "runtime-flash.bin"
            state.write_bytes(b"keep-enrolled-state")
            result = subprocess.run(["bash", str(ESP / "provision-emulator.sh"),
                                     "--config", str(config), "--instance", str(instance)],
                                    capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(state.read_bytes(), b"keep-enrolled-state")

    def test_build_does_not_provision_config(self):
        script = (ESP / "build-firmware.sh").read_text()
        self.assertNotIn("NM_ESP_CONFIG", script)
        self.assertNotIn("make_flash_image", script)
        self.assertNotIn("private-config", script)


if __name__ == "__main__":
    unittest.main()
