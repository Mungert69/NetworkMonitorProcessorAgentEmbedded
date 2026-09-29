"""Path-contract tests: mock EIM, never flash a board or contact a broker."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class LayoutTests(unittest.TestCase):
    def test_single_production_sdkconfig_uses_picolibc_without_compatibility(self):
        configs = sorted(path.name for path in (ROOT / "firmware").glob("sdkconfig*"))
        self.assertEqual(configs, ["sdkconfig.production"])
        config = (ROOT / "firmware/sdkconfig.production").read_text()
        self.assertIn("CONFIG_LIBC_PICOLIBC=y", config)
        self.assertIn("# CONFIG_LIBC_NEWLIB is not set", config)
        self.assertIn("# CONFIG_LIBC_PICOLIBC_NEWLIB_COMPATIBILITY is not set", config)
        self.assertNotIn("NM_IDF_SDKCONFIG", (ROOT / "tools/build-firmware.sh").read_text())

    def test_no_duplicate_processor_and_native_headers_resolve(self):
        self.assertFalse((ROOT / "src").exists())
        self.assertFalse((ROOT / "include").exists())
        cmake = (ROOT / "CMakeLists.txt").read_text()
        self.assertNotIn("nm_core", cmake)
        self.assertNotIn("libmosquitto", cmake)
        self.assertTrue((ROOT / "firmware/main/nm_capabilities.h").is_file())
        self.assertIn('#include "nm_capabilities.h"',
                      (ROOT / "firmware/main/enrollment_registration.c").read_text())

    def test_scripts_parse_and_cli_tools_resolve_outside_repo(self):
        import sys
        for script in list((ROOT / "tools").glob("*.sh")) + list((ROOT / "tests/integration").glob("*.sh")):
            subprocess.run(["bash", "-n", str(script)], check=True)
            self.assertTrue(os.access(script, os.X_OK), script)
        for name in ("prepare_config.py", "stage_firmware.py", "nvs_config.py",
                     "make_flash_image.py", "device_preflight.py",
                     "migrate_emulator_flash.py", "rebase_emulator_flash.py"):
            subprocess.run([sys.executable, str(ROOT / "tools" / name), "--help"],
                           cwd="/tmp", check=True, capture_output=True)

    def test_build_and_provision_use_local_idf_runner(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            repo = directory / "repo"
            shutil.copytree(ROOT / "tools", repo / "tools")
            (repo / "firmware/build").mkdir(parents=True)
            fakebin = directory / "bin"
            fakebin.mkdir()
            eim = fakebin / "eim"
            eim.write_text(
                "#!/usr/bin/env python3\nimport json,os,sys\n"
                "open(os.environ['CAPTURE'],'w').write(json.dumps(sys.argv[1:]))\n")
            eim.chmod(0o700)
            key = directory / "original-key.pem"
            key.write_text("synthetic key fixture")
            key.chmod(0o600)
            capture = directory / "args.json"
            env = dict(os.environ, PATH=str(fakebin) + os.pathsep + os.environ["PATH"],
                       EIM_BIN=str(eim), CAPTURE=str(capture), NM_OTA_SIGNING_KEY=str(key))
            subprocess.run([str(repo / "tools/build-firmware.sh")],
                           cwd=directory, env=env, check=True, capture_output=True)
            args = json.loads(capture.read_text())
            self.assertEqual(args[0], "run")
            self.assertIn("idf.py", args[1])
            self.assertIn("SDKCONFIG=sdkconfig.production", args[1])
            self.assertIn("v6.1", args[2])
            self.assertFalse((repo / "firmware/private-ota-signing-key.pem").exists())
            config = directory / "private.json"
            config.write_text("{}")
            instance = directory / "instance"
            subprocess.run([str(repo / "tools/provision-emulator.sh"),
                            "--config", str(config), "--instance", str(instance)],
                           cwd=directory, env=env, check=True, capture_output=True)
            args = json.loads(capture.read_text())
            self.assertEqual(args[0], "run")
            self.assertIn("make_flash_image.py", args[1])
            self.assertIn("v6.1", args[2])
            self.assertEqual(key.read_text(), "synthetic key fixture")
            # Key generation must preserve an existing signing key.
            capture.unlink()
            subprocess.run([str(repo / "tools/generate-dev-signing-key.sh")],
                           cwd=directory, env=env, check=True, capture_output=True)
            self.assertFalse(capture.exists())


if __name__ == "__main__":
    unittest.main()
