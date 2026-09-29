#!/usr/bin/env python3
"""Create a public, live-configured one-file first-install image."""

import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import zipfile

from nvs_config import generate


FORBIDDEN_CONFIG_KEYS = {
    "wifi_password", "mqtt_password", "mqtt_username", "auth_key",
    "broker_uri", "app_id", "source", "token", "access_token",
}


def public_live_config(template: pathlib.Path) -> bytes:
    config = json.loads(template.read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        raise ValueError("live appsettings template must be a JSON object")
    if config.get("AuthDevice") is not True or config.get("IsQuantumCapable") is not False:
        raise ValueError("live template must enable OAuth enrollment and mark the device non-quantum")
    if not isinstance(config.get("LoadServer"), str) or not config["LoadServer"]:
        raise ValueError("live template must have a LoadServer")
    present = {str(key).lower() for key in config}
    if present.intersection(FORBIDDEN_CONFIG_KEYS):
        raise ValueError("refusing to publish a template containing device credentials")
    config["WiFiSetup"] = True
    config["wifi_ssid"] = ""
    config["wifi_password"] = ""
    return (json.dumps(config, indent=2) + "\n").encode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=pathlib.Path, required=True)
    parser.add_argument("--template", type=pathlib.Path, required=True)
    parser.add_argument("--output-dir", type=pathlib.Path, required=True)
    parser.add_argument("--signing-key", type=pathlib.Path,
                        default=pathlib.Path(os.environ.get(
                            "NM_OTA_SIGNING_KEY",
                            pathlib.Path(__file__).resolve().parents[2] /
                            "securefiles/private-ota-signing-key.pem")))
    args = parser.parse_args()
    build = args.build.resolve(strict=True)
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    version_path = build / "project_description.json"
    project = json.loads(version_path.read_text(encoding="utf-8"))
    version = project.get("project_version", "")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("built firmware has no valid semantic version")
    if (pathlib.Path(__file__).resolve().parents[1] / "firmware/version.txt").read_text(
            encoding="ascii").strip() != version:
        raise ValueError("built firmware version does not match firmware/version.txt")
    app_path = build / "networkmonitor_processor_esp32.bin"
    key_path = args.signing_key.resolve(strict=True)
    if key_path.stat().st_mode & 0o077:
        raise PermissionError("OTA signing key must not be accessible by group/other")
    subprocess.run([
        sys.executable, "-m", "espsecure", "verify-signature", "--version", "2",
        "--keyfile", str(key_path), str(app_path),
    ], check=True)
    image_name = f"networkmonitor-esp32-s3-live-factory-{version}.bin"
    zip_name = "networkmonitor-esp32-s3-live-factory.zip"
    image_path = output_dir / image_name
    zip_path = output_dir / zip_name
    if image_path.exists() or zip_path.exists():
        raise FileExistsError("refusing to overwrite an existing release artifact")

    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="nm-factory-") as temp:
        temp_dir = pathlib.Path(temp)
        config_path = temp_dir / "live-first-boot.json"
        config_path.write_bytes(public_live_config(args.template.resolve(strict=True)))
        config_path.chmod(0o600)
        nvs_path = temp_dir / "nmconfig.bin"
        generate(config_path, nvs_path)
        subprocess.run([
            sys.executable, "-m", "esptool", "--chip", "esp32s3", "merge-bin",
            "--output", str(image_path), "--format", "raw", "--flash-mode", "dio",
            "--flash-freq", "80m", "--flash-size", "16MB",
            "0x0", str(build / "bootloader/bootloader.bin"),
            "0x8000", str(build / "partition_table/partition-table.bin"),
            "0xf000", str(build / "ota_data_initial.bin"),
            "0x12000", str(nvs_path),
            "0x20000", str(app_path),
        ], check=True)

    image_hash = hashlib.sha256(image_path.read_bytes()).hexdigest()
    sums_path = output_dir / "SHA256SUMS.txt"
    sums_path.write_text(f"{image_hash}  {image_name}\n", encoding="ascii")
    with zipfile.ZipFile(zip_path, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(image_path, image_name)
        archive.write(sums_path, "SHA256SUMS.txt")
    image_path.chmod(0o644)
    zip_path.chmod(0o644)
    sums_path.unlink()
    print(f"Created {image_path}")
    print(f"SHA256 {image_hash}")
    print(f"Created {zip_path}")


if __name__ == "__main__":
    main()
