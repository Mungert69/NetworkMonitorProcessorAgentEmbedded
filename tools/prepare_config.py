#!/usr/bin/env python3
"""Add private Wi-Fi settings to an explicitly selected appsettings template."""
import argparse
import json
import os
import pathlib
from wifi_settings import wifi_settings


def configuration(ssid, password, name=None, app_name=None, config_path=None):
    if config_path is None:
        raise ValueError("An appsettings template is required")
    if name is not None and (not name or len(name.encode()) > 128 or
                             any(ord(c) < 32 for c in name)):
        raise ValueError("DeviceName must be 1..128 bytes without control characters")
    if app_name is not None and (len(app_name.encode()) > 128 or
                                any(ord(c) < 32 for c in app_name)):
        raise ValueError("AppName must be at most 128 bytes without control characters")
    result = json.loads(pathlib.Path(config_path).read_text())
    if not isinstance(result, dict):
        raise ValueError("Configuration must be a JSON object")
    result.update(wifi_ssid=ssid, wifi_password=password)
    if name is not None:
        result["DeviceName"] = name
    if app_name is not None:
        result["AppName"] = app_name
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wifi-ssid")
    parser.add_argument("--wifi-password-file", type=pathlib.Path)
    parser.add_argument("--device-name")
    parser.add_argument("--app-name")
    parser.add_argument("--config", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    ssid, password = wifi_settings(args.wifi_ssid, args.wifi_password_file)
    config = configuration(ssid, password, args.device_name, args.app_name, args.config)
    # Never overwrite an existing provisioned identity, or follow a symlink.
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(config, stream, indent=2)
        stream.write("\n")
    print("Created private OAuth device configuration; credentials not printed")


if __name__ == "__main__":
    main()
