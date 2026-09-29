"""Validate private Wi-Fi settings for native ESP32 provisioning."""

import pathlib


def wifi_settings(ssid: str | None, password_file: pathlib.Path | None) -> tuple[str, str]:
    if (ssid is None) != (password_file is None):
        raise ValueError("--wifi-ssid and --wifi-password-file must be supplied together")
    if ssid is None:
        return "myssid", "mypassword"  # Emulator network only.
    if not 1 <= len(ssid.encode("utf-8")) <= 32 or "\x00" in ssid:
        raise ValueError("Wi-Fi SSID must be 1–32 bytes without NUL")
    if not password_file.is_file():
        raise ValueError("Wi-Fi password file is missing")
    if password_file.stat().st_mode & 0o077:
        raise ValueError("Wi-Fi password file must be private (chmod 600)")
    password = password_file.read_text(encoding="utf-8").rstrip("\r\n")
    if not 8 <= len(password.encode("utf-8")) <= 63 or "\x00" in password:
        raise ValueError("Wi-Fi password must be 8–63 bytes without NUL")
    return ssid, password
