#!/usr/bin/env python3
"""Report newer stable library releases for exact dependency pins.

This is notification-only: updating the manifest, lockfile and firmware remains
an explicit reviewed change. Never silently change an OTA build dependency.
"""

import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "firmware/main/idf_component.yml"
COMPONENTS = ("brotli", "mqtt")
WOLFSSL_REPOSITORY = "wolfSSL/wolfssl"


def version_tuple(version: str) -> tuple[int, ...]:
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError(f"unexpected registry version: {version!r}")
    return tuple(map(int, version.split(".")))


def current_pin(text: str, name: str) -> str:
    match = re.search(rf'^\s*espressif/{re.escape(name)}:\s*["\']?(\d+\.\d+\.\d+)', text, re.M)
    if not match:
        raise ValueError(f"missing exact espressif/{name} pin")
    return match.group(1)


def wolfssl_version_tuple(tag: str) -> tuple[int, ...]:
    """Parse only wolfSSL's stable release tags (for example v5.9.2-stable)."""
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)-stable", tag)
    if not match:
        raise ValueError(f"unexpected wolfSSL stable tag: {tag!r}")
    return tuple(map(int, match.groups()))


def main() -> int:
    manifest = MANIFEST.read_text(encoding="utf-8")
    updates = []
    for name in COMPONENTS:
        pinned = current_pin(manifest, name)
        url = f"https://components.espressif.com/api/components/espressif/{name}"
        with urlopen(url, timeout=15) as response:
            registry = json.load(response)
        versions = [v["version"] for v in registry["versions"]
                    if re.fullmatch(r"\d+\.\d+\.\d+", v["version"])]
        if not versions:
            raise ValueError(f"no stable versions found for {name}")
        latest = max(versions, key=version_tuple)
        print(f"espressif/{name}: pinned={pinned} latest={latest}")
        if version_tuple(latest) > version_tuple(pinned):
            updates.append(f"- espressif/{name}: {pinned} → {latest}")
    pinned_yyjson = subprocess.check_output(
        ["git", "-C", str(ROOT / "third_party/yyjson"), "describe", "--exact-match", "--tags"],
        text=True,
    ).strip()
    version_tuple(pinned_yyjson)
    with urlopen("https://api.github.com/repos/ibireme/yyjson/releases/latest", timeout=15) as response:
        latest_yyjson = json.load(response)["tag_name"]
    print(f"yyjson: pinned={pinned_yyjson} latest={latest_yyjson}")
    if version_tuple(latest_yyjson) > version_tuple(pinned_yyjson):
        updates.append(f"- yyjson: {pinned_yyjson} → {latest_yyjson}")

    pinned_wolfssl = subprocess.check_output(
        ["git", "-C", str(ROOT / "third_party/wolfssl"), "describe", "--exact-match", "--tags"],
        text=True,
    ).strip()
    pinned_wolfssl_version = wolfssl_version_tuple(pinned_wolfssl)
    wolfssl_url = f"https://api.github.com/repos/{WOLFSSL_REPOSITORY}/releases/latest"
    with urlopen(wolfssl_url, timeout=15) as response:
        latest_wolfssl = json.load(response)["tag_name"]
    latest_wolfssl_version = wolfssl_version_tuple(latest_wolfssl)
    print(f"wolfSSL: pinned={pinned_wolfssl} latest={latest_wolfssl}")
    if latest_wolfssl_version > pinned_wolfssl_version:
        updates.append(f"- wolfSSL: {pinned_wolfssl} → {latest_wolfssl}")

    if updates:
        print("New stable component releases:\n" + "\n".join(updates))
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, KeyError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"component update check failed: {exc}", file=sys.stderr)
        sys.exit(2)
