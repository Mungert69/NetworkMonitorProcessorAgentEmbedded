#!/usr/bin/env python3
"""Stage an already signed/verified app using its embedded version and SHA-256.

This checks app metadata and size, not the cryptographic signature. Build/sign
and verify with espsecure first. Never supply a merged/configured flash image.
"""
import argparse
import hashlib
import os
import pathlib
import re
import struct
import tempfile


def describe(content):
    """Return (version, sha256_hex) for a signed ESP-IDF application image."""
    if not 1024 <= len(content) <= 6*1024*1024 or content[0] != 0xe9 or \
            struct.unpack_from("<I", content, 32)[0] != 0xabcd5432:
        raise ValueError("Expected an ESP-IDF application, not a merged flash image")
    version = content[48:80].split(b"\0", 1)[0].decode("ascii")
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version) or \
            any(int(part) > 0xffffffff for part in version.split(".")):
        raise ValueError("Invalid embedded firmware version")
    return version, hashlib.sha256(content).hexdigest()


def artifact_name(content):
    version, digest = describe(content)
    return f"networkmonitor-esp32-s3-{version}-{digest}.bin"


def stage(source, directory):
    content = source.read_bytes()
    name = artifact_name(content)
    directory = directory.resolve(strict=True)
    destination = directory/name
    if destination.is_symlink():
        raise ValueError("Refusing a symlink destination")
    if destination.exists():
        if destination.read_bytes() != content:
            raise ValueError("Existing artifact contents do not match")
        return destination
    fd, temporary = tempfile.mkstemp(prefix=".firmware-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o644)
        # Publish atomically without replacing any existing destination.
        os.link(temporary, destination)
    finally:
        os.unlink(temporary)
    return destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=pathlib.Path, required=True)
    parser.add_argument("--directory", type=pathlib.Path, required=True)
    options = parser.parse_args()
    print(stage(options.app, options.directory))
