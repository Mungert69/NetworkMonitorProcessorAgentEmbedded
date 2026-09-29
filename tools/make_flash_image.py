#!/usr/bin/env python3
"""Provision a private ESP32 emulator flash image; never print its credentials."""

import argparse
import os
import pathlib
import subprocess

from nvs_config import generate


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=pathlib.Path, required=True)
    parser.add_argument("--build", type=pathlib.Path, required=True)
    parser.add_argument("--output-dir", type=pathlib.Path, required=True)
    args = parser.parse_args()
    build = args.build.resolve()
    destination = args.output_dir.resolve(strict=True)
    if any(destination.iterdir()):
        raise ValueError("Output directory must be empty; never overwrite enrolled flash")
    os.umask(0o077)
    output = destination / "merged-binary.bin"
    partition = destination / "nmconfig.bin"
    generate(args.config, partition)
    subprocess.run(("python", "-m", "esptool", "--chip", "esp32s3", "merge_bin",
                    "-o", str(output), "-f", "raw", "--flash_mode", "dio",
                    "--flash_freq", "80m", "--flash_size", "16MB",
                    "0x0", str(build / "bootloader/bootloader.bin"),
                    "0x8000", str(build / "partition_table/partition-table.bin"),
                    "0x12000", str(partition),
                    "0x20000", str(build / "networkmonitor_processor_esp32.bin")), check=True)
    os.chmod(partition, 0o600)
    os.chmod(output, 0o600)
    print("Built provisioned emulator image (configuration values hidden)")


if __name__ == "__main__":
    main()
