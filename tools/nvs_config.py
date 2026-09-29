"""Generate the private nmconfig partition from a device JSON configuration."""

import csv
import argparse
import json
import os
import pathlib
import subprocess
import tempfile

NVS_CONFIG_SIZE = 0xE000


def generate(config_path: pathlib.Path, output_path: pathlib.Path) -> None:
    config = config_path.resolve(strict=True)
    output = output_path.resolve()
    raw = config.read_bytes()
    if len(raw) < 2 or len(raw) > 32 * 1024 or not isinstance(json.loads(raw), dict):
        raise ValueError("configuration must be a JSON object below 32 KiB")
    idf = pathlib.Path(os.environ["IDF_PATH"])
    generator = idf / "components/nvs_flash/nvs_partition_generator/nvs_partition_gen.py"
    with tempfile.TemporaryDirectory(prefix="nm-config-", dir=output.parent) as folder:
        csv_path = pathlib.Path(folder) / "config.csv"
        with csv_path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(("key", "type", "encoding", "value"))
            writer.writerow(("processor", "namespace", "", ""))
            writer.writerow(("config", "file", "binary", str(config)))
        subprocess.run(("python", str(generator), "generate", str(csv_path),
                        str(output), hex(NVS_CONFIG_SIZE)), check=True)
    os.chmod(output, 0o600)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    options = parser.parse_args()
    generate(options.config, options.output)
    print("Private nmconfig partition generated (values hidden)")
