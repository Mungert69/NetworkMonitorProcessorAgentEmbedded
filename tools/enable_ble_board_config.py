#!/usr/bin/env python3
"""Prepare a BLE-capable nmconfig image from a backed-up physical-board NVS partition.

Run with ``tools/idf-local.sh python`` so ESP-IDF 6.1 provides its NVS parser
and partition generator. The input and outputs contain credentials; keep them
in a private directory.
"""

import argparse
import json
import os
import pathlib
import sys

idf_path = os.environ.get("IDF_PATH")
if not idf_path:
    raise RuntimeError("Run through tools/idf-local.sh with ESP-IDF 6.1 selected")
sys.path.insert(0, str(pathlib.Path(idf_path) / "components/nvs_flash/nvs_partition_tool"))

import nvs_parser

from nvs_config import NVS_CONFIG_SIZE, generate


BLE_ENDPOINTS = frozenset(("blebroadcast", "blebroadcastlisten"))


def current_config(partition: bytes) -> dict:
    if len(partition) != NVS_CONFIG_SIZE:
        raise ValueError("nmconfig partition has the wrong size")
    parsed = nvs_parser.NVS_Partition("nmconfig", bytearray(partition))
    entries = [entry for page in parsed.pages for entry in page.entries
               if entry.state == "Written"]
    namespace = [entry for entry in entries if entry.metadata["namespace"] == 0]
    if len(namespace) != 1 or namespace[0].key != "processor":
        raise ValueError("unexpected nmconfig namespace")
    namespace_id = namespace[0].data["value"]
    active = [entry for entry in entries if entry.metadata["namespace"] == namespace_id]
    if any(entry.key != "config" or entry.metadata["type"] not in
           ("blob_index", "blob_data") for entry in active):
        raise ValueError("nmconfig has an additional active key; refusing to discard it")
    indexes = [entry for entry in active if entry.metadata["type"] == "blob_index"]
    if len(indexes) != 1:
        raise ValueError("expected exactly one active configuration blob")
    index = indexes[0]
    count = index.data["chunk_count"]
    start = index.data["chunk_start"]
    chunks = {entry.metadata["chunk_index"]: entry for entry in active
              if entry.metadata["type"] == "blob_data"}
    if count < 1 or len(chunks) != count or set(chunks) != set(range(start, start + count)):
        raise ValueError("configuration blob chunks are incomplete")
    blob = bytearray()
    for number in range(start, start + count):
        chunk = chunks[number]
        blob.extend(b"".join(bytes(child.raw) for child in chunk.children)
                    [:chunk.data["size"]])
    if len(blob) != index.data["size"]:
        raise ValueError("configuration blob length does not match its index")
    config = json.loads(blob)
    if not isinstance(config, dict):
        raise ValueError("configuration is not a JSON object")
    return config


def write_private(path: pathlib.Path, data: bytes) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite {path}")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup", type=pathlib.Path, required=True)
    parser.add_argument("--config-output", type=pathlib.Path, required=True)
    parser.add_argument("--partition-output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    before = current_config(args.backup.read_bytes())
    disabled = before.get("DisabledEndpointTypes")
    if not isinstance(disabled, list) or not all(isinstance(item, str) for item in disabled):
        raise ValueError("DisabledEndpointTypes is missing or invalid")
    if not BLE_ENDPOINTS.issubset(disabled):
        raise ValueError("both BLE types must currently be disabled")
    if before.get("AuthDevice") not in (False, "false") or not all(
            isinstance(before.get(key), str) and before[key]
            for key in ("app_id", "mqtt_username", "mqtt_password", "auth_key", "broker_uri")):
        raise ValueError("board is not fully enrolled; refusing to rewrite configuration")
    after = dict(before)
    after["DisabledEndpointTypes"] = [item for item in disabled if item not in BLE_ENDPOINTS]
    encoded = json.dumps(after, separators=(",", ":"), ensure_ascii=False).encode()
    if len(encoded) > 32 * 1024:
        raise ValueError("updated configuration exceeds provisioned size limit")
    write_private(args.config_output, encoded)
    generate(args.config_output, args.partition_output)
    if current_config(args.partition_output.read_bytes()) != after:
        raise ValueError("generated NVS partition does not reproduce the updated configuration")
    print("BLE endpoint restrictions removed; all other configuration fields retained.")


if __name__ == "__main__":
    main()
