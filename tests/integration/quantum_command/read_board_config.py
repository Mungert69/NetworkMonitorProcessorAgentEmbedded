"""Read only nmconfig with IDF's NVS parser; private output stays outside repo.

Optionally remove the former explicit QuantumCert restriction for this test.
Never prints passwords, JWTs or AuthKeys. Does not touch the board/database.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("image", type=Path)
parser.add_argument("output", type=Path)
parser.add_argument("--enable-quantumcert", action="store_true")
parser.add_argument("--enable-command-processors", action="store_true",
                    help="Explicitly enable the six implemented command processors for a test board")
args = parser.parse_args()
root = Path(__file__).resolve().parents[3]
output = args.output.resolve()
if output == root or root in output.parents:
    parser.error("Private config output must be outside repository")
os.umask(0o077)
sys.path.insert(0, str(Path(os.environ["IDF_PATH"]) / "components/nvs_flash/nvs_partition_tool"))
from nvs_parser import NVS_Partition
partition = NVS_Partition("nmconfig", bytearray(args.image.read_bytes()))
entries = [entry for page in sorted(partition.pages, key=lambda p: p.header["page_index"])
           for entry in page.entries if entry.state == "Written"]
namespace = [entry.data["value"] for entry in entries if entry.metadata["namespace"] == 0
             and entry.key == "processor"][-1]
indices = [entry for entry in entries if entry.metadata["namespace"] == namespace
           and entry.key == "config" and entry.metadata["type"] == "blob_index"]
index = indices[-1]
parts = {}
for entry in entries:
    if entry.metadata["namespace"] == namespace and entry.key == "config" and entry.metadata["type"] == "blob_data":
        parts[entry.metadata["chunk_index"]] = b"".join(bytes(child.raw) for child in entry.children)[:entry.data["size"]]
data = b"".join(parts[i] for i in range(index.data["chunk_start"], index.data["chunk_start"] + index.data["chunk_count"]))
if len(data) != index.data["size"]:
    raise ValueError("Incomplete NVS config")
config = json.loads(data)
if args.enable_quantumcert:
    config["DisabledCommands"] = [value for value in config.get("DisabledCommands", [])
                                  if value.lower() not in ("quantumcert", "quantum-cert")]
if args.enable_command_processors:
    implemented = {"quantumcert", "quantum-cert", "quantumconnect", "quantum",
                   "quantumportscanner", "quantum-scan", "quantuminfo", "openssl", "nmap"}
    config["DisabledCommands"] = [value for value in config.get("DisabledCommands", [])
                                  if value.lower() not in implemented]
output.write_text(json.dumps(config, indent=2) + "\n")
output.chmod(0o600)
payload = config["mqtt_password"].split(".")[1]
claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
scopes = claims.get("scope_as_list", [])
print("AppID:", config["app_id"])
print("Broker:", config["broker_uri"])
for route in ("processor.out.scan-ran", "processor.out.scan-ack"):
    print(route, "scope present:", any(scope.endswith("/" + route) for scope in scopes))
print("Private config prepared; credentials hidden")
