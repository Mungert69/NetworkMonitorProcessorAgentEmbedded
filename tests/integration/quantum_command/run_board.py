"""Signed command/response tests against an enrolled dev board and local broker.

Requires pika, private config, original .NET-generated fixtures, Docker data and
devrabbitmq. Creates/deletes only its own short-lived broker test queue.
Does not modify any database, device configuration, or existing queues.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time
import uuid
import pika

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--config", required=True, type=Path)
parser.add_argument("--fixtures", required=True, type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parents[3]
for path in (args.config.resolve(), args.fixtures.resolve()):
    if path == root or root in path.parents:
        parser.error("Private input/fixtures must stay outside repository")
config = json.loads(args.config.read_text())
app = config["app_id"]
route = "u_" + config["mqtt_username"] + "_p_" + hashlib.sha256(app.encode()).hexdigest()
container = json.loads(subprocess.check_output(["docker", "inspect", "data"]))[0]
env = dict(value.split("=", 1) for value in container["Config"]["Env"] if "=" in value)
connection = pika.BlockingConnection(pika.ConnectionParameters(
    "127.0.0.1", 5672, "/vhostuser",
    pika.PlainCredentials("usercommonxf1", env["RabbitPassword"]),
    socket_timeout=10, blocked_connection_timeout=10, heartbeat=60))
channel = connection.channel()
channel.confirm_delivery()
queue = "quantumcmd.test." + uuid.uuid4().hex

def fixture(name):
    return json.loads((args.fixtures / (name + ".json")).read_text())

def send(name, corrupt=False):
    body = (args.fixtures / (name + ".json")).read_text()
    if corrupt:
        event = json.loads(body)
        event["data"]["Arguments"] = "--target tampered.invalid"
        body = json.dumps(event)
    operation = ("getCmdProcessorList" if name == "list" else
                 "getCmdProcessorHelp" if name == "help" else
                 "cancelCommand" if name == "cancel-request" else "processorCommand")
    channel.basic_publish("monitorProcessor.commands.v2", route + "." + operation,
        body, pika.BasicProperties(content_type="application/cloudevents+json"),
        mandatory=True)

def receive(name, timeout=60):
    expected = fixture(name)["data"]
    deadline = time.monotonic() + timeout
    acks = 0
    while time.monotonic() < deadline:
        method, _, body = channel.basic_get(queue, auto_ack=True)
        if method is None:
            connection.process_data_events(time_limit=0.1)
            continue
        data = json.loads(body)["data"]
        if data.get("AgentID") != app or data.get("MessageID") != expected["MessageID"]:
            continue
        assert data["AuthKey"] == config["auth_key"]
        assert data["Type"] == expected["Type"]
        assert data["LlmServiceObj"]["RootMessageID"] == "quantumcmd-test-root"
        if method.routing_key == "processor.out.scan-ack":
            acks += 1
        else:
            assert acks, "Result arrived without acknowledgement"
            return data
    raise RuntimeError("No command result within timeout (check OAuth scopes and serial log)")

created = False
try:
    channel.queue_declare(queue, durable=False, exclusive=True, arguments={"x-expires": 300000})
    created = True
    for key in ("processor.out.scan-ran", "processor.out.scan-ack"):
        channel.queue_bind(queue, "monitorProcessor.mqtt.v1", routing_key=key)
    checks = {
        "list": (True, "QuantumCert"),
        "help": (True, "--target"),
        "pqc": (True, "ML-DSA-65"),
        "classical": (False, "Certificate PQC: no"),
        "invalid": (False, "Invalid"),
        "timeout": (False, "timed out"),
        "connect": (True, "X25519MLKEM768"),
        "connect-default": (True, "Using quantum safe handshake"),
        "scan": (True, "Port 443"),
        "scan-discovery": (True, "Port 443"),
        "info": (True, "Algorithm: mlkem768"),
        "info-broad": (False, "Multiple algorithms matched"),
        "info-signature": (True, "Algorithm: mldsa65"),
        "info-missing": (False, "No algorithms found"),
        "openssl": (True, "ML-DSA-65"),
        "openssl-unsupported": (False, "unsupported"),
        "openssl-groups": (True, "MLKEM768"),
        "openssl-verified": (True, "Negotiated TLS group: X25519"),
        "nmap": (True, "45678/tcp open"),
        "nmap-range": (True, "45678/tcp open"),
        "nmap-unsupported": (False, "unsupported"),
    }
    for name, (success, text) in checks.items():
        send(name)
        result = receive(name)
        assert result["ScanCommandSuccess"] == success and text in result["ScanCommandOutput"], (
            name, result["ScanCommandSuccess"], result["ScanCommandOutput"])
        if name == "list":
            for command in ("QuantumConnect", "QuantumPortScanner", "QuantumInfo", "Openssl", "Nmap"):
                assert command in result["ScanCommandOutput"]
        print("BOARD_COMMAND_PASS", name, flush=True)
    send("cancel")
    time.sleep(0.5)
    send("cancel-request")
    result = receive("cancel")
    assert not result["ScanCommandSuccess"] and "canceled" in result["ScanCommandOutput"]
    print("BOARD_COMMAND_PASS cancel", flush=True)
    channel.queue_purge(queue)
    send("pqc", corrupt=True)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        method, _, body = channel.basic_get(queue, auto_ack=True)
        if method:
            assert json.loads(body)["data"].get("AgentID") != app
        connection.process_data_events(time_limit=0.1)
    print("BOARD_COMMAND_PASS tampered-signature rejected", flush=True)
finally:
    if created and channel.is_open:
        channel.queue_delete(queue)
    if connection.is_open:
        connection.close()
