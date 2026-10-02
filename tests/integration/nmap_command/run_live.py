"""Run signed Nmap command cases against one live TCP service through the dev board."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time
import uuid

import pika

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--config", required=True, type=Path, help="private enrolled board config JSON")
parser.add_argument("--fixtures", required=True, type=Path, help="private .NET-signed fixture directory")
parser.add_argument("--serial-log", type=Path,
                    help="fresh private board log; require real ARP FIFO contention and monitor progress")
parser.add_argument("--monitor-id", type=int, help="assigned Nmap monitor used for overlap assertion")
args = parser.parse_args()
if args.serial_log and args.monitor_id is None:
    parser.error("--serial-log requires --monitor-id")
root = Path(__file__).resolve().parents[3]
for path in (args.config.resolve(), args.fixtures.resolve(),
             *([args.serial_log.resolve()] if args.serial_log else [])):
    if path == root or root in path.parents:
        parser.error("Private inputs/fixtures must stay outside the repository")

config = json.loads(args.config.read_text())
app_id = config["app_id"]
route = "u_" + config["mqtt_username"] + "_p_" + hashlib.sha256(app_id.encode()).hexdigest()
container = json.loads(subprocess.check_output(["docker", "inspect", "data"]))[0]
env = dict(value.split("=", 1) for value in container["Config"]["Env"] if "=" in value)
connection = pika.BlockingConnection(pika.ConnectionParameters(
    "127.0.0.1", 5672, "/vhostuser",
    pika.PlainCredentials("usercommonxf1", env["RabbitPassword"]),
    socket_timeout=10, blocked_connection_timeout=10, heartbeat=60))
channel = connection.channel()
channel.confirm_delivery()
queue = "nmap-live-test." + uuid.uuid4().hex


def fixture(name):
    return json.loads((args.fixtures / (name + ".json")).read_text())


def send(name):
    body = (args.fixtures / (name + ".json")).read_text()
    operation = "cancelCommand" if name == "cancel-request" else "processorCommand"
    channel.basic_publish(
        "monitorProcessor.commands.v2", route + "." + operation, body,
        pika.BasicProperties(content_type="application/cloudevents+json"), mandatory=True)


def receive(name, timeout=70):
    expected = fixture(name)["data"]
    deadline = time.monotonic() + timeout
    ack = False
    while time.monotonic() < deadline:
        method, _, body = channel.basic_get(queue, auto_ack=True)
        if method is None:
            connection.process_data_events(time_limit=0.1)
            continue
        data = json.loads(body)["data"]
        if data.get("AgentID") != app_id or data.get("MessageID") != expected["MessageID"]:
            continue
        assert data["AuthKey"] == config["auth_key"]
        assert data["Type"] == "Nmap"
        if method.routing_key == "processor.out.scan-ack":
            ack = True
        else:
            assert ack, "Command result arrived before acknowledgement"
            return data
    raise TimeoutError(f"No Nmap result for {name}; check board serial logs and token scopes")


created = False
try:
    channel.queue_declare(queue, durable=False, exclusive=True, arguments={"x-expires": 300000})
    created = True
    for key in ("processor.out.scan-ran", "processor.out.scan-ack"):
        channel.queue_bind(queue, "monitorProcessor.mqtt.v1", routing_key=key)

    names = sorted(path.name.removesuffix(".expect.json")
                   for path in args.fixtures.glob("*.expect.json"))
    if not names:
        raise RuntimeError("No signed Nmap fixtures found")
    for name in names:
        expected = fixture(name)["data"]
        send(name)
        if name == "discovery-cancel":
            connection.process_data_events(time_limit=2)
            send("cancel-request")
        result = receive(name)
        success = bool(result["ScanCommandSuccess"])
        text = result["ScanCommandOutput"]
        # Expectations accompany each signed fixture but are not part of its signature.
        sidecar = args.fixtures / (name + ".expect.json")
        if not sidecar.is_file():
            raise RuntimeError(f"Missing expectation sidecar for {name}")
        check = json.loads(sidecar.read_text())
        wanted_success = check["success"]
        wanted_text = check["contains"]
        if success != wanted_success or wanted_text not in text:
            raise AssertionError((name, success, text, check))
        rows = [line.split() for line in text.replace("\\n", "\n").splitlines()]
        for service_port, service_name in (check.get("services") or {}).items():
            assert any(len(row) >= 3 and row[0] == service_port and row[2] == service_name
                       for row in rows), (name, service_port, service_name, text)
        print("LIVE_NMAP_PASS", name, flush=True)
    if args.serial_log:
        import re
        log = args.serial_log.read_text(errors="replace")
        waits = re.findall(r"FIFO wait completed: admitted=1 cancelled=0 wait_ms=(\d+)", log)
        assert any(int(wait) > 0 for wait in waits), "No real concurrent ARP admission observed"
        assert re.search(rf"probe id={args.monitor_id} ok=1\b", log), "Scheduled Nmap monitor did not succeed"
        assert "application acknowledgement applied in RAM" in log, "No backend acknowledgement"
        assert "ARP discovery could not execute" not in log, "ARP contention still failed"
        assert "FIFO wait completed: admitted=0 cancelled=0" not in log, "ARP admission expired"
        print("LIVE_NMAP_FIFO_OVERLAP_PASS", flush=True)
finally:
    if created and channel.is_open:
        channel.queue_delete(queue)
    if connection.is_open:
        connection.close()
