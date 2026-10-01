#!/usr/bin/env python3
"""Refresh an enrolled ESP32's BLE capabilities through authenticated MQTT.

This publishes the same ProcessorObj registration shape as firmware enrollment,
without clearing the board's state or requiring another browser OAuth login.
The private config file is read locally and credentials are never printed.
"""

import argparse
import hashlib
import json
import pathlib
import re
import secrets
import socket
import ssl
import struct
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse


def mqtt_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    if len(encoded) > 65535:
        raise ValueError("MQTT string exceeds protocol limit")
    return struct.pack("!H", len(encoded)) + encoded


def remaining_length(length: int) -> bytes:
    if not 0 <= length <= 268435455:
        raise ValueError("MQTT packet exceeds protocol limit")
    result = bytearray()
    while True:
        digit = length % 128
        length //= 128
        result.append(digit | (0x80 if length else 0))
        if not length:
            return bytes(result)


def read_exact(connection: ssl.SSLSocket, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        part = connection.recv(count - len(result))
        if not part:
            raise ConnectionError("MQTT broker closed the connection")
        result.extend(part)
    return bytes(result)


def read_packet(connection: ssl.SSLSocket) -> tuple[int, bytes]:
    kind = read_exact(connection, 1)[0]
    length = 0
    multiplier = 1
    for _ in range(4):
        digit = read_exact(connection, 1)[0]
        length += (digit & 127) * multiplier
        if digit & 128 == 0:
            break
        multiplier *= 128
    else:
        raise ValueError("invalid MQTT remaining length")
    if length > 32768:
        raise ValueError("oversized MQTT response")
    return kind, read_exact(connection, length)


def registration(config: dict) -> tuple[str, str, bytes]:
    app_id = config["app_id"]
    owner = config["mqtt_username"]
    if not re.fullmatch(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", owner) or \
            not app_id.startswith(owner + "-"):
        raise ValueError("processor identity does not match its MQTT owner")
    routing_id = "u_" + owner + "_p_" + hashlib.sha256(app_id.encode()).hexdigest()
    uri = urlparse(config["broker_uri"])
    if uri.scheme != "mqtts" or not uri.hostname or uri.port != 8883 or \
            uri.username or uri.password or uri.path or uri.query or uri.fragment:
        raise ValueError("expected a credential-free mqtts://host:8883 broker URI")
    disabled = config["DisabledEndpointTypes"]
    commands = config["DisabledCommands"]
    if not isinstance(disabled, list) or not isinstance(commands, list) or \
            any(not isinstance(value, str) for value in disabled + commands) or \
            any(value in disabled for value in ("blebroadcast", "blebroadcastlisten")):
        raise ValueError("configuration does not advertise both BLE endpoints")
    if config.get("AuthDevice") not in (False, "false") or not config.get("auth_key"):
        raise ValueError("processor must already be enrolled")
    payload = {
        "AppID": app_id,
        "Owner": owner,
        "Location": config["MonitorLocation"],
        "RabbitHost": uri.hostname,
        "MaxLoad": config["max_monitors"],
        "IsQuantumCapable": config.get("IsQuantumCapable", True),
        "RabbitTopologyVersion": 2,
        "DisabledEndPointTypes": disabled,
        "DisabledCommands": commands,
    }
    event = {
        "type": "ProcessorObj",
        "source": config["source"],
        "specversion": "",
        "datacontenttype": "",
        "id": str(uuid.uuid4()),
        "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "data": payload,
    }
    body = json.dumps(event, separators=(",", ":")).encode()
    if len(body) > 32768:
        raise ValueError("registration exceeds backend limit")
    return uri.hostname, "processor/register/" + owner + "/" + routing_id, body


def publish(config: dict) -> None:
    host, topic, body = registration(config)
    username = config["mqtt_username"]
    password = config["mqtt_password"]
    if not isinstance(password, str) or not password:
        raise ValueError("MQTT credential is missing")
    client_id = "capability-refresh-" + secrets.token_hex(8)
    connect = (mqtt_string("MQTT") + bytes((4, 0xC2)) + struct.pack("!H", 60) +
               mqtt_string(client_id) + mqtt_string(username) + mqtt_string(password))
    context = ssl.create_default_context()
    with socket.create_connection((host, 8883), timeout=15) as plain:
        with context.wrap_socket(plain, server_hostname=host) as connection:
            connection.settimeout(15)
            connection.sendall(b"\x10" + remaining_length(len(connect)) + connect)
            kind, reply = read_packet(connection)
            if kind != 0x20 or reply != b"\x00\x00":
                raise ConnectionError("MQTT registration connection was rejected")
            content = mqtt_string(topic) + b"\x00\x01" + body
            connection.sendall(b"\x32" + remaining_length(len(content)) + content)
            kind, reply = read_packet(connection)
            if kind != 0x40 or reply != b"\x00\x01":
                raise ConnectionError("MQTT registration publication was not acknowledged")
            connection.sendall(b"\xe0\x00")
    print("Registration published to the authenticated broker; verify Data accepted it.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=pathlib.Path, required=True)
    args = parser.parse_args()
    publish(json.loads(args.config.read_text(encoding="utf-8")))


if __name__ == "__main__":
    main()
