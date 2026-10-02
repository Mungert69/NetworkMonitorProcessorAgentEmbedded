# Embedded command integration

Use an enrolled **dev** test board, local devrabbitmq/data/service, both sibling
.NET checkouts, local IDF 6.1, and the existing ML-DSA signing key. Do not run
against a production device or live broker. No database writes are used.

1. Build signed normal firmware with `./tools/build-firmware.sh` and update the
   board using the documented app-only recovery procedure. Preserve bootloader,
   enrollment/config and monitoring partitions.
2. Enable the six implemented command types in the test board's configuration
   (remove their previous explicit restrictions if present). Re-register to
   advertise updated capabilities. Do not override an intentional restriction.
3. Ensure the issued OAuth token has both scan publication scopes from
   `docs/backend-integration.md`. Issue a new token after lambda changes.
4. Generate fixtures outside the repository using the original .NET model/signing:

```sh
dotnet run --project tests/integration/quantum_command/dotnet/Fixtures.csproj -- \
  /private/config.json /private/messages \
  /private/authkey-signing-ml-dsa-65-private.pem
python3 -m venv /private/test-venv
/private/test-venv/bin/pip install -r tests/integration/quantum_command/requirements.txt
/private/test-venv/bin/python tests/integration/quantum_command/run_board.py \
  --config /private/config.json --fixtures /private/messages
```

The runner obtains dev broker credentials from the local data container without
printing them. It creates an expiring private test queue, binds only scan reply
routes and deletes its queue afterward. It sends signed help/list, PQ/classical
certificate, explicit/default quantum handshake, quantum port scan, algorithm
information, bounded OpenSSL/Nmap, invalid-argument, timeout, cancellation and
tampered-signature cases. Signed fixture JSON must be sent unchanged: reparsing
and reserializing it would invalidate the authenticated byte representation.
Host 192.168.1.238:45678 must accept TCP without speaking TLS for the timeout/
cancel fixtures; adjust these test-specific fixtures for another machine.
The PQ fixture requires quantum.readyforquantum.com:4433 to be reachable.

These tests validate actual device signature verification, execution and MQTT
ack/result wire contracts. They do **not** create an LLM request/session and
therefore do not claim successful frontend/LLM result delivery; Service can
report no matching pending request for this synthetic correlation ID. Observe
normal monitoring/application acknowledgements concurrently in serial logs.

`read_board_config.py` is a private-fixture helper that uses the official IDF NVS
parser on a dump of **only nmconfig**. It prints AppID/broker and scope-presence
booleans, never secrets. Its `--enable-quantumcert` switch is an explicit test
configuration edit, not an automatic production migration. The
`--enable-command-processors` switch enables all six implemented types on a
disposable test board; it never edits database capabilities. All generated config,
NVS dumps, signed messages (containing AuthKey), tokens and serial logs stay
outside the source repository with restricted permissions. Never commit them.
