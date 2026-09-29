# ESP32 backend integration

This is the deployment contract for the ESP32 firmware in this repository.
It does not depend on documentation from another C implementation. The .NET
backends still need their own deployments and database migrations; the firmware
tools do not configure or deploy them.

For device setup and OTA artifact staging, follow [the guide](guide.md).
Use the matching dev/live configuration throughout. The examples below are
additions to existing configuration, not replacement broker or service files.

## Broker and routing

- Enable RabbitMQ's `rabbitmq_mqtt` plugin alongside the existing OAuth backend.
  Devices use the OAuth subject as their username and access token as password,
  not a shared bootstrap user or a newly created static MQTT user.
- Map MQTT to the existing `/vhostuser` vhost and the durable topic exchange
  `monitorProcessor.mqtt.v1`.
- Keep the existing durable topic exchange `monitorProcessor.commands.v2`.
  Bind it to `monitorProcessor.mqtt.v1` using routing key `#`.
  [definitions-mqtt.json](broker/definitions-mqtt.json) is the additive fragment;
  its source exchange must already exist. Do not replace existing users,
  permissions, exchanges or vhosts with that fragment.
- Devices connect with MQTTS on port 8883. Terminate TLS either at the broker or
  at the deployment's TCP TLS proxy. Keep plaintext MQTT private.
  [rabbitmq-mqtt.conf.example](broker/rabbitmq-mqtt.conf.example) shows the MQTT
  settings; its loopback listener example is for same-host testing. In Docker,
  distinguish the container listener from host port publication: a host proxy
  needs a reachable container listener and a loopback-only host port mapping.
- Preserve existing AMQP listeners and OAuth configuration. MQTT ingress is
  additional; existing .NET processors continue using AMQP.

An enrolled device's MQTT client ID is its routing ID:
`u_<lowercase-user-uuid>_p_<sha256-of-full-AppID>`.
It subscribes at QoS 1 to `<routing-id>/<operation>`. The broker maps MQTT
topic separators to AMQP routing-key dots. Queue creation/binding is performed
by RabbitMQ's MQTT plugin when the client subscribes; a topic is not a separately
created resource.

| Device publication | Broker routing key | Consumer/purpose |
|---|---|---|
| `processor/register/<user-id>/<routing-id>` | `processor.register.<user-id>.<routing-id>` | Data: authenticated registration |
| `processor/out/ready` | `processor.out.ready` | Backend readiness listeners |
| `processor/out/data` | `processor.out.data` | Data: monitoring results |
| `processor/out/status-alerts` | `processor.out.status-alerts` | Alert: status changes |
| `processor/out/reset-alerts` | `processor.out.reset-alerts` | Alert: reset requests |
| `processor/out/firmware-status` | `processor.out.firmware-status` | Data: OTA health/status |

The registration reply is `<routing-id>/processorAuthKey`.
OTA commands use `<routing-id>/processorFirmwareUpdate` and
`<routing-id>/processorFirmwareHealthAck`. Normal ready and firmware-status
messages are distinct contracts/topics.

## OAuth scope additions

Inside the existing FusionAuth `populate(jwt, user, registration)` lambda,
append these MQTT scopes **after** assigning the existing scopes. Keep existing
AMQP permissions for tokens also used by .NET processors. This snippet does not
change token issuance, audiences or RabbitMQ's OAuth configuration.

```javascript
var audience = Array.isArray(jwt.aud) ? jwt.aud[0] : jwt.aud;
var userId = String(user.id).toLowerCase();
var mqttQueue = "mqtt-subscription-u_" + userId + "_p_*qos1";
var ownRoutes = "u_" + userId + "_p_*.*";
var mqttScopes = [
  audience + ".configure:*/" + mqttQueue,
  audience + ".read:*/" + mqttQueue,
  audience + ".write:*/" + mqttQueue + "/" + ownRoutes,
  audience + ".read:*/monitorProcessor.mqtt.v1/" + ownRoutes,
  audience + ".write:*/monitorProcessor.mqtt.v1/processor.register." + userId + ".*",
  audience + ".write:*/monitorProcessor.mqtt.v1/processor.out.ready",
  audience + ".write:*/monitorProcessor.mqtt.v1/processor.out.data",
  audience + ".write:*/monitorProcessor.mqtt.v1/processor.out.status-alerts",
  audience + ".write:*/monitorProcessor.mqtt.v1/processor.out.reset-alerts",
  audience + ".write:*/monitorProcessor.mqtt.v1/processor.out.firmware-status"
];
jwt.scope_as_list = (jwt.scope_as_list || []).concat(mqttScopes);
```

Issue a new token after changing scopes; an existing token does not acquire
them automatically. Keep the registration permission bound to the token
subject. Do not grant device tokens publication rights on command routes.
The other outbound routes remain shared: they rely on the existing backend
validation, not per-user broker routing. This documents the current design,
including its accepted reset-alert limitations; it is not a claim that every
message has end-to-end signature protection.

## Backend listener configuration

Set `EnableMqttProcessorIngress: true` on the active `SystemUrl` used by each
backend listener that consumes processor MQTT publications. In Data, also set
`EnableMqttProcessorRegistration: true` after deploying the user-bound scopes.
These flags are properties of the listener's broker configuration, not
root-level appsettings properties. Check which `SystemUrls` entry or
`LocalSystemUrl` the deployment actually selects rather than setting an
unused entry.

Retain normal AMQP publisher-identity checks. MQTT registration uses its own
exchange/routing validation; do not manufacture an AMQP publisher identity from
an untrusted MQTT message field.

HTTPS LoadServer discovery must return a broker present in Data's configured
`SystemUrls`. Data validates registration's RabbitHost against that list,
including load-balanced destinations; missing/unknown destinations are rejected.
The device subscribes for the signed AuthKey reply before publishing registration.
It does not need a shared `usersetup` connection or an HTTP registration endpoint.

## Command signing

`ProcessorObj.IsQuantumCapable` selects the backend signer. Missing/default
capability remains `true` for existing .NET processors (ML-DSA-65).
ESP32's public templates explicitly set it to `false`, and authenticated
registration/readiness announce that value. Signers use shared processor state,
not hard-coded AppID lists or a guess based on transport.

Apply Data's `ProcessorIsQuantumCapable` migration and deploy backends built
against the updated shared library. Data, Service and Scheduler publishers of
protected ESP32 commands need the P-256 command private key. Configure this
root-level appsettings section, or its equivalent environment variable:

```json
"ProcessorCommandSigning": {
  "PrivateKeyPath": "/app/keys/processor-command-ecdsa-p256-private.pem"
}
```

```yaml
environment:
  ProcessorCommandSigning__PrivateKeyPath: /app/keys/processor-command-ecdsa-p256-private.pem
volumes:
  - ${FILES_DIR}/processor-command-ecdsa-p256-private.pem:/app/keys/processor-command-ecdsa-p256-private.pem:ro
```

Alert supports the same signing pipeline, but its existing alert operations
are outside the signing policy and do not require this private key. If it
publishes protected operations, configure the appropriate signer/key there too.
Keep existing ML-DSA keys/configuration: they still protect .NET processors
and backend-to-backend traffic.

The command private key must match the public trust anchor compiled from
`firmware/main/command-signing-public.pem`. Keep it outside Git/build images,
restricted to the runtime service account and administrators, and mount it
read-only. Do not generate a replacement key to fix a missing mount.
This is a different key from the OTA application signing key used by
`tools/build-firmware.sh`.

The C verifier accepts version-1 `ES256` envelopes: base64 exact payload bytes
and a DER-encoded P-256/SHA-256 signature. The signed payload binds operation,
routing ID and JSON using three big-endian length-prefixed fields.
Verification precedes protected-command processing, with no unsigned or
algorithm fallback. AuthKey checks are additional where required.

Protected operations include initialization, monitor updates, registration's
AuthKey reply and both OTA commands. Connect/wakeup, ordinary result
acknowledgements and alert operations retain the .NET policy's unsigned
behaviour. The precise policy lives in `firmware/main/command_security.c` and
is cross-checked against the .NET registry by
`tests/integration/test-command-signatures.sh`.

A valid signature proves possession of the shared backend signing key, not
uniquely that Data sent a message. Ordinary commands retain the existing
replay semantics; OTA adds expiry/request-ID/version checks. Hardware Secure
Boot and flash encryption are not enabled by this development profile.

## Verification

Use the tests in [README.md](../README.md#tests) and
[monitoring parity](monitoring-parity.md). Cross-language signature tests require
the sibling .NET source checkouts and host dependencies documented in the guide;
this document replaces external documentation dependencies, not those test inputs.

For an authorized backend integration test, verify in order: OAuth broker login,
signed registration reply, command subscriptions, probes, Data database saves,
and application `removePingInfos` acknowledgements. MQTT connection/PUBACK alone
does not prove that the backend accepted or persisted results.
Use [the guide's OTA procedure](guide.md#build-and-publish-ota-firmware) separately
to stage a verified application image; never publish provisioned flash.
