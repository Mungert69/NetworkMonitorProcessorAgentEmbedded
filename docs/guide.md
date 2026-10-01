# ESP32-S3 native processor prototype

This ESP-IDF firmware targets **16 MB flash / 8 MB PSRAM** and uses ESP-IDF v6.1. Host tests exercise native firmware code in this repository. This firmware is **not yet a drop-in replacement** for the .NET processor: the standard profile supports DNS, ICMP, TCP/rawconnect, HTTP/HTTPS/httphtml and passive BLE broadcast/listen probes, MQTT v2 ingress/egress, Brotli quality-0 data, bounded pending pings, NVS persistence, and two-slot HTTPS OTA. Specialist endpoints, complete command/state parity, and ML-DSA command verification are not implemented. See [monitoring parity](monitoring-parity.md) for supported behaviour and deliberate adaptations.

The 16 MB partition table has two 6 MiB app slots (`ota_0`, `ota_1`), an `otadata` selector, 56 KiB of device configuration (`nmconfig`), and 2 MiB of processor state (`nmdata`). App updates replace only the inactive app slot; they leave configuration and state intact.

`nmconfig` and `nmdata` are the two application-owned NVS partitions. There is
also a separate SDK `nvs` partition for Wi-Fi settings/calibration; these are
not the only two NVS partitions. See `firmware/partitions.csv` for the layout.

## Prerequisites and paths

Run all commands below from the **repository root**, not from `firmware/`.
Use Linux, Bash, Git, Python 3, CMake, Ninja, and the ESP-IDF Installation
Manager (EIM) with ESP-IDF v6.1 installed for the `esp32s3` target. Project
scripts use the local environment through `tools/idf-local.sh`; Docker is not
needed. The host also needs `flock` and `realpath`. Physical flashing requires
`jq`, serial-port permissions, and a data-capable USB cable. Debian/Ubuntu may
need `flex`, `bison`, `gperf`, and `dfu-util` for EIM's prerequisite checks.

### Setting up a new development machine

Install common host packages (Debian/Ubuntu):

```sh
sudo apt update
sudo apt install -y git wget flex bison gperf python3 python3-venv \
  cmake ninja-build ccache libffi-dev libssl-dev dfu-util libusb-1.0-0 jq
```

Install EIM using [Espressif's EIM instructions](https://docs.espressif.com/projects/idf-im-ui/en/latest/installation.html), then install this project's toolchain for ESP32-S3:

```sh
eim install --idf-versions v6.1 --target esp32s3 --cleanup true \
  --do-not-track true --skip-components-download true
eim run 'idf.py --version' v6.1
```

If EIM is not on `PATH`, set `EIM_BIN` to its executable. The runner defaults
to v6.1 and `firmware/build`; `NM_IDF_VERSION` and `NM_IDF_BUILD_DIR` override
those defaults. The sole production configuration is the checked-in
`firmware/sdkconfig.production`. It selects Picolibc without Newlib
compatibility; the build rejects either Newlib selection or compatibility.
Use `firmware/build` for the active build. Do not create alternate production
sdkconfig or build directories.

Concurrent probes, MQTT and BLE require both `CONFIG_MBEDTLS_THREADING_C=y`
and `CONFIG_MBEDTLS_THREADING_PTHREAD=y`. `sdkconfig.production` enables these
and the build rejects configurations that disable them. Do not replace private
provisioned device configuration.

Initialize repository submodules with `git submodule update --init --recursive`.
Restore the existing private OTA signing key securely under `../securefiles/`
or set `NM_OTA_SIGNING_KEY`; never copy it into the repository. Physical boards
require read/write access to `/dev/serial/by-id/` (usually via the `dialout`
group). Install `esp-emu` separately on the host for emulator tests; it is not
part of EIM or this repository.

For emulation, install `esp-emu` separately at `~/.local/bin/esp-emu`, or
set `ESP_EMU_BIN` to its executable path. The emulator runs as a foreground
host process; compilation and provisioning use local ESP-IDF through EIM.

Before building updates, securely restore the **existing**
`../securefiles/private-ota-signing-key.pem` with mode 600 (or set
`NM_OTA_SIGNING_KEY` to its absolute path). It is mounted read-only for signing and absent
from Git. Only a completely new test fleet should generate a new key using
`./tools/generate-dev-signing-key.sh`; a replacement key is not compatible
with devices trusting the original key.

| Artifact | Purpose | Distribution |
| --- | --- | --- |
| `firmware/config/appsettings-{dev,live}.json` | Public deployment templates | Safe to commit |
| Signed firmware `.bin` files | OTA or factory release artifacts | Keep outside the Git working tree; publish intentional public downloads as GitHub Release assets only |
| Private generated configuration | Wi-Fi and initial deployment settings | Keep private |
| `merged-binary.bin`, `nmconfig.bin`, raw flash dumps, NVS images | Provisioned device contents | Keep private and outside the repository; never publish or OTA |
| Instance `runtime-flash.bin` | Enrolled credentials and mutable state | Keep private; never clone identities or commit to Git |

Never commit firmware images, factory images, OTA images, merged flash images,
or device flash dumps to the Git repository. Build outputs belong in the ignored
`firmware/build/` directory. Stage OTA files in the external
`~/code/securefiles/{dev,live}/firmware/` directories. Public factory downloads,
when deliberately released, are attached to a GitHub Release and are not Git
repository files. Factory images containing credentials or device state must
never be published.

There is no separate dev/live application build or environment encoded by an image
tag. Select the deployment in configuration; keep dev/live runtime state separate.

## First boot with browser login (no .NET bootstrap)

### Dev and live environments

Initial device configuration selects the environment; the signed application
binary is identical for both. Deployment settings live in
`firmware/config/appsettings-dev.json` and `firmware/config/appsettings-live.json`, not in Python
or an environment flag. Select a file explicitly:

```sh
umask 077
mkdir -p runtime
python3 tools/prepare_config.py --config firmware/config/appsettings-dev.json --device-name esp32.dev.test --output runtime/config-dev.json
./tools/build-firmware.sh
./tools/provision-emulator.sh --config runtime/config-dev.json --instance runtime/dev
./tools/run-emulator.sh runtime/dev
```

The firmware build uses the checked-in `sdkconfig.production`; review and
commit any intentional configuration changes there. The
main firmware profile includes the NimBLE observer and Wi-Fi/BLE software
coexistence in the normal OTA image.
The current profile enables external probe stacks and 64 lwIP sockets, with
`FD_SETSIZE=80` reserving additional console/VFS descriptors; a build guard
rejects the old ten-socket setting. A new firmware build reads existing raw
monitoring NVS state and saves it in Brotli quality-zero format at the next
cycle. This does not change enrollment, Wi-Fi configuration or OTA metadata.

For live, select `appsettings-live.json`, generate `config-live.json`, and provision
a separate `runtime/live` instance, using a different test device name:

```sh
python3 tools/prepare_config.py \
  --config firmware/config/appsettings-live.json \
  --device-name esp32.live.test --output runtime/config-live.json
./tools/provision-emulator.sh --config runtime/config-live.json --instance runtime/live
./tools/run-emulator.sh runtime/live
```

The already-built signed app is reused. There is no implicit live default.
Dev discovery must return the dev broker. OAuth and signature verification stay enabled.

The runner preserves each instance's enrolled flash and refuses simultaneous use of
one instance. Rebuilding firmware does not overwrite its installed firmware or identity.
Use OTA to update an enrolled instance, or provision a new directory for a fresh test.
Do not run two instances with the same processor identity.

Physical boards use the same compiled firmware, but pass a real Wi-Fi configuration
to `device.sh flash --config`. No emulator provisioning is needed for physical flashing.
OTA staging copies only the signed application into the explicitly chosen
`securefiles/dev/firmware` or `securefiles/live/firmware` directory. OTA preserves
the device's deployment settings; never publish merged flash or NVS images.

Fresh devices can now enroll directly. `AuthDevice: true` (or string `"true"`)
starts the FusionAuth device-code flow implemented in `enrollment_oauth.c`. The first
broker connection uses the authenticated user's token, never `usersetup`.
The device subscribes to its own `processorAuthKey` reply before publishing to
`processor/register/<user-id>/<routing-id>`. Registration includes the RabbitHost
returned by HTTPS LoadServer discovery. Data validates it against its configured
SystemUrls brokers, allowing load-balanced destinations without accepting arbitrary
broker connections. Missing or unknown hosts are rejected instead of falling back
to the primary broker. Deploy Data 0.18.10 or later with this firmware change.
Enrollment completes only after
the reply's configured command signature, operation and target are verified. Credentials
and `AuthDevice: false` are committed to NVS; reboot and OTA retain them.
An enrolled device starts normally with `AuthDevice: false` and its saved credentials.

The device decodes the token's subject for identity construction; it does not
locally verify the JWT signature. The token comes from the HTTPS OAuth flow and
RabbitMQ authenticates it before registration. The enrollment endpoint guard
requires discovered OAuth endpoints to share the configured HTTPS authority.
It rejects userinfo/query/fragment characters in that authority, but does not
reject query strings or fragments throughout a discovered endpoint URL. Do not
describe this as a general-purpose URL/SSRF validator. See
`firmware/main/enrollment_policy.h` and `enrollment_http.c`.

For physical boards, supply `--wifi-ssid SSID --wifi-password-file /private/path`
to the generator (password file mode 600), omit `--device-name` to derive a stable
name from the Wi-Fi MAC, then pass the output to `tools/device.sh flash --config`.
Names follow the .NET registration convention: AppID is
`<user-id>-<AppName-><machine>` and Location is `<email>-<AppName-><machine>`.
The optional `AppName-` prefix is set with `--app-name`. By default machine is
`esp32.<12 lowercase hexadecimal Wi-Fi MAC digits>`; `--device-name` overrides
it for tests. Machine-name hyphens become dots, as on .NET. AppID is bounded to
255 UTF-8 bytes without splitting characters; oversized locations fail enrollment
instead of being silently truncated. The full AppID is hashed for broker routing,
so dots in the display identity do not become routing separators. Existing
enrolled configurations keep their identity until explicitly re-enrolled.
Emulators may share a fixed MAC: give concurrent test instances distinct
`--device-name` or `--app-name` values to avoid sharing a processor identity.

The helper refuses to overwrite existing files. It embeds no token or AuthKey;
the initial config still contains your Wi-Fi password and must remain private.

Data must enable MQTT ingress and registration, and tokens need the user-bound
`processor.register.<user-id>.*` publish permission described in
[backend integration](backend-integration.md). No new HTTPS registration endpoint is used.
HTTPS discovery and polling use the ESP-IDF certificate bundle and bounded
responses; redirects are not followed. Registration waits up to 60 seconds.
Failed enrollment leaves `AuthDevice` enabled in persistent config; restart to
retry. Token refresh is not implemented in this firmware.

Tests: `python3 -m unittest discover -s tests/tooling -p 'test_*.py'`,
`./tests/integration/test-command-signatures.sh`, and the host C policy test in
`tests/native/test_enrollment_policy.c` (link yyjson, optionally ASan/UBSan).

On a new test fleet only,
`./tools/generate-dev-signing-key.sh` creates the development/test OTA signing key.
Here “dev” means a test signing key, **not the dev server environment**.
Preserve the existing key when building updates for already provisioned devices;
do not generate a replacement. No private configuration is needed to compile firmware.
Provisioning writes configuration to NVS, never into the application binary.

For **real ICMP monitoring**, use TAP networking. The emulator's default `--net user` fabricates ICMP echo replies for every destination, so it cannot validate reachability or round-trip times. On Linux, the following creates a dedicated TAP interface and narrow IPv4 forwarding/NAT rules (requires sudo and an available `192.168.4.0/24` subnet):

```sh
sudo bash tools/setup-tap.sh
NM_ESP_NET=tap,ifname=nm-esp-tap NM_ESP_PERSIST=1 \
  NM_ESP_EXIT_ON='' NM_ESP_TIMEOUT=86400s ./tools/run-emulator.sh runtime/dev
```

Use the same instance directory on subsequent runs to retain credentials and state. The TAP setup is idempotent; after stopping the emulator, `sudo bash tools/setup-tap.sh --teardown` removes only its TAP interface and rules. A graceful Ctrl+C saves NVS to the instance runtime image. The host network must permit ICMP for the target addresses; physical-device behavior still needs testing on hardware.

The helper redirects the emulator's UDP DNS requests to the first non-loopback
IPv4 resolver in `/etc/resolv.conf`, preserving LAN split-DNS for dev services.
If the host uses only a loopback resolver, run
`sudo NM_ESP_DNS=192.168.1.1 bash tools/setup-tap.sh` with your actual LAN resolver.
Use the same override for teardown. Tear down before changing resolver or uplink.

### Emulator restart, logs and troubleshooting

The runner persists state by default, runs for up to 86400 seconds by default,
and has no default early-exit marker. Restart with the **same instance path**
to retain credentials, installed firmware and pending results. Stop gracefully
with Ctrl+C so the emulator can save its runtime flash.

To keep a local serial log while interacting with the foreground process:

```sh
umask 077
set -o pipefail
NM_ESP_NET=tap,ifname=nm-esp-tap ./tools/run-emulator.sh runtime/dev 2>&1 | tee -a runtime/dev/serial.log
```

In another terminal, use `tail -f runtime/dev/serial.log`. Treat logs as
private: enrollment displays a short-lived authorization URL/code.
`ESP_EMU_BIN`, `NM_ESP_NET`, `NM_ESP_TIMEOUT`, and `NM_ESP_EXIT_ON`
control the executable, networking, run duration and optional early-exit marker.
`NM_ESP_PERSIST=0` is for disposable non-persistent tests, not normal monitoring.

- Existing instance: provision into a **new** directory; never delete an enrolled
  instance just to rebuild firmware. Provisioning deliberately refuses existing
  directories. A failed provision can leave a partial directory; retain it for
  diagnosis and choose another path for the retry.
- Instance already in use: stop its existing emulator before starting another.
- Missing key: restore the original OTA signing key; do not replace it.
- Discovery/broker failure: verify the selected template and that environment's
  discovery service, MQTT TLS listener and Data registration are available.
- Rebuilt app not running: compilation does not replace persistent emulator flash.
  Use OTA, or provision a fresh test instance.
- To re-enroll an existing instance, use the serial reset commands documented
  below. Factory reset preserves deployment endpoints; it does not switch dev/live.

TAP mode proves real packet reachability, but `esp-emu` guest millisecond timing can still report `0 ms` for a successful fast reply. Do not use emulator RTT values as performance measurements; validate latency on the physical ESP32-S3. The firmware main-task stack is set to 16 KiB because real ICMP timeouts exposed an overflow with ESP-IDF's 3584-byte default.

The ESP32 uses the selected appsettings template during provisioning, but does not need a copied .NET processor configuration, `.env`, or monitor list. Use the native OAuth setup above. Monitors arrive from the backend through authenticated registration and normal processor commands; no monitor-seeding config is supported. Protected commands require ECDSA P-256 verification against the compiled public key, with no unsigned bypass.

The device holds configuration and credentials in `nmconfig`, while monitor and pending-ping state lives in `nmdata`. Both partitions survive normal OTA app updates. Initial flash images contain the Wi-Fi password; enrolled flash images also contain extractable broker credentials. Protect them and never commit or distribute them. NVS encryption and hardware flash encryption are **not enabled** by this emulator profile. A physical production device needs a deliberate Secure Boot V2, flash-encryption, key-provisioning, and recovery procedure before being trusted with live credentials.

OTA is triggered by a `processorFirmwareUpdate` command on the processor's own MQTT v2 command route. CloudEvent `data` must contain `AuthKey`, the matching `AppID`, `ExpiresAtUnixSeconds` (within the next five minutes), `RequestId` (lowercase UUID), `Version` (strict numeric `major.minor.patch`), `Sha256` (lowercase hex), and an HTTPS `UpdateUrl` ending in `/<Sha256>.bin`. It downloads only a signed **app binary**, never a full-flash image. TLS validation, complete-download checks, raw-image SHA-256, the embedded app version, and ESP-IDF's app signature are checked before selecting the inactive slot. Downloading is bounded to five minutes plus the current HTTP operation's timeout. From 0.1.8, authenticated owners may upgrade or downgrade; the running version itself and the last accepted/pending request ID are still rejected. Accepted metadata survives reboot in `nmdata`. This intentionally removes the monotonic version floor, not signature or request validation. Older running firmware must first upgrade to 0.1.8 or newer to accept downgrades. After a downgrade, the installed release's own OTA policy applies. Hardware eFuse anti-rollback is not enabled.

After reboot, `processor/out/firmware-status` carries a `CProcessorFirmwareStatusObj` with `AppID`, `AuthKey`, `RequestId`, `Version`, and `Status: PendingConfirmation`. Data must send an AuthKey-protected `processorFirmwareHealthAck` with matching `RequestId` and `Version` before the 120-second boot health deadline. A MQTT PUBACK does not confirm the app. A matching Data acknowledgement marks the image valid; the device then publishes `Status: Confirmed` on the firmware-status topic. Failure to receive the acknowledgement causes rollback. Data's pending-request tracking is currently in-memory: a Data restart mid-update fails safe to rollback. Deploy the updated Data and shared Lib before using this flow. Ordinary monitoring acknowledgements remain independent.

Normal readiness uses `CProcessorReadyObj` on `processor/out/ready`, with no OTA fields. OTA status uses its own topic and Data handler; its C-specific contract remains separate from ML-DSA and currently uses AuthKey/broker ACL authentication. Add `audience + ".write:*/monitorProcessor.mqtt.v1/processor.out.firmware-status"` to the FusionAuth token scopes and issue a new token before testing. No shared-exchange changes are needed in `definitions.json`.

Firmware releases use `firmware/version.txt`; increment it before building an update, and supply that exact version to Service's owner-authorized endpoint. Service serves the versioned signed app through its hash-based URL and sends the signed backend request to Data. Hardware Secure Boot remains disabled as requested. From 0.1.3, device commands covered by the .NET signing policy plus both OTA commands require ECDSA P-256 signatures; AuthKey checks remain additional checks. Durable backend audit is not yet implemented. Never grant processor credentials command-publish permissions.

## Build and publish OTA firmware

Before publishing a binary, follow the [licensing and matching-source
checklist](licensing.md). In particular, the GitHub-generated source archives
do not include the wolfSSL and yyjson submodules. A signed image is not a
substitute for the corresponding source and applicable third-party notices.

Update `firmware/version.txt` for a new release, run `./tools/build-firmware.sh`,
and verify the signed application with ESP-IDF's `espsecure` tooling and the
expected signing key. Staging validates metadata and hashing, **not signatures**.
No Wi-Fi configuration or emulator provisioning is needed to build an OTA app.

Create the destination directory before staging. For dev:

```sh
mkdir -p "$HOME/code/securefiles/dev/firmware"
```

Stage the signed, verified app with its embedded version and hash in the filename:

```sh
python3 tools/stage_firmware.py \
  --app firmware/build/networkmonitor_processor_esp32.bin \
  --directory "$HOME/code/securefiles/dev/firmware"
```

For live, create `~/code/securefiles/live/firmware` and use that directory
instead. You can stage the exact same verified application in both locations.
Copy only the versioned application file to the remote server's firmware volume;
staging locally does not deploy it, trigger OTA, or change backend configuration.
Service mounts that directory read-only at `/app/firmware`. Data's
`FirmwareUpdate:PublicBaseUrl` must be the matching Service origin
(`https://devmonitorsrv.readyforquantum.com` for dev,
`https://monitorsrv.readyforquantum.com` for live).

This creates `networkmonitor-esp32-s3-<version>-<sha256>.bin` (using the actual
embedded version, not a manually supplied label). The helper validates app
metadata/size and computes the hash; it does not replace signature verification.
The updated Service resolves versioned filenames; its public URL stays
`/firmware/esp32-s3/<sha256>.bin`. Deploy the Service change before copying these
files to live. Digest-only filenames are no longer supported. Device firmware
and Data need no filename-related changes. Copy the versioned file unchanged;
never stage `merged-binary.bin`, NVS images, or private keys.

### BLE broadcast monitoring

`./tools/build-firmware.sh` builds both BLE endpoints into the normal signed
OTA image. One NimBLE host runs a passive scan with 50 ms interval/window and
Wi-Fi/BLE coexistence; hardware/radio arbitration still determines the actual
listening time. Duplicate filtering is off so a later advertisement can satisfy
a fresh probe. NimBLE callbacks copy only matching packets into one bounded
one-item queue per probe worker; decryption and model updates run outside the
callback. Scan diagnostics are rate-limited and never log encrypted payloads.

`blebroadcast` requires a MAC address. `blebroadcastlisten` ignores its Address
field, which can remain a frontend label, and counts captures up to
`--max_captures` (default 10, limit 50) or the
monitor timeout, returning success even at zero captures like .NET. The 256-byte
monitor message reports the count/end reason rather than concatenating every
captured payload; this is a deliberate embedded-size adaptation. Set a timeout
longer than the beacon interval (for a 60-second Victron beacon, use over 60 s).
Existing provisioned devices retain their stored appsettings, so an OTA image
alone does not remove an older explicit `blebroadcastlisten` disable entry;
update/reprovision that configuration before assigning such a monitor.

Supported payload formats are `raw`, `aesgcm`, `aesctr`, and `victron` (which
requires a 16-byte key). `--metric` supports PV power, battery voltage/current, yield and
load current. `--manufacturer_id`, `--payload manufacturer|service|raw`,
`--service_uuid` (16/32-bit or canonical GUID), `--raw_payload` (bounded hex),
`--nonce_len`, `--tag_len`, and `--nonce_at start|end` are accepted. A raw-payload
override skips RF scanning, as in .NET. BLE command processors remain
unsupported. The passive scanner cannot
obtain scan-response-only fields. No physical-board BLE integration result is
implied by the host filter/endpoint tests or firmware build.

## USB recovery (ROM download mode)

When the application will not boot, recover over USB in ROM download mode: hold
`BOOT`, tap `RESET`, then run the recovery tool from the repository root:

```sh
tools/recover_serial.py --port /dev/serial/by-id/usb-DEVICE
```

It writes the signed app into `ota_0` and selects it with the initial otadata
image, leaving `nmconfig` and `nmdata` intact, so Wi-Fi configuration and
enrollment are preserved. It asks you to type the device MAC to confirm, and the
bootloader still verifies the app signature. Prefer the signed MQTT OTA for
updating a working device.

## Command signing (0.1.3+)

The backend defaults to its existing ML-DSA behavior. Native OAuth provisioning
sets `IsQuantumCapable: true` on the quantum branch, and registration
announces that capability before the backend signs its reply. Authenticated
readiness also updates the ProcessorObj record and shared backend state.
There are no AppID lists. See
[backend integration](backend-integration.md#command-signing) for deployment settings.
The ECDSA trust anchor is `firmware/main/command-signing-public.pem`; the ML-DSA-65
anchor is `firmware/main/command-signing-mldsa-public.pem`. Never replace either
without a coordinated key transition. The command private key remains on the
backend and is separate from the firmware image signing key.

An explicit `IsQuantumCapable: false` uses the existing envelope containing protocol version, algorithm, base64 exact signed payload
and a DER ECDSA signature. The payload uses the same three big-endian
length-prefixed fields as .NET: operation, processor routing ID and JSON.
Verification happens before JSON command dispatch, with no unsigned fallback
and no algorithm negotiation. `true` instead verifies the original .NET signed
object with wolfSSL ML-DSA-65. The device preserves the signed JSON bytes and
replaces only `BackendSignature` with an empty string when reconstructing the
same length-prefixed payload. Signature/key/context workspace uses PSRAM.
Deploy the updated Data/shared library before using ML-DSA enrollment or OTA.
Existing topics and unsigned .NET operations
(connect, wakeup, acknowledgements and alert updates) stay unchanged.
Signing does not add replay protection to ordinary .NET-equivalent commands;
OTA keeps its request ID, expiry and version checks.

The implemented inbound command checks are explicitly different by operation:

| Operations | Configured command signature | Payload AuthKey |
| --- | --- | --- |
| `processorAuthKey` (enrollment reply) | Required | No pre-existing AuthKey required |
| `processorInit`, `processorQueueDic` | Required | Required |
| `processorFirmwareUpdate`, `processorFirmwareHealthAck` | Required | Required |
| `processorConnect`, `processorWakeUp`, `processorAlertFlag`, `processorAlertSent`, `processorResetAlerts`, `processorUserEvent`, `removePingInfos` | Not required | Not required |

The final row relies on authenticated broker access and command-route permissions,
not an application-level signature or AuthKey check. Runtime dispatch also checks
the device routing prefix and operation-specific payload requirements. Do not
assume every message is signed, or that every unsigned message carries an AuthKey.
The signature policy lists additional .NET operations that this device does not
implement; listing them does not advertise endpoint/command support. Sources:
`firmware/main/processor_commands.c`, `command_security.c` and
`enrollment_registration.c`.

Run `./tests/integration/test-command-signatures.sh` for .NET-to-C signature fixtures,
policy parity, wrong target/operation, tampering and downgrade rejection tests.
Host signature-test dependencies: .NET 10 SDK, C compiler, `libmbedtls-dev`,
and the pinned yyjson submodule (`git submodule update --init --recursive`).

### Historical prototype transitions (not the normal setup)

Do not deploy against an unsigned backend. For the old prototype fleet,
bootstrap the emulator with the new image and `IsQuantumCapable: false` in
device configuration after applying the backend migration; old 0.1.1/0.1.2
images cannot read the signed envelope.
An OTA across that protocol boundary would also require the backend profile
to switch before the new image's health acknowledgement, so it is not an
unattended migration path. Configuration and monitor state can be preserved
using the existing rebase tool. This transition does not affect .NET devices.

OTA command expiration is evaluated in UTC. The device refreshes SNTP time
before validating an authenticated update command and refuses the update if
fresh synchronization fails. Regular synchronization runs every 60 seconds;
this also limits drift when emulator time advances slower than host time.
This is ordinary SNTP, not authenticated time synchronization or an anti-spoofing
mechanism. A fresh reply addresses stale synchronization; it does not prove the
time source's identity. Command authenticity is checked separately by the configured signature verifier.
No clock-skew exemption is applied to the five-minute command window. Keep
the backend host clock synchronized too. Validation logs show device time and
command expiry, but never AuthKey or broker credentials.

The previous prototype app did not save OTA request metadata. It cannot OTA directly into this stricter confirmation flow: bootstrap the emulator once using a new runtime image via `tools/rebase_emulator_flash.py`, preserving its config/state and old recovery image. New physical boards should start with this build. Do not overwrite an active emulator image.

The old single-slot emulator flash image cannot be converted by OTA. For the one-time emulator transition, stop the old emulator, build the new provisioned image, then run `tools/migrate_emulator_flash.py` to copy its old `nmdata` NVS bytes into a **new** flash image. This leaves the old image as a recovery copy. On hardware, choose the dual-slot table at first provisioning; do not casually rewrite a deployed partition table.

### Delivery and persistence

The firmware publishes ready and data using MQTT QoS 1. A broker PUBACK does **not** clear pending pings; only backend `removePingInfos` does. At the configured pending limit, probes pause and stored data is resent. NVS flash wear and long-term retention still need measurement on hardware.

Monitoring configuration, pending data, reconciliation queues, user-flow flags and
scheduler state now share one `monitoring` JSON snapshot in NVS. The firmware
uses typed records/collections in RAM and constructs JSON only at its storage
and messaging boundaries. The stored schema remains unchanged by this refactor.
Probe results and incoming monitoring commands update the PSRAM model, not NVS.
Each cycle attempts one snapshot save after its accepted probe jobs finish and
before publishing, even when no probes ran. There are no per-probe or per-ack
writes and no dirty-state save gating. Changes arriving during publication are
included next cycle. Failed saves preserve RAM and the previous NVS snapshot;
delivery is still attempted. Power loss can lose changes since the last save or
replay already-acknowledged ping IDs. This trade-off is intentional. OAuth/config
and OTA metadata retain their separate persistence rules.
The firmware
imports the old `monitors`/`processor` blobs without floating-point conversion of
IDs, then retires the old blobs only after the new snapshot is committed. Do not
downgrade an active device to code that only reads the old blobs: they are
migration inputs, not mirrored state.
Configuration/OAuth/OTA metadata retain their separate storage and trust rules.
See [monitoring parity](monitoring-parity.md) for tests and limits.

## First physical board (development setup)

### Re-register over USB serial (0.1.6+)

Connect the board's **USB-to-UART bridge port**, open its serial console at
115200 baud (`./tools/device.sh monitor --port /dev/serial/by-id/YOUR-BOARD`),
and enter these lines, pressing Enter after each:

```text
reregister
confirm reregister
```

Confirmation must arrive within 30 seconds. `cancel` aborts; `help` lists the
commands. Overlong/malformed input is rejected. This is a local physical-access
administration interface, not a network endpoint. The default firmware reads
UART0; do not assume the separate native USB port accepts these commands.

The device saves a durable reset request and restarts. Before reconnecting it
removes the old broker login, AuthKey, AppID/location and monitoring state
(**including unsent pings**), then starts browser OAuth enrollment again.
Wi-Fi settings, DeviceName/AppName, limits, firmware, signing trust and OTA
version/rollback metadata are preserved. The same account and machine/AppName
produce the same AppID. The backend's agent/host records are not deleted; its
signed registration response supplies the assigned monitors again.

Interrupted resets retry on boot; monitoring never starts with a partially
reset identity. The console works while Wi-Fi or broker login is unavailable.
Re-registration is refused during an OTA update or pending OTA health check.
It is not a factory reset and does not erase Wi-Fi settings. Logical removal
from NVS is not forensic erasure; hardware flash encryption remains a separate
deployment concern.

Tests: `tests/native/test_serial_commands.c` (host yyjson, ASan/UBSan) and
`python3 tests/integration/test_serial_emulator.py` after building. The latter uses
synthetic credentials and a separate flash image, verifies a real serial-triggered
reboot and persistent state changes, and never re-registers the live test agent.

### Factory reset and USB Wi-Fi setup (0.1.7+)

On the same USB-to-UART console at 115200 baud, enter:

```text
factory-reset
confirm factory-reset
```

Confirm within 30 seconds, or enter `cancel`. After reboot, the board asks for
the 2.4 GHz Wi-Fi SSID and then its password. Press Enter after each. The device
does not echo either entry; keep your terminal's local echo disabled so it does
not display the password itself. SSIDs must be 1–32 bytes and passwords 8–63
bytes (secured Wi-Fi only). Invalid/overlong input is rejected without printing
it. Backspace is supported. No rebuilding or reflashing is needed.

Factory reset clears Wi-Fi, OAuth/broker credentials, AuthKey, processor identity,
custom DeviceName/AppName, monitors and pending results. Limits return to the
device defaults. Firmware, compiled signing keys, deployment OAuth/discovery
endpoints, configured OTA CA trust, and OTA security/rollback metadata survive.
The ESP-IDF Wi-Fi NVS partition is erased; Wi-Fi calibration is regenerated.
That erase is only one reset step: the application configuration is also rebuilt
and monitoring state is cleared. Separate partitions do not mean those contents
are retained by factory reset.
It does not delete the backend's processor/monitor records.

If power is interrupted during setup, the next boot prompts for Wi-Fi again.
If connection fails, the device restarts into setup for another attempt. After
successful connection it saves setup completion and prints the OAuth login URL;
authorize in your browser to finish registration. Login interrupted after Wi-Fi
setup resumes on the next boot without entering Wi-Fi again. The default name
is rebuilt from the MAC. Neither reset is accepted during an OTA installation or
pending health confirmation. Logical deletion of credentials from the separate
configuration partition is not guaranteed forensic erasure.

Run `python3 tests/integration/test_serial_emulator.py --factory-reset` to test the
confirmed reset, interruption before password entry, reboot/resume, hidden
password validation, Wi-Fi connection, and continuation to OAuth using a
synthetic local authority (no real account is reset).

### Initial flashing

For end-user first installation, download the Live factory `.bin` from the
[latest public release](https://github.com/Mungert69/NetworkMonitorProcessorAgentEmbedded/releases/latest)
and follow [First ESP32-S3 board: Live setup](first-physical-board.md). That is
the supported public procedure; it uses a single prebuilt image and does not
require ESP-IDF. The developer-only `tools/device.sh` flow below this document
is for locally built images and must not be substituted for the public guide.

The root CMake project runs host tests against actual native firmware code, not
a copied Linux processor. See [the test instructions](developer-reference.md#tests).
