# Network Monitor for ESP32-S3

Run a small, dedicated Network Monitor processor on an ESP32-S3. The firmware
connects over Wi-Fi, authorizes with your Network Monitor account, and reports
monitoring results to the dashboard.

## Supported hardware

The current firmware is built and tested for an **ESP32-S3 board with 16 MB
flash and 8 MB octal PSRAM**, such as the ESP32-S3-DevKitC-1-N16R8. Other
memory sizes or PSRAM modes are not currently supported by this setup guide.
The board also needs a USB data connection and a 2.4 GHz Wi-Fi network.

## First-time setup

Download the versioned **Live factory `.bin`** and `SHA256SUMS.txt` from the
[latest GitHub release](https://github.com/Mungert69/NetworkMonitorProcessorAgentEmbedded/releases/latest).
The single `.bin` contains the signed firmware application, Live service
settings, and interactive Wi-Fi setup. It does not contain a Wi-Fi password,
account token, or processor identity. Follow the concise
[first-board setup guide](docs/first-physical-board.md); it covers flashing,
the serial OAuth sign-in, and assigning hosts. Do not use this factory image
to update an enrolled board; use **Profile → Device firmware** instead.

The [website download page](https://readyforquantum.com/Download) also links to
this image and the same setup procedure.

## Monitoring support

This embedded processor supports ICMP ping, DNS, TCP connection, HTTP/HTTPS,
and passive Bluetooth LE broadcast monitoring. It does not currently support
command-running processors or every endpoint available in the Windows and
Docker agents. BLE monitoring requires the ESP32 board to be within radio range
of the broadcasting device.

The current firmware also includes quantum key-exchange and quantum-certificate
probes. The documented Live first-install package is published separately from
the OTA application image.

## License

Project-authored code and documentation are licensed under the
[GNU General Public License, version 3 only](LICENSE) (GPL-3.0-only).
Third-party components retain their own licenses; see
[licensing and release requirements](docs/licensing.md). The wolfSSL-backed
quantum firmware must be distributed with its corresponding source. Earlier
versions released under MIT remain available under their original terms.

## Firmware updates and recovery

After registration, choose **Profile → Device firmware** on the website to
select an available firmware image for the processor. The device installs
updates over signed HTTPS and keeps its Wi-Fi and account configuration.

To re-register the device, open its USB serial console at 115200 baud, type
`reregister`, then type `confirm reregister` within 30 seconds. This clears its
saved account authorization and monitoring state, preserves Wi-Fi, and starts
the browser sign-in flow again. To return to Wi-Fi setup as well, use
`factory-reset` followed by `confirm factory-reset`. The device prints the
available serial commands when it starts; both reset actions require physical
USB access and confirmation.

## For developers

The implementation notes, build prerequisites, architecture, tests and release
procedures are in the [developer reference](docs/developer-reference.md).
Review [AGENTS.md](AGENTS.md) before changing firmware code.

Firmware v0.3.0 is GPL-3.0-only and links GPLv3 wolfSSL. See
[third-party notices](THIRD_PARTY_NOTICES.md) and
[release source requirements](docs/licensing.md) before redistributing images.
