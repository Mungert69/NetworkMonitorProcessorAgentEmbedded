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

The firmware is in preview, and there is currently no public first-install
image. New boards cannot yet be set up through this repository's releases.
When a signed factory image is published, it can be flashed over USB without
giving users the signing key. Do not use an image intended for a different
ESP32 board.

When a first-install image is available, connect to its USB serial console at
115200 baud and watch its startup logs. The device asks for the Wi-Fi SSID and
password without echoing the password. After it connects, the logs display an
OAuth sign-in URL and user code. Open the URL in a browser, enter the code,
and sign in to your Network Monitor account. The device then registers to your
account. Add hosts from the dashboard and assign them to this processor.

The [download page](https://readyforquantum.com/Download) has current product
information and support contact details.

## Monitoring support

This embedded processor supports ICMP ping, DNS, TCP connection, HTTP/HTTPS,
and passive Bluetooth LE broadcast monitoring. It does not currently support
command-running processors or every endpoint available in the Windows and
Docker agents. BLE monitoring requires the ESP32 board to be within radio range
of the broadcasting device.

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
