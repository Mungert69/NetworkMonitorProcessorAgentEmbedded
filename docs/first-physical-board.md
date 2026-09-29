# First ESP32-S3 board: Live setup

This is the end-user procedure for a **new ESP32-S3 with 16 MB flash and 8 MB
octal PSRAM**, such as the ESP32-S3-DevKitC-1-N16R8. It uses the Live backend.
No ESP-IDF installation, signing key, .NET processor, copied token, or manual
appsettings editing is required.

## 1. Download the factory image

Download `networkmonitor-esp32-s3-live-factory.zip` from the
[latest GitHub release](https://github.com/Mungert69/NetworkMonitorProcessorAgentEmbedded/releases/latest).
Extract it. The archive contains one versioned factory `.bin` and
`SHA256SUMS.txt`. Verify the image before flashing:

```sh
sha256sum -c SHA256SUMS.txt
```

On Windows, use `Get-FileHash -Algorithm SHA256 <image-file>` and compare its
output with the matching line in `SHA256SUMS.txt`.

## 2. Install the serial flashing tool

Install Python 3, create a virtual environment, and install Espressif's
`esptool` in it. This is the small flashing utility, not the ESP-IDF firmware
development toolchain:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install esptool
```

On Windows PowerShell, use `py -m venv .venv`, then
`.venv\Scripts\Activate.ps1`; install with `python -m pip install esptool`.
On Linux, the account must have access to the serial device (often by joining
the `dialout` group and signing in again).

## 3. Erase and flash the new board

Connect the board using a USB data cable. Find its port: `/dev/ttyACM0` or
`/dev/ttyUSB0` on Linux, `/dev/cu.*` on macOS, or `COM3` (for example) on
Windows. For a new board that is not entering download mode automatically,
hold **BOOT**, tap **RESET/EN**, then release **BOOT**.

The following commands erase the entire flash, then write the single factory
image at address `0x0`. **This permanently removes any existing firmware,
Wi-Fi settings, credentials and saved processor state. Use only for a new
board. Never use this procedure to update an enrolled processor.** It does not
burn eFuses.

```sh
python -m esptool --chip esp32s3 --port YOUR_PORT erase-flash
python -m esptool --chip esp32s3 --port YOUR_PORT write-flash 0x0 networkmonitor-esp32-s3-live-factory-VERSION.bin
```

Replace `YOUR_PORT` and `VERSION` with the actual port and image version. For
example, Linux users may use `/dev/ttyACM0`. Keep the flash mode options at
their defaults; the image includes the tested bootloader configuration.

## 4. Connect Wi-Fi and authorize

Open the USB serial console at **115200 baud**. For example, with the same
Python environment:

```sh
python -m serial.tools.miniterm YOUR_PORT 115200
```

The device asks for the 2.4 GHz Wi-Fi SSID and password. Type each at its
prompt; the firmware does not echo the input. After connecting, it prints an
OAuth sign-in URL and user code. Open the URL in a browser, enter the code,
and authorize with your Network Monitor account. Watch the serial output for
successful registration and `ESP32_S3_MQTT_READY`. Keep the serial log private
while the short-lived code is visible.

## 5. Assign hosts and update later

In the website dashboard, add hosts and assign them to this processor. The
ESP32-S3 supports ICMP, DNS, TCP, HTTP/HTTPS and passive BLE broadcast
monitoring; it does not support command processors or every endpoint offered
by the Windows and Docker agents.

For later firmware upgrades or downgrades, use **Profile → Device firmware**
on the website. OTA preserves the device's Wi-Fi and account configuration.
Do not repeat the erase-and-flash procedure for updates.

If Wi-Fi setup or OAuth is interrupted, restart the board and follow the
serial prompts again. The device resumes from its saved setup stage.

## Security note

Firmware application images are signed and verified by the device. Hardware
Secure Boot and flash encryption are not enabled in this preview, so physical
access to a board can expose saved credentials. Protect the device and use
the normal OTA update route after first installation.
