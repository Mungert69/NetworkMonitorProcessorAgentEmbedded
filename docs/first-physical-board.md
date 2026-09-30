# First ESP32-S3 board: Live setup

This is the end-user procedure for a **new ESP32-S3 with 16 MB flash and 8 MB
octal PSRAM**, such as the ESP32-S3-DevKitC-1-N16R8. It uses the Live backend.
No ESP-IDF installation, signing key, .NET processor, copied token, or manual
appsettings editing is required.

## 1. Download the factory image

Download the versioned factory `.bin` and `SHA256SUMS.txt` from the
[latest GitHub release](https://github.com/Mungert69/NetworkMonitorProcessorAgentEmbedded/releases/latest).
Keep both files in the same directory. The current v0.2.2 image is named
`networkmonitor-esp32-s3-live-factory-0.2.2.bin`; use the exact filename shown
on the release page if you download a later version.

Verify the image before flashing. On Linux:

```sh
sha256sum -c SHA256SUMS.txt
```

On macOS, run `shasum -a 256 networkmonitor-esp32-s3-live-factory-0.2.2.bin`
and compare its hash with `SHA256SUMS.txt`. In Windows PowerShell, run
`Get-FileHash .\networkmonitor-esp32-s3-live-factory-0.2.2.bin -Algorithm SHA256`
and compare the `Hash` value with that file.

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

## 3. Find the board's serial port

Connect the board using a USB data cable, then run:

```sh
python -m serial.tools.list_ports -v
```

Use the port reported for the ESP32-S3: it commonly looks like
`/dev/ttyACM0` or `/dev/ttyUSB0` on Linux, `/dev/cu.usbmodem…` on macOS, or
`COM3` on Windows. On Linux, `ls -l /dev/serial/by-id/` may show a stable
device-specific path. In the examples below, replace `/dev/ttyACM0` or `COM3`
with the exact port reported on your computer.

## 4. Erase and flash the new board

If a new board does not automatically enter download mode, hold **BOOT**, tap
**RESET/EN**, then release **BOOT**.

The following commands erase the entire flash, then write the single factory
image at address `0x0`. **This permanently removes any existing firmware,
Wi-Fi settings, credentials and saved processor state. Use only for a new
board. Never use this procedure to update an enrolled processor.** It does not
burn eFuses.

On Linux or macOS, from the directory containing the downloaded `.bin`:

```sh
python -m esptool --chip esp32s3 --port /dev/ttyACM0 erase-flash
python -m esptool --chip esp32s3 --port /dev/ttyACM0 write-flash 0x0 networkmonitor-esp32-s3-live-factory-0.2.2.bin
```

For example, if the port listing showed `/dev/ttyUSB0`, replace both instances
of `/dev/ttyACM0` with `/dev/ttyUSB0`. If you downloaded a later release, use
its exact `.bin` filename in the second command. In Windows PowerShell, use
the same commands with the port and filename in variables:

```powershell
$Port = "COM3"
$Image = "networkmonitor-esp32-s3-live-factory-0.2.2.bin"
python -m esptool --chip esp32s3 --port $Port erase-flash
python -m esptool --chip esp32s3 --port $Port write-flash 0x0 $Image
```

Set `$Port` to the reported COM port, and `$Image` to the exact `.bin` filename
you downloaded. Keep the flash mode options at their defaults; the image
includes the tested bootloader configuration.

## 5. Connect Wi-Fi and authorize

Open the USB serial console at **115200 baud**. For example, with the same
Python environment:

```sh
python -m serial.tools.miniterm /dev/ttyACM0 115200
```

Substitute the same serial port you used to flash (for example `COM3` on
Windows or `/dev/cu.usbmodem…` on macOS).

The device asks for the 2.4 GHz Wi-Fi SSID and password. Type each at its
prompt; the firmware does not echo the input. After connecting, it prints an
line beginning `nm_enrollment: Sign in at`, followed by an HTTPS URL and a
short user code. Copy only the URL (not the trailing `; code ...`) into a
browser on your computer or phone. Leave the board powered and the serial
console open. Sign in with your Network Monitor account and approve the
device; if the page asks for a code, enter the code printed on the serial
console. The URL may already include it.

Return to the serial console and wait for successful registration and
`ESP32_S3_MQTT_READY`. Browser approval alone does not confirm registration.
If the code expires, restart the board to obtain a new URL and code. Keep
the serial log private while the short-lived code is visible.

Erasing flash clears the board's local configuration and saved monitoring
state, so Wi-Fi setup and browser authorization are required again. It does
not delete your website's processor or host records. Registering the same
board to the same account can restore its previously assigned hosts from
the backend; that does not mean the erase failed.

## 6. Assign hosts and update later

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
