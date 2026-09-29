# First ESP32-S3 board: dev setup

This procedure is for a **new ESP32-S3 with 16 MB flash and 8 MB PSRAM**. Run
the commands from this repository's root on a Linux host with local ESP-IDF 6.1
through EIM, `jq`, a
USB data cable, and access to the serial port. It uses the dev backend. For a
live board, choose `firmware/config/appsettings-live.json` and keep its private
configuration in a separate directory.

## 1. Identify and inspect the board

Connect the board's USB-to-UART port. Either `/dev/ttyACM*` or `/dev/ttyUSB*`
may appear, depending on the bridge. Use the stable by-id path:

```sh
ls -l /dev/serial/by-id/
BOARD_PORT=/dev/serial/by-id/YOUR-BOARD
```

Restore the existing OTA signing key at
`../securefiles/private-ota-signing-key.pem` with mode `600`, then build and
inspect:

```sh
./tools/build-firmware.sh
./tools/device.sh inspect --port "$BOARD_PORT"
```

The inspection reads the chip, MAC, flash size, and development security
eFuses. It requires an ESP32-S3 with 16 MB flash. PSRAM is checked by the
firmware on boot; the serial preflight cannot confirm its size. Neither of
these commands writes to the device. Keep the MAC shown by `inspect` for the
flash confirmation prompt.

## 2. Prepare private configuration

Use a 2.4 GHz Wi-Fi network. Create the password file in a private directory
with a text editor; do not put the password on a shell command line. The file
must contain the password, optionally followed by one newline.

```sh
install -d -m 700 runtime/my-new-board
${EDITOR:-vi} runtime/my-new-board/wifi-password.txt
chmod 600 runtime/my-new-board/wifi-password.txt
python3 tools/prepare_config.py \
  --config firmware/config/appsettings-dev.json \
  --wifi-ssid YOUR_2_4_GHZ_SSID \
  --wifi-password-file runtime/my-new-board/wifi-password.txt \
  --output runtime/my-new-board/config.json
```

The generated config uses in-app OAuth device authorization. `runtime/` is
ignored by Git; keep both private files backed up securely. No .NET processor
or copied token is needed for this setup. The device derives its processor
identity from its own Wi-Fi MAC during enrollment.

## 3. Flash once and watch first boot

```sh
./tools/device.sh flash --port "$BOARD_PORT" \
  --config runtime/my-new-board/config.json
./tools/device.sh monitor --port "$BOARD_PORT"
```

The flash command repeats the chip/eFuse checks and reads the full 2 MiB
`nmdata` state partition. It refuses nonblank processor state, then asks you
to type the board's MAC before writing. It flashes the bootloader, partition
table, OTA selector, private config, and signed application. It does not erase
the processor state partition or burn eFuses. If automatic download mode fails,
hold BOOT, tap RESET/EN, and retry.

In the 115200-baud serial monitor, confirm the firmware reports 16 MB flash
and 8 MB PSRAM, joins Wi-Fi, and prints the OAuth sign-in URL and user code.
Open that URL on another device, authorize the code, then watch for successful
registration and `ESP32_S3_MQTT_READY`. After assigning monitors, look for
accepted host commands, probe results, backend data saves, and
`removePingInfos` acknowledgements. A broker publish acknowledgement alone
does not clear pending ping data.

If the Wi-Fi details were wrong, the serial setup flow prompts for corrected
details; see [serial Wi-Fi setup](guide.md#factory-reset-and-usb-wi-fi-setup-017). If OAuth is
interrupted, reboot and follow the displayed device-flow instructions.

### PSRAM verification and early-boot failures

`Found 8MB PSRAM device` confirms the detected density, but by itself does not
prove memory is usable. The diagnostic in `tests/hardware/psram_probe/` now
verifies both the full ESP-IDF boot memory test and a 7 MiB address-dependent
write/read pattern.

Historical hardware check (before the current IDF 6.1 migration): on the
attached ESP32-S3 rev v0.2 board, ESP-IDF v5.5.5 with QIO flash at 80 MHz and
octal PSRAM at 40 MHz booted successfully. The serial log identified
flash as 16 MB MXIC and PSRAM as AP (`vendor 0x0d`, `device 0x02`, 64 Mbit),
reported `Found 8MB PSRAM device`, passed `SPI SRAM memory test OK`, and
reported `PSRAM_PROBE_PASS checked_bytes=7340032`. This confirms the board has
8 MiB of addressable, working PSRAM under this configuration. The probe is
**not** a processor image or OTA artifact. It was flashed only to the test
board's `ota_0` app slot at `0x20000`; do not flash it to a working processor.

Earlier DIO-mode trials on the experimental boards ended at `cpu_start:
Multicore app` with `RTCWDT_RTC_RST`; disabling the boot memory test moved the
failure to an `IllegalInstruction` before `app_main`. A DIO 20 MHz flash trial
with octal PSRAM at 40 MHz also failed. The subsequent QIO/80 MHz run passed,
so the previous blanket conclusion that these boards cannot use PSRAM was too
strong. The successful trial changed flash mode and frequency together, so it
does not isolate which change resolved startup. Quad PSRAM mode still fails
with `quad_psram: PSRAM chip is not connected, or wrong PSRAM line mode`; this
board requires octal PSRAM mode.

[Espressif issue #18806](https://github.com/espressif/esp-idf/issues/18806)
describes a similar ESP32-S3 rev v0.2 / AP octal PSRAM startup failure, but the
successful test above shows that this attached board can pass the full memory
test and exercise most of its PSRAM. Issue
[#11567](https://github.com/espressif/esp-idf/issues/11567) concerns a
different 32 MB PSRAM module with an unknown vendor ID, so it is not evidence
that this N16R8 board has counterfeit or incorrectly sized memory.

## Subsequent updates

Use signed HTTPS OTA for later application updates. OTA keeps the private
config and monitor state. Do not run the initial flash command on an enrolled
board or copy an enrolled flash image to another board. This development
profile does not enable Secure Boot or flash encryption; use test credentials
until the hardware security process is in place.
