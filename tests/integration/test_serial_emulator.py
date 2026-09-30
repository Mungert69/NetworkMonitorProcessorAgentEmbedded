#!/usr/bin/env python3
"""Exercise UART re-registration with synthetic credentials, no live identity.

Run from repository root after building firmware:
python3 tests/integration/test_serial_emulator.py
Requires local ESP-IDF 6.1 through EIM and esp-emu. Creates private fixtures under build/.
"""
import csv
import argparse
import json
import os
import pathlib
import signal
import struct
import subprocess
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]


def blobs(image, start, end):
    """Read currently written NVS blob chunks/indexes for test assertions only."""
    chunks, indexes = {}, {}
    for offset in range(start, end, 4096):
        page = image[offset:offset+4096]
        seq = struct.unpack_from("<I", page, 4)[0]
        for i in range(126):
            if (page[32+i//4] >> ((i%4)*2)) & 3 != 2:
                continue
            pos = 64+i*32
            entry = page[pos:pos+32]
            key = entry[8:24].split(b"\0")[0]
            if entry[1] == 0x42:
                size = struct.unpack_from("<H", entry, 24)[0]
                chunks.setdefault((key,entry[3]), []).append((seq,i,page[pos+32:pos+32+size]))
            elif entry[1] == 0x48:
                indexes.setdefault(key, []).append((seq,i,struct.unpack_from("<I",entry,24)[0],entry[28],entry[29]))
    result = {}
    for key, records in indexes.items():
        _, _, size, count, first = max(records)
        payload = b"".join(max(chunks[(key,n)])[2] for n in range(first,first+count))
        result[key.decode()] = json.loads(payload[:size])
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--factory-reset",action="store_true")
    args=parser.parse_args()
    os.umask(0o077)
    work = pathlib.Path(tempfile.mkdtemp(prefix="serial-test-", dir=ROOT/"firmware/build"))
    cfg = {"AuthDevice":False,"IsQuantumCapable":False,"wifi_ssid":"myssid",
           "wifi_password":"mypassword","broker_uri":"mqtt://127.0.0.1:1",
           "mqtt_username":"test","mqtt_password":"synthetic-token",
           "auth_key":"synthetic-key","app_id":"serial-fixture","source":"https://fixture.invalid",
           "BaseFusionAuthURL":"https://127.0.0.1:1","DeviceName":"serial.test","AppName":"Lab",
           "max_monitors":50,"max_pending_ping_infos":500,"poll_seconds":60}
    (work/"config.json").write_text(json.dumps(cfg))
    # Raw seed blobs exercise reset of a pre-compression/legacy state. The
    # production compressed monitoring writer is covered by psram_memory.
    values={"monitors":[{"ID":1,"Address":"127.0.0.1"}],
            "processor":{"MonitorPingInfos":[],"PingInfos":[{"ID":1}],"PiIDKey":2},
            "monitoring":{"MonitorIPs":[],"ProcessorData":{"MonitorPingInfos":[],
                          "PingInfos":[],"PiIDKey":2}},
            "fwmeta":{"AcceptedVersion":"0.1.5"}}
    relative=work.relative_to(ROOT/"firmware")
    with (work/"state.csv").open("w",newline="") as stream:
        writer=csv.writer(stream)
        writer.writerow(("key","type","encoding","value"))
        writer.writerow(("networkmonitor","namespace","",""))
        for key,value in values.items():
            (work/(key+".json")).write_text(json.dumps(value))
            writer.writerow((key,"file","binary",str(relative/(key+".json"))))
    command=(f'python "{ROOT}/tools/nvs_config.py" --config {relative}/config.json '
             f'--output {relative}/config.bin && '
             'python "$IDF_PATH/components/nvs_flash/nvs_partition_generator/nvs_partition_gen.py" '
             f'generate {relative}/state.csv {relative}/state.bin 0x200000')
    subprocess.run([str(ROOT/"tools/idf-local.sh"),"bash","-c",command],
                   cwd=ROOT/"firmware",check=True,capture_output=True)
    image=bytearray(b"\xff"*(16*1024*1024))
    build=ROOT/"firmware/build"
    # esp-emu needs the matching ELF to intercept the ESP32-S3 BLE controller;
    # without it the production scanner starves IDLE0 before enrollment.
    elf=build/"networkmonitor_processor_esp32.elf"
    if not elf.is_file():
        raise FileNotFoundError(f"Build the production firmware first: {elf}")
    for offset,path in [(0,build/"bootloader/bootloader.bin"),(0x8000,build/"partition_table/partition-table.bin"),
                        (0xf000,build/"ota_data_initial.bin"),(0x12000,work/"config.bin"),
                        (0x20000,build/"networkmonitor_processor_esp32.bin"),(0xc20000,work/"state.bin")]:
        content=path.read_bytes(); image[offset:offset+len(content)]=content
    flash=work/"runtime.bin"; flash.write_bytes(image)
    emulator=pathlib.Path(os.environ.get("ESP_EMU_BIN",str(pathlib.Path.home()/".local/bin/esp-emu")))
    log=work/"serial.log"
    with log.open("wb") as output:
        proc=subprocess.Popen([str(emulator),"--chip","esp32s3","--elf",str(elf),"--firmware",str(flash),
                               "--psram-size","8M","--net","user","--save-state","--timeout","100s"],
                              stdin=subprocess.PIPE,stdout=output,stderr=subprocess.STDOUT)
        def wait_for(text, timeout=45):
            deadline=time.monotonic()+timeout
            while time.monotonic()<deadline:
                if text in log.read_text(errors="replace"): return
                if proc.poll() is not None: break
                time.sleep(.2)
            raise AssertionError(f"Missing serial marker: {text}; inspect {log}")
        try:
            wait_for("Serial commands:")
            command=b"factory-reset" if args.factory_reset else b"reregister"
            proc.stdin.write(command+b"\ncancel\n"); proc.stdin.flush()
            wait_for("Reset cancelled.")
            assert "Re-register request saved" not in log.read_text(errors="replace")
            assert "Factory reset request saved" not in log.read_text(errors="replace")
            proc.stdin.write(command+b"\nconfirm "+command+b"\n"); proc.stdin.flush()
            if args.factory_reset:
                wait_for("Factory reset applied:")
                wait_for("Wi-Fi SSID (1-32 bytes):")
                proc.stdin.write(b"myssid\r\n"); proc.stdin.flush()
                wait_for("Wi-Fi password (8-63 bytes; input hidden):")
                # Interrupt setup before the password is entered.
            else:
                wait_for("Re-register request saved")
                wait_for("Re-register applied:")
        finally:
            if proc.poll() is None: proc.send_signal(signal.SIGINT)
            proc.wait(timeout=30)
    saved=flash.read_bytes()
    config=blobs(saved,0x12000,0x20000)["config"]
    assert config["AuthDevice"] is True
    for key in ("mqtt_password","mqtt_username","auth_key","app_id","MonitorLocation"):
        assert key not in config
    if args.factory_reset:
        assert config["WiFiSetup"] is True
        for key in ("wifi_ssid","wifi_password","DeviceName","AppName"):
            assert key not in config
    else:
        for key in ("wifi_ssid","wifi_password","DeviceName","AppName"):
            assert config[key]==cfg[key]
    state=blobs(saved,0xc20000,0xe20000)
    assert "monitors" not in state and "processor" not in state and "monitoring" not in state
    assert state["fwmeta"]==values["fwmeta"]
    assert saved[0x20000:0x620000]==image[0x20000:0x620000]
    if args.factory_reset:
        log=work/"serial-resume.log"
        with log.open("wb") as output:
            proc=subprocess.Popen([str(emulator),"--chip","esp32s3","--elf",str(elf),"--firmware",str(flash),
                                   "--psram-size","8M","--net","user","--save-state","--timeout","100s"],
                                  stdin=subprocess.PIPE,stdout=output,stderr=subprocess.STDOUT)
            try:
                wait_for("Wi-Fi SSID (1-32 bytes):")
                proc.stdin.write(b"myssid\r\n"); proc.stdin.flush()
                wait_for("Wi-Fi password (8-63 bytes; input hidden):")
                proc.stdin.write(b"q7!4\r\n"); proc.stdin.flush()
                wait_for("Invalid password length/input")
                proc.stdin.write(b"mypassword\r\n"); proc.stdin.flush()
                wait_for("Wi-Fi setup complete. Starting browser authorization.")
                # The fixture authority deliberately refuses connections; we
                # prove continuation without involving a real user/token.
                # BLE scanner startup precedes enrollment and can take much
                # longer than guest time under emulation on slower hosts.
                wait_for("ESP32_S3_ENROLLMENT_FAILED", timeout=180)
            finally:
                if proc.poll() is None: proc.send_signal(signal.SIGINT)
                proc.wait(timeout=30)
        assert "mypassword" not in log.read_text(errors="replace")
        assert "q7!4" not in log.read_text(errors="replace")
        saved=flash.read_bytes()
        config=blobs(saved,0x12000,0x20000)["config"]
        assert config["WiFiSetup"] is False and config["AuthDevice"] is True
        assert config["wifi_ssid"]=="myssid" and config["wifi_password"]=="mypassword"
        assert "auth_key" not in config and "mqtt_password" not in config
        assert blobs(saved,0xc20000,0xe20000)["fwmeta"]==values["fwmeta"]
        assert saved[0x20000:0x620000]==image[0x20000:0x620000]
        print("PASS: factory reset, interrupted/resumed setup, hidden password, Wi-Fi connection and OAuth continuation")
        print("Synthetic fixture logs:",log)
        return
    print("PASS: UART cancellation, confirmation, reboot, persisted enrollment reset; Wi-Fi/firmware/OTA metadata preserved")
    print("Synthetic fixture logs:",log)


if __name__ == "__main__":
    main()
