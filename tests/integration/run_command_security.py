"""Run the actual IDF crypto verifier in an isolated, network-free emulator."""
import os
from pathlib import Path
import subprocess
import sys
import time

directory = Path(sys.argv[1])
log = directory / "serial.log"
emulator = os.environ.get("ESP_EMU_BIN", str(Path.home() / ".local/bin/esp-emu"))
with log.open("w") as output:
    process = subprocess.Popen([
        emulator, "--chip", "esp32s3", "--elf",
        str(directory / "build/command_security_test.elf"),
        "--firmware", str(directory / "flash.bin"), "--psram-size", "8M",
    ], stdout=output, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            text = log.read_text(errors="replace")
            if "COMMAND_SECURITY_INTEGRATION_PASS" in text:
                print("IDF 6.1 signature integration passed; log:", log)
                break
            if (process.poll() is not None or "assert failed" in text or
                    "Guru Meditation" in text or "Task watchdog got triggered" in text):
                raise RuntimeError(f"Signature integration failed: {log}")
            time.sleep(0.25)
        else:
            raise RuntimeError(f"Signature integration timed out: {log}")
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
