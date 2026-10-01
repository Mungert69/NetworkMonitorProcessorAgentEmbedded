"""Reset the hardware trial and capture its bounded test run over USB."""
import argparse
import os
import pathlib
import sys
import time
import serial


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[3]
    output = args.output.resolve()
    if output == root or root in output.parents:
        parser.error("Serial logs must be saved outside the repository")
    os.umask(0o077)
    with serial.Serial(args.port, 115200, timeout=1, exclusive=True) as port:
        port.dtr = False
        port.rts = True
        time.sleep(0.1)
        port.rts = False
        deadline = time.monotonic() + 180
        with output.open("wb") as log:
            while time.monotonic() < deadline:
                line = port.readline()
                log.write(line)
                log.flush()
                text = line.decode("utf-8", errors="replace")
                print(text, end="", flush=True)
                if "QUANTUM_BOARD_RESULT" in text:
                    return 0 if "passed=15 total=15" in text else 1
                if any(marker in text for marker in ("Guru Meditation", "QUANTUM_BOARD_NETWORK_FAILED",
                                                     "QUANTUM_BOARD_TASK_FAILED")):
                    return 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
