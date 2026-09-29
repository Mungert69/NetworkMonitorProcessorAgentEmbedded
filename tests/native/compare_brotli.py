"""Compare complete streams against the same pinned unmodified encoder."""
from pathlib import Path
import subprocess
import sys
import tempfile

with tempfile.TemporaryDirectory(prefix="nm-brotli-q0-") as a, \
     tempfile.TemporaryDirectory(prefix="nm-brotli-ref-") as b:
    subprocess.run([sys.argv[1], a], check=True)
    subprocess.run([sys.argv[2], b], check=True)
    files = sorted(Path(a).glob("*.br"))
    assert len(files) == 78
    for path in files:
        assert path.read_bytes() == (Path(b) / path.name).read_bytes(), path.name
    print("All 78 compressed streams match upstream quality zero byte-for-byte")
