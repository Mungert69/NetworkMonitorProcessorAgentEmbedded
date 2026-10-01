"""Embed public test fixtures only; rejects unrecognised fixture names."""
import json
import pathlib
import sys

directory = pathlib.Path(sys.argv[1])
names = {"public.pem": "public", "mldsa-public.pem": "mldsa_public", "target.txt": "target",
         "ecdsa-0.json": "ecdsa_0", "ecdsa-50.json": "ecdsa_50",
         "mldsa-0.json": "mldsa_0", "mldsa-50.json": "mldsa_50"}
text = "/* Public synthetic fixtures, never enrollment credentials. */\n"
for name, symbol in names.items():
    text += f"static const char benchmark_{symbol}[] = {json.dumps((directory/name).read_text())};\n"
(directory/"benchmark_fixtures.h").write_text(text)
