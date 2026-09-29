#!/usr/bin/env python3
"""Generate a quality-zero-only encode.c from the pinned, unmodified upstream.

Keep upstream allocation, streaming, bounds and fallback logic. Constant quality
lets compiler/linker garbage collection remove other encoders. Never edit the
managed dependency in place; fail closed when upgrading its source.
"""
import hashlib
from pathlib import Path
import sys

SOURCE_SHA256 = "79c4bca6f88d3c8725642c01c7a470d768312d573193a600bd13a02d657b06f7"


def specialize(source: bytes) -> str:
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise ValueError("Brotli encode.c changed: review quality-zero specialization before building")
    text = source.decode("utf-8")

    def replace(old: str, new: str) -> None:
        nonlocal text
        if text.count(old) != 1:
            raise ValueError(f"Brotli specialization anchor mismatch: {old!r}")
        text = text.replace(old, new)

    replace("state->params.quality = (int)value;",
            "if (value != 0) return BROTLI_FALSE;\n      state->params.quality = 0;")
    replace("params->quality = BROTLI_DEFAULT_QUALITY;", "params->quality = 0;")
    replace("BrotliInitSharedEncoderDictionary(&params->dictionary);",
            "/* Q0 never uses a static or prepared dictionary. */\n"
            "  memset(&params->dictionary, 0, sizeof(params->dictionary));")
    replace("BrotliCleanupSharedEncoderDictionary(m, &params->dictionary);",
            "/* No dictionary allocation exists in this profile. */\n  (void)m; (void)params;")
    # All occurrences are reads, not assignments, in the hash-pinned source.
    text = text.replace("s->params.quality", "0 /* quality-zero-only */")
    replace("  size_t out_size = *encoded_size;",
            "  if (quality != 0) return BROTLI_FALSE;\n  size_t out_size = *encoded_size;")
    replace("  params.quality = quality;",
            "  if (quality != 0) return 0;\n  params.quality = 0;")
    # Prepared dictionaries are not supported by the fast Q0 algorithm.
    start = text.index("  ManagedDictionary* managed_dictionary = NULL;",
                       text.index("BrotliEncoderPrepareDictionary("))
    end = text.index("\n}\n", start)
    text = text[:start] + ("  (void)type; (void)size; (void)data; (void)quality;\n"
                          "  (void)alloc_func; (void)free_func; (void)opaque;\n"
                          "  return NULL;") + text[end:]
    start = text.index("  /* First field of dictionary structs */",
                       text.index("BrotliEncoderAttachPreparedDictionary("))
    end = text.index("\n}\n", start)
    text = text[:start] + "  (void)state; (void)dictionary;\n  return BROTLI_FALSE;" + text[end:]
    return text


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: specialize_brotli.py UPSTREAM_ENCODE_C GENERATED_ENCODE_C")
    result = specialize(Path(sys.argv[1]).read_bytes())
    target = Path(sys.argv[2])
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists() or target.read_text() != result:
        target.write_text(result)
