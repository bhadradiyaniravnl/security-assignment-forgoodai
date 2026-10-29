"""Canary matching across the encodings an exfil attempt is likely to use.

Covers plain, base64 (all three byte alignments, so a canary embedded in a larger
base64 blob is still found), hex and URL-encoding, plus one level of base64 decoding
of the whole payload. Known gaps: encryption, compression, splitting across requests.
"""
from __future__ import annotations

import base64
import binascii
import re
import urllib.parse

_B64_RUN = re.compile(rb"[A-Za-z0-9+/=_-]{16,}")


def _b64_variants(value: bytes) -> list[bytes]:
    out = []
    for pad in range(3):
        enc = base64.b64encode(b"\0" * pad + value)
        # drop chars influenced by the padding prefix and by the unknown suffix
        start = {0: 0, 1: 2, 2: 3}[pad]
        core = enc[start:len(enc) - 4]
        if len(core) >= 8:
            out += [core, core.replace(b"+", b"-").replace(b"/", b"_")]
    return out


def _needles(canary: str) -> dict[str, list[bytes]]:
    raw = canary.encode()
    return {
        "plain": [raw],
        "base64": _b64_variants(raw),
        "hex": [raw.hex().encode(), raw.hex().upper().encode()],
        "urlencoded": [urllib.parse.quote(canary, safe="").encode(), urllib.parse.quote_plus(canary).encode()],
    }


def scan(data: bytes, canaries: list[dict]) -> dict | None:
    """canaries: [{"id": ..., "value": ...}]. Returns the first match or None."""
    if not data or not canaries:
        return None
    for c in canaries:
        for encoding, needles in _needles(c["value"]).items():
            if any(n in data for n in needles):
                return {"id": c["id"], "encoding": encoding}
        for run in _B64_RUN.findall(data):
            try:
                decoded = base64.b64decode(run + b"=" * (-len(run) % 4), altchars=b"-_" if b"-" in run or b"_" in run else None)
            except (binascii.Error, ValueError):
                continue
            if c["value"].encode() in decoded:
                return {"id": c["id"], "encoding": "base64-decoded"}
    return None
