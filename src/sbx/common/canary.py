"""Canary matching across the encodings an exfil attempt is likely to use.

Canaries are fake secrets planted in each session (values come from the control plane's policy
lookup). Any outbound byte stream that contains one is proof of an exfiltration attempt, whatever
the destination. The gateway scans every model request, tool_use input and plain-HTTP egress
request with this; the control plane and the security test harness reuse it.

Covers plain, base64 (all three byte alignments, so a canary embedded in a larger
base64 blob is still found), hex and URL-encoding, plus one level of base64 decoding
of every base64-looking run in the payload. Known gaps: encryption, compression,
splitting across requests. This is a tripwire, not a DLP engine: it decides nothing on its own,
it only labels evidence (canary_match) that the sentinel acts on.
"""
from __future__ import annotations

import base64
import binascii
import re
import urllib.parse

_BASE64_RUN = re.compile(rb"[A-Za-z0-9+/=_-]{16,}")


def _base64_substrings(value: bytes) -> list[bytes]:
    """Stable inner substrings of base64(value) at each of the 3 possible byte offsets.

    base64 encodes 3 bytes at a time, so how `value` encodes depends on where it starts inside
    the larger blob; we encode with 0-2 prefix bytes and keep only the characters that depend
    solely on `value` (plus the URL-safe alphabet variant).
    """
    out = []
    for pad in range(3):
        enc = base64.b64encode(b"\0" * pad + value)
        # drop chars influenced by the padding prefix and by the unknown suffix
        start = {0: 0, 1: 2, 2: 3}[pad]
        core = enc[start:len(enc) - 4]
        if len(core) >= 8:
            out += [core, core.replace(b"+", b"-").replace(b"/", b"_")]
    return out


def _encoded_forms(canary: str) -> dict[str, list[bytes]]:
    """encoding name -> byte strings whose presence means the canary is in the payload."""
    raw = canary.encode()
    return {
        "plain": [raw],
        "base64": _base64_substrings(raw),
        "hex": [raw.hex().encode(), raw.hex().upper().encode()],
        "urlencoded": [urllib.parse.quote(canary, safe="").encode(), urllib.parse.quote_plus(canary).encode()],
    }


def scan(data: bytes, canaries: list[dict]) -> dict | None:
    """Look for any canary in `data`.

    canaries: [{"id": ..., "value": ...}]. Returns {"id", "encoding"} for the first match, or None.
    """
    if not data or not canaries:
        return None
    for canary in canaries:
        for encoding, needles in _encoded_forms(canary["value"]).items():
            if any(needle in data for needle in needles):
                return {"id": canary["id"], "encoding": encoding}
        for run in _BASE64_RUN.findall(data):
            try:
                decoded = base64.b64decode(run + b"=" * (-len(run) % 4), altchars=b"-_" if b"-" in run or b"_" in run else None)
            except (binascii.Error, ValueError):
                continue
            if canary["value"].encode() in decoded:
                return {"id": canary["id"], "encoding": "base64-decoded"}
    return None
