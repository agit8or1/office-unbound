"""IMAP modified UTF-7 (RFC 3501 5.1.3) for mailbox names."""
from __future__ import annotations

import base64
import re


def encode(s: str) -> str:
    out, buf = [], []

    def flush():
        if buf:
            b = "".join(buf).encode("utf-16-be")
            out.append("&" + base64.b64encode(b).decode().rstrip("=").replace("/", ",") + "-")
            buf.clear()

    for ch in s:
        if 0x20 <= ord(ch) <= 0x7E:
            flush()
            out.append("&-" if ch == "&" else ch)
        else:
            buf.append(ch)
    flush()
    return "".join(out)


def decode(s: str) -> str:
    def rep(m):
        t = m.group(1)
        if t == "":
            return "&"
        t = t.replace(",", "/")
        t += "=" * (-len(t) % 4)
        try:
            return base64.b64decode(t, validate=True).decode("utf-16-be", "replace")
        except ValueError:      # binascii.Error: hostile/broken name from the source must not crash the run
            return m.group(0)

    return re.sub(r"&([^-]*)-", rep, s)
