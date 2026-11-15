#!/usr/bin/env python3
"""Generate the Office Unbound placeholder brand assets (original artwork: an open ring = "unbound").
Pure python, deterministic. Output dir given as argv[1] (default ../debian/branding).
Replace with final brand artwork later; the package build only copies these files, nothing else depends on them."""
import math
import os
import struct
import sys
import zlib

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "debian", "branding")
os.makedirs(OUT, exist_ok=True)
BLUE = (0x1F, 0x6F, 0xEB)

ICON_SVG = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><path d="M50 12a38 38 0 1 0 38 38" fill="none" '
            'stroke="#1f6feb" stroke-width="14" stroke-linecap="round"/></svg>\n')
LOGO_SVG = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 420 100"><path d="M50 12a38 38 0 1 0 38 38" fill="none" '
            'stroke="#1f6feb" stroke-width="14" stroke-linecap="round"/><text x="112" y="66" font-family="Roboto,Arial,sans-serif" '
            'font-size="46" font-weight="600" fill="#3f3f3f">Office Unbound</text></svg>\n')
open(os.path.join(OUT, "grommunio_icon.svg"), "w").write(ICON_SVG)
open(os.path.join(OUT, "grommunio-logo.svg"), "w").write(LOGO_SVG)


def covered(x, y):
    """ring with a gap in the upper right (angle 270..360 deg measured clockwise from 3 o'clock is open)"""
    dx, dy = x - 50, y - 50
    r = math.hypot(dx, dy)
    ang = math.degrees(math.atan2(dy, dx)) % 360    # 0 = right, 90 = down
    if 31 <= r <= 45 and not (270 <= ang <= 355):
        return True
    for a in (270, 355):                              # round caps
        cx, cy = 50 + 38 * math.cos(math.radians(a)), 50 + 38 * math.sin(math.radians(a))
        if math.hypot(x - cx, y - cy) <= 7:
            return True
    return False


def png(size):
    ss = 3
    rows = []
    for py in range(size):
        row = bytearray([0])
        for px in range(size):
            hit = 0
            for sy in range(ss):
                for sx in range(ss):
                    if covered((px + (sx + .5) / ss) * 100 / size, (py + (sy + .5) / ss) * 100 / size):
                        hit += 1
            a = round(255 * hit / (ss * ss))
            row += bytes((*BLUE, a))
        rows.append(bytes(row))
    raw = b"".join(rows)

    def chunk(t, d):
        c = struct.pack(">I", len(d)) + t + d
        return c + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def ico(sizes):
    imgs = [png(s) for s in sizes]
    head = struct.pack("<HHH", 0, 1, len(sizes))
    off = 6 + 16 * len(sizes)
    ent = b""
    for s, im in zip(sizes, imgs):
        ent += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(im), off)
        off += len(im)
    return head + ent + b"".join(imgs)


for s in (192, 512):
    open(os.path.join(OUT, f"grommunio_icon_{s}.png"), "wb").write(png(s))
data = ico([16, 32, 48])
for n in ("favicon.ico", "grommunio.ico"):
    open(os.path.join(OUT, n), "wb").write(data)
print("wrote brand assets to", OUT)
