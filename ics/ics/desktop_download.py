"""Office Unbound Desktop for Windows, downloaded from our own servers (owner 2026-11-25: "the app needs to be able to be directly
downloaded from the ui"; not from GitHub).

ICS side: the console serves the same file from the ICS's own copy (ICS_DESKTOP_WINDOWS_DIR, default
/var/lib/office-unbound/desktop/windows), the contents of the very `ou-desktop-windows` package the deployments install
(blueprints/build/desktop-windows-deb/build-deb.sh, docs/desktop/download.md). Only the file
the manifest names is ever served, and only after its bytes hash to the manifest's sha256 (the verified result is cached per file
identity: device, inode, size, mtime). Copied from portal/app/desktop_download.py (the portal and the ICS ship separately); keep the two in step.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import threading
from pathlib import Path

DEFAULT_DIR = "/var/lib/office-unbound/desktop/windows"
MAX_MANIFEST = 4096
CHUNK = 256 * 1024
FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}\.(exe|msi)$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.]{1,40})?$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
TYPES = {"exe": "application/vnd.microsoft.portable-executable", "msi": "application/x-msi"}

_lock = threading.Lock()
_verified: dict[tuple, bool] = {}   # (path, dev, ino, size, mtime_ns, sha256) -> the bytes hashed to sha256


class Unavailable(Exception):
    """No (valid) manifest or no installer: the download is not offered."""


class Mismatch(Exception):
    """The installer on disk is not the one the manifest names (hash or size): never served."""


def manifest(directory: str | os.PathLike) -> dict | None:
    """The validated manifest, or None when there is none or it is malformed (then nothing is offered)."""
    p = Path(directory) / "manifest.json"
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        raw = os.read(fd, MAX_MANIFEST + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_MANIFEST:
        return None
    try:
        m = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(m, dict) or m.get("schema") != 1 or m.get("platform") != "windows-x64":
        return None
    f, v, h, n = m.get("file"), m.get("version"), m.get("sha256"), m.get("size")
    if not (isinstance(f, str) and FILE_RE.match(f) and isinstance(v, str) and VERSION_RE.match(v) and isinstance(h, str) and SHA_RE.match(h)
            and isinstance(n, int) and not isinstance(n, bool) and 0 < n <= 2 * 1024 ** 3):
        return None
    return {"product": "Office Unbound Desktop", "platform": "windows-x64", "version": v, "file": f, "sha256": h, "size": n,
            "unsigned": m.get("unsigned") is not False, "stage": m.get("stage") if m.get("stage") in ("alpha", "beta", "stable") else "alpha",
            "content_type": TYPES[f.rsplit(".", 1)[1]]}


def open_verified(directory: str | os.PathLike) -> tuple[dict, int]:
    """(manifest, open file descriptor at offset 0) of the installer whose bytes match the manifest. The caller owns the descriptor and
    streams from it, so the bytes served are the bytes that were hashed (a file replaced after the check is not what is sent)."""
    m = manifest(directory)
    if m is None:
        raise Unavailable("no manifest")
    path = str(Path(directory) / m["file"])
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise Unavailable("no installer") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Unavailable("installer is not a regular file")
        if st.st_size != m["size"]:
            raise Mismatch("size differs from the manifest")
        key = (path, st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, m["sha256"])
        with _lock:
            ok = _verified.get(key)
        if ok is None:
            h = hashlib.sha256()
            while b := os.read(fd, CHUNK):
                h.update(b)
            ok = h.hexdigest() == m["sha256"]
            with _lock:
                if len(_verified) > 64:
                    _verified.clear()
                _verified[key] = ok
            os.lseek(fd, 0, os.SEEK_SET)
        if not ok:
            raise Mismatch("sha256 differs from the manifest")
        return m, fd
    except BaseException:
        os.close(fd)
        raise


def chunks(fd: int, size: int):
    """The installer's bytes (exactly `size`), then the descriptor is closed."""
    try:
        left = size
        while left > 0:
            b = os.read(fd, min(CHUNK, left))
            if not b:
                break
            left -= len(b)
            yield b
    finally:
        os.close(fd)


def human_size(n: int) -> str:
    return f"{n / 1024 ** 2:.1f} MB" if n >= 1024 ** 2 else f"{max(1, round(n / 1024))} KB"
