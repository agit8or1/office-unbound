"""Core of the root helper /usr/local/sbin/ou-console-access (ics/deploy/public-entry): replaces the nginx include that decides who may reach the
console under its public name. Standard library only; paths and commands are parameters so the tests run it against temporary files.

The ICS (settings.management.update) sends the rendered file on stdin. The helper trusts nothing in it: every line must be a comment,
`allow <address range>;`, `allow all;` or `deny all;`, so the input can never add any other nginx directive. The new file replaces the old one
atomically, `nginx -t` must accept it, otherwise the previous file is put back; only then is nginx reloaded."""
from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import sys

MAX_BYTES = 8192
_COMMENT = re.compile(r"^#[^\r\n]*$")
_ALLOW = re.compile(r"^allow ([0-9a-fA-F:./]+|all);$")
_DENY = re.compile(r"^deny all;$")


class Refused(Exception):
    pass


def validate(data: bytes) -> str:
    """The only accepted language: comment lines, `allow <cidr>;`, `allow all;`, `deny all;`. At least one allow/deny line."""
    if len(data) > MAX_BYTES:
        raise Refused(f"input larger than {MAX_BYTES} bytes")
    try:
        s = data.decode("ascii")
    except UnicodeDecodeError:
        raise Refused("input is not plain ASCII") from None
    rules = 0
    for n, line in enumerate(s.split("\n"), 1):
        if line == "" or _COMMENT.fullmatch(line):
            continue
        m = _ALLOW.fullmatch(line)
        if m:
            if m.group(1) != "all":
                try:
                    ipaddress.ip_network(m.group(1), strict=False)
                except ValueError:
                    raise Refused(f"line {n}: not an address range") from None
            rules += 1
            continue
        if _DENY.fullmatch(line):
            rules += 1
            continue
        raise Refused(f"line {n}: only comments, 'allow <address range>;', 'allow all;' and 'deny all;' are accepted")
    if not rules:
        raise Refused("no allow/deny line")
    return s if s.endswith("\n") else s + "\n"


def apply(text: str, target: str, test_cmd: list[str], reload_cmd: list[str]) -> str:
    """Write <target>.new, keep <target>.prev, rename into place, `nginx -t`; on failure put the previous file back. Returns a short message."""
    new, prev = target + ".new", target + ".prev"
    had_old = os.path.exists(target)
    old = None
    if had_old:
        with open(target, "rb") as f:
            old = f.read()
        _write(prev, old)
    _write(new, text.encode("ascii"))
    os.replace(new, target)
    t = subprocess.run(test_cmd, capture_output=True, text=True, timeout=60)
    if t.returncode != 0:
        if had_old:
            _write(new, old)
            os.replace(new, target)
        else:
            os.unlink(target)
        raise Refused("nginx rejected the configuration; the previous file was restored: " + (t.stderr or t.stdout).strip()[-300:])
    r = subprocess.run(reload_cmd, capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise Refused("configuration accepted but the nginx reload failed: " + (r.stderr or r.stdout).strip()[-300:])
    return "applied"


def _write(path: str, data: bytes) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def main(argv: list[str], stdin, target: str, test_cmd: list[str], reload_cmd: list[str]) -> int:
    if argv == ["apply", "--socket"]:
        # socket-activated (ou-console-access.socket, Accept=yes): stdin/stdout ARE the connection; the caller reads exactly one line
        try:
            text = validate(stdin.read(MAX_BYTES + 1))
            print("OK " + " ".join(str(apply(text, target, test_cmd, reload_cmd)).split())[:300], flush=True)
        except Refused as e:
            print("ERROR " + " ".join(str(e).split())[:400], flush=True)
        return 0
    if argv != ["apply"]:
        print("usage: ou-console-access apply  (the new access rules on stdin)", file=sys.stderr)
        return 2
    try:
        text = validate(stdin.read(MAX_BYTES + 1))
        print(apply(text, target, test_cmd, reload_cmd))
        return 0
    except Refused as e:
        print(f"ou-console-access: {e}", file=sys.stderr)
        return 1
