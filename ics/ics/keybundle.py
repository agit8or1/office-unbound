"""Encrypted, explicit transfer of controller secrets to a standby (ADR-0012). STANDALONE: stdlib + `cryptography` only, so
bootstrap.sh can run it before the ICS venv exists:  python3 -I keybundle.py {export|import|inspect} ...

Format: b"OUKB1\\n" | salt(16) | nonce(12) | AES-256-GCM(scrypt(passphrase) , json) ; the header (magic+salt) is authenticated data.
The passphrase is generated at export (160 bits), printed once, and travels out of band (never with the bundle).
Contents: file name -> bytes (vault.key, audit.key, ics-signing.key, ics.env, ics-migrate.env, replicator password, primary CA) + metadata.
Only fixed file names are accepted on import (no paths), and files are created 0600/0640 with O_EXCL-style replace semantics.
"""
import argparse
import base64
import getpass
import json
import os
import secrets
import sys
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"OUKB1\n"
ALLOWED = {"vault.key": 0o640, "audit.key": 0o640, "ics-signing.key": 0o640, "ics.env": 0o640, "ics-migrate.env": 0o600,
           "replicator.pw": 0o600, "primary-ca.crt": 0o644}
_N, _R, _P = 2**15, 8, 1


class BundleError(Exception):
    pass


def new_passphrase() -> str:
    raw = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")   # 160 bits
    return "-".join(raw[i:i + 8] for i in range(0, len(raw), 8))


def _key(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=_N, r=_R, p=_P).derive(passphrase.encode())


def seal(files: dict[str, bytes], meta: dict, passphrase: str) -> bytes:
    for n in files:
        if n not in ALLOWED:
            raise BundleError(f"file not allowed in a bundle: {n}")
    payload = json.dumps({"meta": meta, "files": {n: base64.b64encode(b).decode() for n, b in files.items()}}, sort_keys=True).encode()
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    return MAGIC + salt + nonce + AESGCM(_key(passphrase, salt)).encrypt(nonce, payload, MAGIC + salt)


def unseal(blob: bytes, passphrase: str) -> tuple[dict, dict[str, bytes]]:
    if not blob.startswith(MAGIC) or len(blob) < len(MAGIC) + 28 + 16:
        raise BundleError("not an Office Unbound key bundle")
    salt, nonce, ct = blob[6:22], blob[22:34], blob[34:]
    try:
        payload = json.loads(AESGCM(_key(passphrase, salt)).decrypt(nonce, ct, MAGIC + salt))
    except Exception:  # noqa: BLE001 - wrong passphrase or tampering are indistinguishable by design
        raise BundleError("bundle cannot be decrypted (wrong passphrase or modified file)") from None
    files = {n: base64.b64decode(v) for n, v in payload["files"].items()}
    bad = [n for n in files if n not in ALLOWED]
    if bad:
        raise BundleError(f"bundle contains unexpected file names: {bad}")
    return payload["meta"], files


def _passphrase(args) -> str:
    if args.passphrase_file:
        return open(args.passphrase_file).read().strip()
    return getpass.getpass("bundle passphrase: ")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("export")
    e.add_argument("--etc", default="/etc/office-unbound")
    e.add_argument("--out", required=True)
    e.add_argument("--passphrase-out", required=True, help="file (0600) that receives the generated passphrase")
    e.add_argument("--replicator-password-file", required=True)
    e.add_argument("--primary-ip", required=True)
    e.add_argument("--primary-ca", required=True)
    for n in ("import", "inspect"):
        i = sub.add_parser(n)
        i.add_argument("--bundle", required=True)
        i.add_argument("--passphrase-file")
        if n == "import":
            i.add_argument("--etc", default="/etc/office-unbound")
            i.add_argument("--owner-group", default="ics")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "export":
            files = {n: open(os.path.join(a.etc, n), "rb").read() for n in ("vault.key", "audit.key", "ics-signing.key", "ics.env", "ics-migrate.env")}
            files["replicator.pw"] = open(a.replicator_password_file, "rb").read().strip()
            files["primary-ca.crt"] = open(a.primary_ca, "rb").read()
            pw = new_passphrase()
            blob = seal(files, {"primary_ip": a.primary_ip, "exported_at": int(time.time()), "format": 1}, pw)
            for path, data in ((a.out, blob), (a.passphrase_out, (pw + "\n").encode())):
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                os.write(fd, data)
                os.close(fd)
            print(f"bundle written to {a.out} ({len(blob)} bytes); passphrase in {a.passphrase_out}: carry them by DIFFERENT channels, then shred both")
            return 0
        meta, files = unseal(open(a.bundle, "rb").read(), _passphrase(a))
        if a.cmd == "inspect":
            print(json.dumps({"meta": meta, "files": sorted(files)}))
            return 0
        import grp
        gid = grp.getgrnam(a.owner_group).gr_gid
        for n, data in files.items():
            dst = os.path.join(a.etc, n)
            if n == "replicator.pw":
                dst = os.path.join(a.etc, "replicator.pw")
            tmp = dst + ".new"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.write(fd, data)
            os.fchown(fd, 0, 0 if ALLOWED[n] == 0o600 else gid)
            os.fchmod(fd, ALLOWED[n])
            os.close(fd)
            os.replace(tmp, dst)
        print(json.dumps({"imported": sorted(files), "meta": meta}))
        return 0
    except (BundleError, OSError) as ex:
        print(f"keybundle: {ex}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
