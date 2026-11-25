"""The ICS's own copy of Office Unbound Desktop for Windows, filled automatically from the published, signed `ou-desktop-windows` deb in
this host's artifact tree (owner 2026-11-25: "yes, have the ICS extract it automatically"). The console serves it (downloads_api).

What is extracted and how it is trusted (the guests' own trust path, ADR-0015):
  1. the version is the catalog pin of the portal component (blueprints/catalog/components/portal.yaml), never "latest"; no pin = nothing to do
  2. the channel's InRelease in the PUBLISHED tree (<data_dir>/apt/current) must verify with gpgv against the channel key pinned in the
     publisher's own configuration (server.json `channel_fprs`, keys/ou-release-<channel>.pub.asc; the key file must hash to that fingerprint),
     must be for that suite and not expired
  3. main/binary-amd64/Packages must match the signed InRelease (size + sha256); its stanza for exactly the pinned version names the deb
  4. the deb (copied while hashed, so the parsed bytes are the checked bytes) must match the stanza's size + sha256
  5. data.tar.{xz,gz} members: directories and regular files only (no symlink, hard link, device, fifo), no absolute path, no `..`, and only
     under usr/share/ou-desktop/windows/ (extracted: manifest.json + the installer it names) or usr/share/doc/ou-desktop-windows/ (ignored)
  6. the extracted installer must hash to the manifest's sha256 (desktop_download.open_verified)
Replacement is atomic: extract into releases/.tmp-*, rename to releases/<version>-<deb sha256[:12]>, then flip the `windows` symlink with
os.replace. The previous release stays until the flip succeeded (and one older is kept for rollback). Any failure leaves the current copy as it
is and is audited once (`desktop.installer.refused`); a successful flip is audited as `desktop.installer.extracted` (version, sha256).

When it runs: the worker leader calls tick() at start and every SYNC_SECONDS (the publisher's atomic `current` flip is detected by the changed
InRelease; an unchanged tree and pin cost two stat calls). `python -m ics.desktop_sync` runs the same pass once right after a publication.
No API and no parameters: nothing a caller sends decides what is read, run or written."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import logging
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path

from . import audit, desktop_download
from .artifacts import REPO_SUITE, _dearmor, pgp_fingerprint

log = logging.getLogger("ics.desktop_sync")
PACKAGE = "ou-desktop-windows"
PAYLOAD = "usr/share/ou-desktop/windows/"
DOCS = "usr/share/doc/ou-desktop-windows/"
SYNC_SECONDS = 300
MAX_DEB = 512 * 1024 ** 2
MAX_MEMBERS = 64
CHUNK = 1 << 20
DEFAULT_ETC = "/etc/office-unbound/artifacts"
ALLOWED_DIRS = {"/".join(p.strip("/").split("/")[:i]) for p in (PAYLOAD, DOCS) for i in range(1, len(p.strip("/").split("/")) + 1)}
_state: dict = {"key": None, "next": 0.0, "result": None}


class Refused(Exception):
    pass


# ---------------------------------------------------------------------------------------------------------------- inputs
def catalog_pin(cat=None) -> tuple[str, str] | None:
    """(package version, apt suite) the portal component pins, or None."""
    if cat is None:
        from .deploy.catalog import load_catalog
        cat = load_catalog()
    comp = cat.components.get("portal")
    for a in (comp.artifacts if comp else []):
        if a.kind == "package" and a.package == PACKAGE:
            suite = REPO_SUITE.get(a.repo)
            if suite is None:
                raise Refused(f"the {PACKAGE} pin must come from our own repository, not {a.repo}")
            return a.version, suite
    return None


def channel(etc: str, suite: str) -> tuple[str, Path, str]:
    """(pinned fingerprint, apt tree root, armored key) from the publisher's configuration."""
    try:
        c = json.loads((Path(etc) / "server.json").read_text())
    except (OSError, ValueError):
        raise Refused("no artifact service configuration (server.json)") from None
    fpr = ((c.get("channel_fprs") or {}).get(suite) or "").upper()
    if not re.fullmatch(r"[0-9A-F]{40}", fpr):
        raise Refused(f"no pinned key for channel {suite}")
    try:
        armored = (Path(etc) / "keys" / f"ou-release-{suite}.pub.asc").read_text()
    except OSError:
        raise Refused(f"no key file for channel {suite}") from None
    if pgp_fingerprint(armored) != fpr:
        raise Refused(f"the key file of channel {suite} does not match its pinned fingerprint")
    return fpr, Path(c.get("data_dir") or "/var/lib/office-unbound/artifacts") / "apt" / "current", armored


# ---------------------------------------------------------------------------------------------------------------- apt trust path
def verify_inrelease(path: Path, armored: str, fpr: str, suite: str, now: float) -> str:
    with tempfile.TemporaryDirectory() as t:
        kr, out = Path(t) / "k.gpg", Path(t) / "out"
        kr.write_bytes(_dearmor(armored))
        try:
            v = subprocess.run(["gpgv", "--keyring", str(kr), "--status-fd", "1", "--output", str(out), str(path)],
                               env={"PATH": "/usr/bin:/bin", "LANG": "C"}, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            raise Refused("gpgv could not run") from None
        sig = [ln.split() for ln in v.stdout.splitlines() if ln.startswith("[GNUPG:] VALIDSIG")]
        if v.returncode != 0 or not sig or not any(x[2].upper() == fpr or (len(x) > 11 and x[11].upper() == fpr) for x in sig):
            raise Refused(f"InRelease of {suite} is not signed by the pinned key")
        text = out.read_text(errors="replace")
    if not re.search(rf"^Suite:\s*{re.escape(suite)}\s*$", text, re.M):
        raise Refused("InRelease is for another suite")
    m = re.search(r"^Valid-Until:\s*(.+)$", text, re.M)
    if m:
        try:
            vu = time.mktime(time.strptime(m.group(1).strip().replace("UTC", "GMT"), "%a, %d %b %Y %H:%M:%S %Z")) - time.timezone
        except ValueError:
            raise Refused("InRelease has an unreadable Valid-Until") from None
        if vu < now:
            raise Refused("InRelease has expired")
    return text


def _release_hashes(text: str) -> dict:
    files, on = {}, False
    for ln in text.splitlines():
        if ln.startswith("SHA256:"):
            on = True
            continue
        if on:
            if not ln.startswith(" "):
                break
            p = ln.split()
            if len(p) == 3 and p[1].isdigit():
                files[p[2]] = (p[0], int(p[1]))
    return files


def _sha(p: Path) -> tuple[str, int]:
    h, n = hashlib.sha256(), 0
    with open(p, "rb", opener=lambda f, fl: os.open(f, fl | os.O_NOFOLLOW)) as f:
        while b := f.read(CHUNK):
            h.update(b)
            n += len(b)
    return h.hexdigest(), n


def _stanzas(raw: bytes) -> list[dict]:
    out = []
    for blk in raw.decode("utf-8", "replace").split("\n\n"):
        d = {}
        for ln in blk.splitlines():
            if ln[:1] not in (" ", "\t") and ":" in ln:
                k, _, v = ln.partition(":")
                d[k] = v.strip()
        if d:
            out.append(d)
    return out


def find_deb(tree: Path, suite: str, text: str, version: str) -> tuple[Path, str, int]:
    listed = _release_hashes(text)
    for name, opener in (("main/binary-amd64/Packages", lambda b: b), ("main/binary-amd64/Packages.gz", gzip.decompress)):
        if name in listed:
            p = tree / "dists" / suite / name
            if not p.is_file() or _sha(p) != listed[name]:
                raise Refused(f"{name} does not match the signed InRelease")
            raw = opener(p.read_bytes())
            break
    else:
        raise Refused("the signed InRelease lists no Packages index")
    hits = [s for s in _stanzas(raw) if s.get("Package") == PACKAGE and s.get("Version") == version]
    if len(hits) != 1:
        raise Refused(f"{PACKAGE} {version} is not in the signed {suite} index")
    s = hits[0]
    fn, h, size = s.get("Filename", ""), s.get("SHA256", ""), s.get("Size", "")
    parts = fn.split("/")
    if not fn.startswith(f"pool/{suite}/") or fn.startswith("/") or ".." in parts or "" in parts or not fn.endswith(".deb"):
        raise Refused("unsafe Filename in the index")
    if not re.fullmatch(r"[0-9a-f]{64}", h) or not size.isdigit() or not 0 < int(size) <= MAX_DEB:
        raise Refused("the index has no valid SHA256/Size for the package")
    return tree / fn, h, int(size)


def copy_verified(src: Path, sha: str, size: int, dst: Path) -> None:
    """Copy while hashing; the copy is what gets parsed, so the bytes cannot change between check and use."""
    try:
        fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise Refused("the package file is missing") from None
    with os.fdopen(fd, "rb") as f, open(dst, "wb") as o:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise Refused("the package is not a regular file")
        h, n = hashlib.sha256(), 0
        while b := f.read(CHUNK):
            n += len(b)
            if n > size:
                raise Refused("the package does not match the signed index (larger than listed)")
            h.update(b)
            o.write(b)
    if n != size or h.hexdigest() != sha:
        raise Refused("the package does not match the signed index")


# ---------------------------------------------------------------------------------------------------------------- deb payload
def _ar_members(raw: bytes) -> dict[str, bytes]:
    if not raw.startswith(b"!<arch>\n"):
        raise Refused("not a deb (ar) file")
    out, i = {}, 8
    while i < len(raw):
        if i + 60 > len(raw) or raw[i + 58:i + 60] != b"`\n":
            raise Refused("corrupt ar header")
        name = raw[i:i + 16].decode("ascii", "replace").strip().rstrip("/")
        try:
            n = int(raw[i + 48:i + 58].decode("ascii").strip())
        except ValueError:
            raise Refused("corrupt ar member size") from None
        out[name] = raw[i + 60:i + 60 + n]
        i += 60 + n + (n & 1)
    return out


def extract_payload(deb: Path, dest: Path) -> list[str]:
    ar = _ar_members(deb.read_bytes())
    if ar.get("debian-binary", b"").strip() != b"2.0":
        raise Refused("unsupported deb format")
    data = [(k, v) for k, v in ar.items() if k.startswith("data.tar")]
    if len(data) != 1 or data[0][0] not in ("data.tar.xz", "data.tar.gz"):
        raise Refused("data member must be data.tar.xz or data.tar.gz")
    mode = "r:xz" if data[0][0].endswith(".xz") else "r:gz"
    wrote = []
    try:
        with tarfile.open(fileobj=io.BytesIO(data[0][1]), mode=mode) as tf:
            members = tf.getmembers()
            if len(members) > MAX_MEMBERS:
                raise Refused("too many members in the package")
            for m in members:
                name = m.name[2:] if m.name.startswith("./") else m.name
                parts = [p for p in name.split("/") if p and p != "."]
                if m.name.startswith("/") or ".." in parts or "\\" in name:
                    raise Refused(f"unsafe member path {m.name!r}")
                if not (m.isdir() or m.isreg()):
                    raise Refused(f"member {m.name!r} is not a regular file or directory")
                rel = "/".join(parts)
                if m.isdir():
                    if rel and rel not in ALLOWED_DIRS:
                        raise Refused(f"unexpected directory {rel!r}")
                    continue
                if rel.startswith(DOCS) and "/" not in rel[len(DOCS):]:
                    continue
                leaf = rel[len(PAYLOAD):] if rel.startswith(PAYLOAD) else ""
                if not leaf or "/" in leaf or not (leaf == "manifest.json" or desktop_download.FILE_RE.match(leaf)):
                    raise Refused(f"unexpected file {rel!r}")
                src = tf.extractfile(m)
                with open(dest / leaf, "xb") as o:   # x: never through an existing name
                    shutil.copyfileobj(src, o)
                os.chmod(dest / leaf, 0o644)
                wrote.append(leaf)
    except (tarfile.TarError, EOFError, OSError, ValueError) as e:
        if isinstance(e, FileExistsError):
            raise Refused("duplicate member in the package") from None
        raise Refused(f"cannot read the package payload ({type(e).__name__})") from None
    return wrote


# ---------------------------------------------------------------------------------------------------------------- the pass
def sync(rt, cat=None, now: float | None = None, force: bool = False) -> dict:
    """One pass. Returns {status: no_pin|current|extracted|unchanged_input|refused, ...}."""
    s = rt.settings
    target = Path(s.desktop_windows_dir)
    base = target.parent
    rels = base / "releases"
    key = version = None
    try:
        pin = catalog_pin(cat)
        if pin is None:
            _state.update(key=None, result={"status": "no_pin"})
            return {"status": "no_pin"}
        version, suite = pin
        fpr, tree, armored = channel(getattr(s, "desktop_artifacts_etc", DEFAULT_ETC), suite)
        inrel = tree / "dists" / suite / "InRelease"
        try:
            st = inrel.stat()
        except OSError:
            raise Refused(f"no published {suite} channel") from None
        key = (str(tree.resolve()), st.st_ino, st.st_mtime_ns, st.st_size, version, suite, os.path.realpath(target))
        if not force and key == _state["key"] and _state["result"]:
            return {**_state["result"], "status": "unchanged_input" if _state["result"]["status"] == "refused" else _state["result"]["status"]}
        text = verify_inrelease(inrel, armored, fpr, suite, now or time.time())
        deb, deb_sha, deb_size = find_deb(tree, suite, text, version)
        name = f"{re.sub(r'[^A-Za-z0-9.+~-]', '_', version)}-{deb_sha[:12]}"
        if os.path.realpath(target) == str((rels / name).resolve()) and desktop_download.manifest(target):
            res = {"status": "current", "package_version": version, "release": name}
            _state.update(key=key, result=res)
            return res
        rels.mkdir(parents=True, exist_ok=True)
        tmp = Path(tempfile.mkdtemp(prefix=".tmp-", dir=rels))
        try:
            copy_verified(deb, deb_sha, deb_size, tmp / "pkg.deb")
            out = tmp / "out"
            out.mkdir()
            wrote = extract_payload(tmp / "pkg.deb", out)
            m = desktop_download.manifest(out)
            if m is None:
                raise Refused("the package carries no valid manifest")
            if sorted(wrote) != sorted({"manifest.json", m["file"]}):
                raise Refused("the package payload is not exactly the manifest and the installer it names")
            try:
                _, fd = desktop_download.open_verified(out)
                os.close(fd)
            except desktop_download.Unavailable:
                raise Refused("the installer the manifest names is missing") from None
            except desktop_download.Mismatch as e:
                raise Refused(f"installer: {e}") from None
            os.chmod(out, 0o755)
            final = rels / name
            if final.exists():
                shutil.rmtree(final)
            os.rename(out, final)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        previous = os.path.realpath(target) if target.is_symlink() else None
        if target.exists() and not target.is_symlink():       # a hand-placed copy: kept as the previous release, then replaced
            previous = str(rels / f"manual-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}")
            os.rename(target, previous)
        link = base / ".windows.new"
        if link.is_symlink() or link.exists():
            link.unlink()
        os.symlink(Path("releases") / name, link)
        os.replace(link, target)                               # atomic: readers see the old or the new release, never a mix
        keep = {name, os.path.basename(previous or "")}
        for old in rels.iterdir():
            if old.name not in keep and not old.name.startswith(".tmp-"):
                shutil.rmtree(old, ignore_errors=True)
        res = {"status": "extracted", "version": m["version"], "sha256": m["sha256"], "size": m["size"], "package_version": version,
               "deb_sha256": deb_sha, "release": name, "previous": os.path.basename(previous) if previous else None}
        with rt.session() as db:
            audit.append(db, "desktop.installer.extracted", actor_name="worker", resource="desktop_installer", resource_id=m["version"],
                         details={k: res[k] for k in ("version", "sha256", "size", "package_version", "deb_sha256", "release", "previous")})
            db.commit()
        log.info("desktop installer %s extracted (%s)", m["version"], name)
        _state.update(key=key, result=res)
        return res
    except Refused as e:
        res = {"status": "refused", "reason": str(e)}
        k = key
        if k is None or k != _state["key"] or force:           # audit a refusal once per input, not every pass
            log.error("desktop installer not extracted: %s", e)
            with rt.session() as db:
                audit.append(db, "desktop.installer.refused", actor_name="worker", resource="desktop_installer",
                             details={"reason": str(e)[:300], "package_version": version})
                db.commit()
        _state.update(key=k, result=res)
        return res


def tick(rt) -> dict | None:
    """Called by the worker leader: at start, then every SYNC_SECONDS."""
    if not getattr(rt.settings, "desktop_sync_enabled", True) or time.monotonic() < _state["next"]:
        return None
    _state["next"] = time.monotonic() + SYNC_SECONDS
    return sync(rt)


def main() -> int:   # pragma: no cover - thin wrapper; `sudo -u ics python -m ics.desktop_sync` after `ou-artifact-publish apt`
    from .config import load_settings
    from .runtime import Runtime
    rt = Runtime(load_settings())
    r = sync(rt, force=True)
    print(json.dumps(r))
    return 0 if r["status"] in ("extracted", "current", "no_pin") else 3


if __name__ == "__main__":   # pragma: no cover
    raise SystemExit(main())
