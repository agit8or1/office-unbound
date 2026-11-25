"""The ICS fills its copy of Office Unbound Desktop for Windows from the published, signed ou-desktop-windows deb (ics.desktop_sync).
A real signed apt tree (throw-away gpg keys), real debs from build-deb.sh with dummy installers, and hand-made malicious debs."""
import dataclasses
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import time
from pathlib import Path
from types import SimpleNamespace as NS

import pytest
from sqlalchemy import text

from ics import desktop_sync

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "blueprints/build/desktop-windows-deb/build-deb.sh"
pytestmark = pytest.mark.skipif(not (shutil.which("gpg") and shutil.which("gpgv") and shutil.which("dpkg-deb")), reason="gpg/gpgv/dpkg-deb missing")


def body(v: str) -> bytes:
    return f"MZ dummy Office Unbound Desktop {v}\x00".encode() * 3000


def cat(version="0.1.0-ou1", repo="ob-apt-dev", pkg="ou-desktop-windows"):
    arts = [NS(kind="package", package="ou-portal", version="0.5.4-ou1", repo="ob-apt-dev")]
    if version:
        arts.append(NS(kind="package", package=pkg, version=version, repo=repo))
    return NS(components={"portal": NS(artifacts=arts)})


class Repo:
    """Publisher side: keys, server.json, a published apt tree under <data_dir>/apt/current."""

    def __init__(self, tmp: Path):
        self.tmp, self.gh = tmp, tmp / "gh"
        self.gh.mkdir(mode=0o700)
        for who in ("a", "b"):
            assert self.gpg("--quick-generate-key", f"{who} <{who}@example.org>", "ed25519", "sign", "1d").returncode == 0
        self.fpr = {w: next(ln.split(":")[9] for ln in self.gpg("--list-keys", "--with-colons", f"{w}@example.org").stdout.splitlines()
                            if ln.startswith("fpr")) for w in "ab"}
        self.etc = tmp / "etc"
        (self.etc / "keys").mkdir(parents=True)
        (self.etc / "keys" / "ou-release-dev.pub.asc").write_text(self.gpg("--armor", "--export", "a@example.org").stdout)
        self.data = tmp / "data"
        (self.etc / "server.json").write_text(json.dumps({"data_dir": str(self.data), "channel_fprs": {"dev": self.fpr["a"]}}))
        self.debs: list[Path] = []
        self.n = 0

    def gpg(self, *a):
        return subprocess.run(["gpg", "--batch", "--no-tty", "--pinentry-mode", "loopback", "--passphrase", "", *a],
                              env={**os.environ, "GNUPGHOME": str(self.gh)}, capture_output=True, text=True)

    def build(self, version: str, data: bytes | None = None) -> Path:
        exe = self.tmp / f"in-{version}.exe"
        exe.write_bytes(data or body(version))
        out = self.tmp / "debs"
        r = subprocess.run(["bash", str(BUILD), str(exe), hashlib.sha256(exe.read_bytes()).hexdigest(), version, str(out)], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        return next(out.glob(f"ou-desktop-windows_{version.replace('-', '~')}-ou1_all.deb"))

    def publish(self, debs: list[tuple[Path, str]], signer="a", after=None):
        """debs: (file, version). A new release directory and an atomic `current` flip, like ou-artifact-publish."""
        self.n += 1
        rel = self.data / "apt" / "releases" / f"r{self.n}"
        pool = rel / "pool" / "dev" / "ou-desktop-windows"
        pool.mkdir(parents=True)
        st = []
        for f, ver in debs:
            shutil.copy(f, pool / f.name)
            b = (pool / f.name).read_bytes()
            st.append(f"Package: ou-desktop-windows\nVersion: {ver}\nArchitecture: all\nFilename: pool/dev/ou-desktop-windows/{f.name}\n"
                      f"Size: {len(b)}\nSHA256: {hashlib.sha256(b).hexdigest()}\n")
        pk = ("\n".join(st) + "\n").encode()
        d = rel / "dists" / "dev"
        (d / "main" / "binary-amd64").mkdir(parents=True)
        (d / "main" / "binary-amd64" / "Packages").write_bytes(pk)
        until = time.strftime("%a, %d %b %Y %H:%M:%S UTC", time.gmtime(time.time() + 86400))
        (d / "Release").write_text(f"Origin: t\nSuite: dev\nCodename: dev\nValid-Until: {until}\nSHA256:\n {hashlib.sha256(pk).hexdigest()} {len(pk)} main/binary-amd64/Packages\n")
        assert self.gpg("--local-user", f"{signer}@example.org", "--clearsign", "-o", str(d / "InRelease"), str(d / "Release")).returncode == 0
        if after:
            after(rel)
        cur = self.data / "apt" / "current"
        tmp = cur.with_name("current.new")
        tmp.symlink_to(rel)
        os.replace(tmp, cur)
        return rel


def evil_deb(path: Path, members: list[tuple[str, bytes | None, str]]) -> Path:
    """A deb with chosen data.tar.xz members: (name, content or None for a dir, type 'f'|'d'|'l'|'h')."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:xz") as tf:
        for name, data, kind in members:
            ti = tarfile.TarInfo(name)
            if kind == "d":
                ti.type = tarfile.DIRTYPE
                tf.addfile(ti)
            elif kind in ("l", "h"):
                ti.type = tarfile.SYMTYPE if kind == "l" else tarfile.LNKTYPE
                ti.linkname = "/etc/passwd"
                tf.addfile(ti)
            else:
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
    parts = [("debian-binary", b"2.0\n"), ("control.tar.xz", b"\xfd7zXZ"), ("data.tar.xz", buf.getvalue())]
    out = b"!<arch>\n"
    for n, d in parts:
        out += f"{n:<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(d):<10}`\n".encode() + d + (b"\n" if len(d) % 2 else b"")
    path.write_bytes(out)
    return path


def manifest_for(data: bytes, version="0.3.0", file="OfficeUnbound-Desktop-0.3.0-x64-setup.exe", **over) -> bytes:
    return json.dumps({"schema": 1, "platform": "windows-x64", "version": version, "file": file, "sha256": hashlib.sha256(data).hexdigest(),
                       "size": len(data), "unsigned": True, "stage": "alpha", **over}).encode()


@pytest.fixture()
def env(rt, tmp_path, monkeypatch, mk_user, login):
    desktop_sync._state.update(key=None, next=0.0, result=None)
    repo = Repo(tmp_path)
    target = tmp_path / "desktop" / "windows"
    target.parent.mkdir()
    monkeypatch.setattr(rt, "settings", dataclasses.replace(rt.settings, desktop_windows_dir=str(target), desktop_artifacts_etc=str(repo.etc)))
    c, _ = login(mk_user("ds-viewer", "viewer"))
    yield NS(rt=rt, repo=repo, target=target, c=c)
    desktop_sync._state.update(key=None, next=0.0, result=None)


def events(rt, action):
    with rt.session() as db:
        return [r.details for r in db.execute(text("SELECT details FROM audit_events WHERE action = :a ORDER BY seq"), {"a": action})]


def test_extracts_the_pinned_signed_deb_audits_and_the_console_serves_it(env):
    deb = env.repo.build("0.1.0")
    other = env.repo.build("0.2.0")                     # a newer version in the index is NOT taken: the pin decides
    env.repo.publish([(deb, "0.1.0-ou1"), (other, "0.2.0-ou1")])
    r = desktop_sync.sync(env.rt, cat("0.1.0-ou1"))
    assert r["status"] == "extracted" and r["version"] == "0.1.0" and r["sha256"] == hashlib.sha256(body("0.1.0")).hexdigest()
    assert env.target.is_symlink() and sorted(p.name for p in env.target.iterdir()) == ["OfficeUnbound-Desktop-0.1.0-x64-setup.exe", "manifest.json"]
    ev = events(env.rt, "desktop.installer.extracted")
    assert len(ev) == 1 and ev[0]["version"] == "0.1.0" and ev[0]["sha256"] == r["sha256"] and ev[0]["package_version"] == "0.1.0-ou1"
    got = env.c.get("/api/v1/downloads/desktop/windows")
    assert got.status_code == 200 and got.content == body("0.1.0")
    assert desktop_sync.sync(env.rt, cat("0.1.0-ou1"))["status"] == "current"          # unchanged input: no second extraction or event
    assert desktop_sync.sync(env.rt, cat("0.1.0-ou1"), force=True)["status"] == "current"
    assert len(events(env.rt, "desktop.installer.extracted")) == 1


def test_upgrade_flips_atomically_and_keeps_the_previous_release(env):
    env.repo.publish([(env.repo.build("0.1.0"), "0.1.0-ou1")])
    first = desktop_sync.sync(env.rt, cat("0.1.0-ou1"))["release"]
    env.repo.publish([(env.repo.build("0.1.0"), "0.1.0-ou1"), (env.repo.build("0.2.0"), "0.2.0-ou1")])
    r = desktop_sync.sync(env.rt, cat("0.2.0-ou1"))
    assert r["status"] == "extracted" and r["previous"] == first
    assert sorted(p.name for p in (env.target.parent / "releases").iterdir()) == sorted([first, r["release"]])
    assert env.c.get("/api/v1/downloads/desktop").json()["windows"]["version"] == "0.2.0"


def test_tampered_deb_is_refused_and_nothing_is_written(env):
    env.repo.publish([(env.repo.build("0.1.0"), "0.1.0-ou1")],
                     after=lambda rel: (lambda p: p.write_bytes(p.read_bytes() + b"x"))(next((rel / "pool/dev/ou-desktop-windows").glob("*.deb"))))
    r = desktop_sync.sync(env.rt, cat("0.1.0-ou1"))
    assert r["status"] == "refused" and "does not match the signed index" in r["reason"]
    assert not env.target.exists() and env.c.get("/api/v1/downloads/desktop").json() == {"windows": None}
    assert len(events(env.rt, "desktop.installer.refused")) == 1
    assert desktop_sync.sync(env.rt, cat("0.1.0-ou1"))["status"] == "unchanged_input"   # refused once per input, not audited every pass
    assert len(events(env.rt, "desktop.installer.refused")) == 1


def test_tampered_index_or_foreign_signature_is_refused(env):
    deb = env.repo.build("0.1.0")
    env.repo.publish([(deb, "0.1.0-ou1")], after=lambda rel: (rel / "dists/dev/main/binary-amd64/Packages").write_text(
        (rel / "dists/dev/main/binary-amd64/Packages").read_text().replace("Size:", "X-Evil: 1\nSize:")))
    r = desktop_sync.sync(env.rt, cat("0.1.0-ou1"))
    assert r["status"] == "refused" and "does not match the signed InRelease" in r["reason"]
    env.repo.publish([(deb, "0.1.0-ou1")], signer="b")
    r = desktop_sync.sync(env.rt, cat("0.1.0-ou1"))
    assert r["status"] == "refused" and "not signed by the pinned key" in r["reason"]
    env.repo.publish([(deb, "0.1.0-ou1")], after=lambda rel: (rel / "dists/dev/InRelease").write_text(
        (rel / "dists/dev/InRelease").read_text().replace("Suite: dev", "Suite: dex")))
    assert desktop_sync.sync(env.rt, cat("0.1.0-ou1"))["status"] == "refused"
    assert not env.target.exists()


def test_key_file_must_match_the_pinned_fingerprint(env):
    env.repo.publish([(env.repo.build("0.1.0"), "0.1.0-ou1")])
    (env.repo.etc / "server.json").write_text(json.dumps({"data_dir": str(env.repo.data), "channel_fprs": {"dev": env.repo.fpr["b"]}}))
    r = desktop_sync.sync(env.rt, cat("0.1.0-ou1"))
    assert r["status"] == "refused" and "pinned fingerprint" in r["reason"]


W = "usr/share/ou-desktop/windows/"
EXE = "OfficeUnbound-Desktop-0.3.0-x64-setup.exe"


@pytest.mark.parametrize("members,why", [
    ([(W + "../../../../tmp/evil", b"x", "f")], "unsafe member path"),
    ([("/etc/cron.d/evil", b"x", "f")], "unsafe member path"),
    ([(W + "manifest.json", None, "l")], "not a regular file"),
    ([(W + "x.exe", None, "h")], "not a regular file"),
    ([("./etc/evil", b"x", "f")], "unexpected file"),
    ([("./opt", None, "d")], "unexpected directory"),
    ([(W + "sub/x.exe", b"x", "f")], "unexpected file"),
])
def test_unsafe_members_are_refused(env, tmp_path, members, why):
    data = body("0.3.0")
    good = [("./usr", None, "d"), ("./usr/share", None, "d"), ("./usr/share/ou-desktop", None, "d"), ("./" + W, None, "d"),
            ("./" + W + "manifest.json", manifest_for(data), "f"), ("./" + W + EXE, data, "f")]
    deb = evil_deb(tmp_path / "ou-desktop-windows_0.3.0-ou1_all.deb", good + members)
    env.repo.publish([(deb, "0.3.0-ou1")])
    r = desktop_sync.sync(env.rt, cat("0.3.0-ou1"))
    assert r["status"] == "refused" and why in r["reason"], r
    assert not env.target.exists() and not (tmp_path / "evil").exists()
    assert not [p for p in (env.target.parent / "releases").iterdir()]       # the temp dir is gone too


def test_a_well_formed_hand_made_deb_is_accepted(env, tmp_path):
    data = body("0.3.0")
    deb = evil_deb(tmp_path / "ou-desktop-windows_0.3.0-ou1_all.deb", [("./" + W, None, "d"), ("./" + W + "manifest.json", manifest_for(data), "f"),
                                                                        ("./" + W + EXE, data, "f"), ("./usr/share/doc/ou-desktop-windows/copyright", b"c", "f")])
    env.repo.publish([(deb, "0.3.0-ou1")])
    assert desktop_sync.sync(env.rt, cat("0.3.0-ou1"))["status"] == "extracted"


def test_old_copy_kept_when_the_new_installer_fails_its_manifest(env, tmp_path):
    env.repo.publish([(env.repo.build("0.1.0"), "0.1.0-ou1")])
    assert desktop_sync.sync(env.rt, cat("0.1.0-ou1"))["status"] == "extracted"
    before = os.path.realpath(env.target)
    data = body("0.3.0")
    bad = evil_deb(tmp_path / "ou-desktop-windows_0.3.0-ou1_all.deb",
                   [("./" + W, None, "d"), ("./" + W + "manifest.json", manifest_for(data, sha256="0" * 64), "f"), ("./" + W + EXE, data, "f")])
    env.repo.publish([(bad, "0.3.0-ou1")])
    r = desktop_sync.sync(env.rt, cat("0.3.0-ou1"))
    assert r["status"] == "refused" and "sha256 differs" in r["reason"]
    assert os.path.realpath(env.target) == before
    got = env.c.get("/api/v1/downloads/desktop/windows")
    assert got.status_code == 200 and got.content == body("0.1.0")
    extra = evil_deb(tmp_path / "x.deb", [("./" + W + "manifest.json", manifest_for(data), "f"), ("./" + W + EXE, data, "f"),
                                          ("./" + W + "other.exe", b"MZ", "f")])
    shutil.copy(extra, bad)
    env.repo.publish([(bad, "0.3.0-ou1")])
    r = desktop_sync.sync(env.rt, cat("0.3.0-ou1"))
    assert r["status"] == "refused" and "exactly the manifest" in r["reason"] and os.path.realpath(env.target) == before


def test_pinned_version_missing_from_the_index_keeps_the_old_copy(env):
    env.repo.publish([(env.repo.build("0.1.0"), "0.1.0-ou1")])
    desktop_sync.sync(env.rt, cat("0.1.0-ou1"))
    r = desktop_sync.sync(env.rt, cat("0.9.0-ou1"))
    assert r["status"] == "refused" and "is not in the signed dev index" in r["reason"]
    assert env.c.get("/api/v1/downloads/desktop").json()["windows"]["version"] == "0.1.0"


def test_no_pin_is_a_no_op_and_the_console_says_not_available(env):
    env.repo.publish([(env.repo.build("0.1.0"), "0.1.0-ou1")])
    assert desktop_sync.sync(env.rt, cat(None)) == {"status": "no_pin"}
    assert not env.target.exists() and not events(env.rt, "desktop.installer.extracted") and not events(env.rt, "desktop.installer.refused")
    assert env.c.get("/api/v1/downloads/desktop").json() == {"windows": None}
    assert env.c.get("/api/v1/downloads/desktop/windows").status_code == 404
    r = desktop_sync.sync(env.rt, cat("0.1.0-ou1", repo="ubuntu-noble"))       # never from a distribution archive
    assert r["status"] == "refused"


def test_the_real_catalog_has_no_pin_yet_so_production_is_a_no_op():
    assert desktop_sync.catalog_pin() is None


def test_a_hand_placed_copy_is_kept_as_the_previous_release(env):
    env.target.mkdir()
    (env.target / "manifest.json").write_text("{}")
    env.repo.publish([(env.repo.build("0.1.0"), "0.1.0-ou1")])
    r = desktop_sync.sync(env.rt, cat("0.1.0-ou1"))
    assert r["status"] == "extracted" and r["previous"].startswith("manual-") and env.target.is_symlink()
    assert (env.target.parent / "releases" / r["previous"] / "manifest.json").exists()


def test_tick_runs_at_start_then_waits(env, monkeypatch):
    calls = []
    monkeypatch.setattr(env.rt, "settings", dataclasses.replace(env.rt.settings, desktop_sync_enabled=True))
    monkeypatch.setattr(desktop_sync, "sync", lambda rt, **k: calls.append(1) or {"status": "no_pin"})
    assert desktop_sync.tick(env.rt) == {"status": "no_pin"}
    assert desktop_sync.tick(env.rt) is None and len(calls) == 1
    monkeypatch.setattr(env.rt, "settings", dataclasses.replace(env.rt.settings, desktop_sync_enabled=False))
    desktop_sync._state["next"] = 0.0
    assert desktop_sync.tick(env.rt) is None and len(calls) == 1


def test_worker_starts_the_desktop_thread_only_when_enabled(rt):
    from ics import worker
    assert rt.settings.desktop_sync_enabled is False             # the suite's workers never touch this host's tree
    src = Path(worker.__file__).read_text()
    assert 'self.threads["desktop"]' in src and "desktop_sync.tick(self.rt)" in src


def test_the_service_may_write_only_the_desktop_directory():
    u = (ROOT / "ics/deploy/ics.service").read_text()
    assert "ReadWritePaths=-/var/lib/office-unbound/desktop\n" in u and "ProtectSystem=strict" in u
    assert "d /var/lib/office-unbound/desktop 0755 ics ics -" in (ROOT / "blueprints/build/ics/debian/ou-ics.tmpfiles").read_text()
    assert "install -d -o ics -g ics -m 0755 /var/lib/office-unbound/desktop" in (ROOT / "ics/deploy/install.sh").read_text()
