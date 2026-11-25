"""Office Unbound Desktop for Windows from the ICS itself (/api/v1/downloads/desktop[/windows]), the deb that carries it
(blueprints/build/desktop-windows-deb/build-deb.sh) and the catalog pin that puts it on the portal's VM. Dummy installer bytes."""
import dataclasses
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from ics import desktop_download

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "blueprints/build/desktop-windows-deb/build-deb.sh"
BODY = b"MZ dummy Office Unbound Desktop installer\x00" * 4000
NAME = "OfficeUnbound-Desktop-0.1.0-x64-setup.exe"


def stage(d: Path, body: bytes = BODY, **over) -> dict:
    m = {"schema": 1, "product": "Office Unbound Desktop", "platform": "windows-x64", "version": "0.1.0", "file": NAME,
         "sha256": hashlib.sha256(body).hexdigest(), "size": len(body), "unsigned": True, "stage": "alpha", **over}
    (d / NAME).write_bytes(body)
    (d / "manifest.json").write_text(json.dumps(m))
    return m


@pytest.fixture()
def dl(rt, mk_user, login, tmp_path, monkeypatch):
    monkeypatch.setattr(rt, "settings", dataclasses.replace(rt.settings, desktop_windows_dir=str(tmp_path)))
    c, _ = login(mk_user("dl-viewer", "viewer"))
    return c, tmp_path


def test_served_to_a_viewer_with_headers_and_exact_bytes(dl):
    c, d = dl
    man = stage(d)
    info = c.get("/api/v1/downloads/desktop").json()["windows"]
    assert info["version"] == "0.1.0" and info["sha256"] == man["sha256"] and info["size"] == len(BODY) and info["unsigned"] is True
    assert info["url"] == "/api/v1/downloads/desktop/windows"
    r = c.get(info["url"])
    assert r.status_code == 200 and r.content == BODY and hashlib.sha256(r.content).hexdigest() == man["sha256"]
    h = r.headers
    assert h["content-disposition"] == f'attachment; filename="{NAME}"'
    assert h["content-type"] == "application/vnd.microsoft.portable-executable"
    assert h["x-content-type-options"] == "nosniff" and h["cache-control"] == "private, no-cache"
    assert h["content-length"] == str(len(BODY)) and h["etag"] == f'"{man["sha256"]}"'


def test_hash_mismatch_refused_without_bytes(dl):
    c, d = dl
    stage(d, sha256="1" * 64)
    r = c.get("/api/v1/downloads/desktop/windows")
    assert r.status_code == 500 and BODY[:20] not in r.content and "integrity" in r.json()["detail"]


def test_size_mismatch_and_tampering_after_a_good_download_refused(dl):
    c, d = dl
    stage(d)
    assert c.get("/api/v1/downloads/desktop/windows").status_code == 200
    (d / NAME).write_bytes(BODY[:-1] + b"X")
    st = os.stat(d / NAME)
    os.utime(d / NAME, ns=(st.st_atime_ns, st.st_mtime_ns + 10 ** 9))
    assert c.get("/api/v1/downloads/desktop/windows").status_code == 500
    stage(d, size=len(BODY) - 1)
    assert c.get("/api/v1/downloads/desktop/windows").status_code == 500


def test_not_configured(dl):
    c, d = dl
    assert c.get("/api/v1/downloads/desktop").json() == {"windows": None}
    assert c.get("/api/v1/downloads/desktop/windows").status_code == 404
    stage(d, file="../../etc/passwd")
    assert c.get("/api/v1/downloads/desktop").json() == {"windows": None}
    assert c.get("/api/v1/downloads/desktop/windows").status_code == 404


def test_unauthenticated_is_401(client, rt, tmp_path, monkeypatch):
    monkeypatch.setattr(rt, "settings", dataclasses.replace(rt.settings, desktop_windows_dir=str(tmp_path)))
    stage(tmp_path)
    for p in ("/api/v1/downloads/desktop", "/api/v1/downloads/desktop/windows"):
        r = client.get(p)
        assert r.status_code == 401 and BODY[:20] not in r.content


def test_the_ics_copy_matches_the_portal_module():
    """One verifier, shipped twice (portal VM, ICS): only the docstring and the default directory differ."""
    def body(p):
        s = p.read_text()
        return s.split('"""', 2)[2].replace('DEFAULT_DIR = "/var/lib/office-unbound/desktop/windows"', 'DEFAULT_DIR = "/usr/share/ou-desktop/windows"')
    assert body(ROOT / "ics/ics/desktop_download.py") == body(ROOT / "portal/app/desktop_download.py")


def test_default_dir_setting():
    from ics.config import Settings
    assert Settings.desktop_windows_dir == desktop_download.DEFAULT_DIR


def test_catalog_pin_when_present_is_on_the_portal_from_our_dev_channel():
    """The pin is added when the first real installer is published (docs/desktop/download.md step 4): an unpublished pin would make
    pkg.install_pinned fail on every portal VM. Until then the catalog must not carry it anywhere else either."""
    from ics.deploy.catalog import load_catalog
    cat = load_catalog()
    where = [(c.name, a) for c in cat.components.values() for a in c.artifacts if a.kind == "package" and a.package == "ou-desktop-windows"]
    assert all(n == "portal" and a.repo == "ob-apt-dev" and a.version.split("-")[-1].startswith("ou") for n, a in where)
    assert len(where) <= 1


needs_dpkg = pytest.mark.skipif(not shutil.which("dpkg-deb"), reason="dpkg-deb not installed")


@needs_dpkg
def test_build_deb_with_a_dummy_installer_serves_from_its_contents(tmp_path):
    exe = tmp_path / "in" / "setup.exe"
    exe.parent.mkdir()
    exe.write_bytes(BODY)
    sha = hashlib.sha256(BODY).hexdigest()
    out = tmp_path / "out"
    r = subprocess.run(["bash", str(BUILD), str(exe), sha, "0.1.0-alpha.1", str(out)], capture_output=True, text=True,
                       env={**os.environ, "OU_REVISION": "ou1"})
    assert r.returncode == 0, r.stderr
    deb = out / "ou-desktop-windows_0.1.0~alpha.1-ou1_all.deb"
    assert deb.is_file()
    f = subprocess.run(["dpkg-deb", "-f", str(deb), "Package", "Version", "Architecture"], capture_output=True, text=True, check=True).stdout
    assert "Package: ou-desktop-windows" in f and "Version: 0.1.0~alpha.1-ou1" in f and "Architecture: all" in f
    x = tmp_path / "x"
    subprocess.run(["dpkg-deb", "-x", str(deb), str(x)], check=True)
    d = x / "usr/share/ou-desktop/windows"
    m = desktop_download.manifest(d)
    assert m is not None and m["version"] == "0.1.0-alpha.1" and m["sha256"] == sha and m["size"] == len(BODY) and m["unsigned"] is True
    assert m["file"] == "OfficeUnbound-Desktop-0.1.0-alpha.1-x64-setup.exe"
    got, fd = desktop_download.open_verified(d)
    assert b"".join(desktop_download.chunks(fd, got["size"])) == BODY
    listing = subprocess.run(["dpkg-deb", "-c", str(deb)], capture_output=True, text=True, check=True).stdout
    assert "root/root" in listing and "-rw-r--r--" in listing
    again = tmp_path / "again"   # reproducible: same input, same bytes
    subprocess.run(["bash", str(BUILD), str(exe), sha, "0.1.0-alpha.1", str(again)], check=True, capture_output=True)
    assert (again / deb.name).read_bytes() == deb.read_bytes()


@needs_dpkg
@pytest.mark.parametrize("args,code", [(["WRONG"], 4), (["0" * 63], 3), (["SHA", "1.0"], 3)])
def test_build_deb_refuses_a_wrong_hash_or_version(tmp_path, args, code):
    exe = tmp_path / "setup.exe"
    exe.write_bytes(BODY)
    sha = hashlib.sha256(BODY).hexdigest()
    a = {"WRONG": "f" * 64, "SHA": sha}
    argv = [a.get(args[0], args[0]), args[1] if len(args) > 1 else "0.1.0"]
    r = subprocess.run(["bash", str(BUILD), str(exe), *argv, str(tmp_path / "o")], capture_output=True, text=True)
    assert r.returncode == code and "REFUSED" in r.stderr and not (tmp_path / "o").exists()
