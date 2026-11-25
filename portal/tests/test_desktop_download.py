"""Office Unbound Desktop for Windows served by the portal itself (/download/windows) and its card on /devices. Dummy installer bytes."""
import dataclasses
import hashlib
import json
import os
import sys
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from app import desktop_download  # noqa: E402
from app.main import create_app  # noqa: E402
from test_portal import BASE, CFG, Mock, finish, login  # noqa: E402

BODY = b"MZ dummy Office Unbound Desktop installer\x00" * 4000
NAME = "OfficeUnbound-Desktop-0.1.0-x64-setup.exe"


def stage(d: Path, body: bytes = BODY, **over) -> dict:
    m = {"schema": 1, "product": "Office Unbound Desktop", "platform": "windows-x64", "version": "0.1.0", "file": NAME,
         "sha256": hashlib.sha256(body).hexdigest(), "size": len(body), "unsigned": True, "stage": "alpha", **over}
    (d / NAME).write_bytes(body)
    (d / "manifest.json").write_text(json.dumps(m))
    return m


@pytest.fixture()
def dl(tmp_path):
    m = Mock()
    app = create_app(dataclasses.replace(CFG, desktop_dir=str(tmp_path)), transport=httpx.MockTransport(m.handler))
    with TestClient(app, base_url=BASE) as c:
        c.follow_redirects = False
        yield c, m, tmp_path


def signed_in(c, m):
    _, q = login(c, m)
    assert finish(c, q).status_code == 303


def test_served_with_headers_and_exact_bytes(dl):
    c, m, d = dl
    man = stage(d)
    signed_in(c, m)
    r = c.get("/download/windows")
    assert r.status_code == 200
    assert hashlib.sha256(r.content).hexdigest() == man["sha256"] and r.content == BODY
    h = r.headers
    assert h["content-disposition"] == f'attachment; filename="{NAME}"'
    assert h["content-type"] == "application/vnd.microsoft.portable-executable"
    assert h["x-content-type-options"] == "nosniff"
    assert h["cache-control"] == "private, no-cache" and h["etag"] == f'"{man["sha256"]}"'
    assert h["content-length"] == str(len(BODY))


def test_hash_mismatch_refused_without_bytes(dl):
    c, m, d = dl
    stage(d, sha256="0" * 64)
    signed_in(c, m)
    r = c.get("/download/windows")
    assert r.status_code == 500 and BODY[:20] not in r.content
    assert "integrity check" in r.text and "attachment" not in r.headers.get("content-disposition", "")


def test_changed_file_after_verified_download_is_refused(dl):
    c, m, d = dl
    stage(d)
    signed_in(c, m)
    assert c.get("/download/windows").status_code == 200        # verified once, cached for this file identity
    tampered = BODY[:-1] + b"X"                                  # same size, new bytes and mtime: hashed again
    (d / NAME).write_bytes(tampered)
    st = os.stat(d / NAME)
    os.utime(d / NAME, ns=(st.st_atime_ns, st.st_mtime_ns + 10 ** 9))
    r = c.get("/download/windows")
    assert r.status_code == 500 and tampered[:20] not in r.content


def test_size_mismatch_refused(dl):
    c, m, d = dl
    stage(d, size=len(BODY) + 1)
    signed_in(c, m)
    assert c.get("/download/windows").status_code == 500


def test_not_configured(dl):
    c, m, d = dl
    signed_in(c, m)
    r = c.get("/download/windows")
    assert r.status_code == 404 and "not available" in r.text.lower()
    page = c.get("/devices").text
    assert "Office Unbound Desktop for Windows" in page and "Not available yet" in page and 'href="/download/windows"' not in page


@pytest.mark.parametrize("over", [{"file": "../etc/passwd"}, {"file": "setup.bat"}, {"sha256": "XYZ"}, {"schema": 2}, {"size": True},
                                  {"platform": "linux"}])
def test_malformed_manifest_offers_nothing(dl, over):
    c, m, d = dl
    stage(d, **over)
    signed_in(c, m)
    assert c.get("/download/windows").status_code == 404
    assert 'href="/download/windows"' not in c.get("/devices").text


def test_symlinked_installer_not_served(dl, tmp_path_factory):
    c, m, d = dl
    stage(d)
    other = tmp_path_factory.mktemp("o") / "x.exe"
    other.write_bytes(BODY)
    (d / NAME).unlink()
    (d / NAME).symlink_to(other)
    signed_in(c, m)
    assert c.get("/download/windows").status_code == 404


def test_unauthenticated_redirects_to_sign_in(dl):
    c, _, d = dl
    stage(d)
    r = c.get("/download/windows")
    assert r.status_code == 303 and r.headers["location"] == "/login?next=%2Fdownload%2Fwindows"
    assert BODY[:20] not in r.content


def test_devices_card_shows_version_size_hash_and_warning(dl):
    c, m, d = dl
    man = stage(d)
    signed_in(c, m)
    t = c.get("/devices").text
    assert "Download Office Unbound Desktop for Windows" in t and 'href="/download/windows"' in t
    assert "0.1.0" in t and man["sha256"] in t and desktop_download.human_size(len(BODY)) in t
    assert "Alpha, not code-signed:" in t and "SmartScreen will warn" in t
    assert 'href="#desktop-windows"' in t                         # the Windows section points to it
    assert "github.com/agit8or1" not in t                          # from this server, never from GitHub


def test_manifest_size_limit(tmp_path):
    (tmp_path / "manifest.json").write_text(" " * 5000)
    assert desktop_download.manifest(tmp_path) is None
    assert desktop_download.human_size(3 * 1024 ** 2) == "3.0 MB"
