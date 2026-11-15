"""Versioning (ADR-0011): VERSION is the single source; BUILD_INFO.json overrides it at install time; no git/network at runtime."""
import json
import re
import subprocess
import sys
from pathlib import Path

from ics import version as ver

ROOT = Path(__file__).resolve().parents[2]


def test_version_matches_root_file_and_semver():
    v = (ROOT / "VERSION").read_text().strip()
    assert re.fullmatch(r"\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?", v)
    import ics
    assert ics.__version__ == v == ver.read_version()


def test_component_versions_aligned():
    vs = json.loads((ROOT / "VERSIONS.json").read_text())
    from ou_agent import __version__ as agent_v
    assert agent_v == vs["components"]["node_agent"]
    src = (ROOT / "portal" / "app" / "version.py").read_text()
    assert f'PORTAL_VERSION = "{vs["components"]["portal"]}"' in src


def test_build_info_overrides_and_falls_back(tmp_path):
    (tmp_path / "BUILD_INFO.json").write_text(json.dumps({"version": "9.9.9", "commit": "abcdef1234567890", "built_at": "2026-01-01T00:00:00Z",
                                                          "dirty": False, "schema_head": "0007", "releases": [{"version": "9.9.10", "date": "2026-02-01"}]}))
    i = ver._compute(tmp_path, ROOT)
    assert i["version"] == "9.9.9" and i["source"] == "build-info" and ver.short_commit(i) == "abcdef1"
    u = ver.update_status(i)
    assert u["update_available"] and u["latest_known"] == "9.9.10"
    # corrupt file -> source tree fallback, no exception
    (tmp_path / "BUILD_INFO.json").write_text("{not json")
    assert ver._compute(tmp_path, ROOT)["source"] == "source-tree"
    # nothing at all -> explicit unknown marker
    assert ver._compute(tmp_path / "x", tmp_path / "y")["version"] == ver.UNKNOWN


def test_update_status_semver_ordering():
    i = {"version": "0.1.0", "releases": [{"version": "0.1.0"}, {"version": "0.10.0"}, {"version": "0.2.0"}]}
    assert ver.update_status(i)["latest_known"] == "0.10.0" and ver.update_status(i)["update_available"]
    assert not ver.update_status({"version": "0.1.0", "releases": [{"version": "0.1.0"}]})["update_available"]
    assert not ver.update_status({"version": "0.1.0", "releases": [{"version": "0.1.0-rc.1"}]})["update_available"]
    assert not ver.update_status({"version": "0.1.0", "releases": []})["update_available"]


def test_write_build_info_script(tmp_path):
    out = tmp_path / "BUILD_INFO.json"
    subprocess.run([sys.executable, str(ROOT / "ics" / "deploy" / "write_build_info.py"), str(ROOT), str(out)], check=True,
                   env={"SOURCE_DATE_EPOCH": "1700000000", "PATH": "/usr/bin:/bin"})
    d = json.loads(out.read_text())
    assert d["version"] == (ROOT / "VERSION").read_text().strip() and d["built_at"] == "2023-11-14T22:13:20Z"
    assert d["schema_head"] and d["components"]["node_agent"]


def test_public_version_is_minimal_and_authed_is_full(client, mk_user, login):
    r = client.get("/api/v1/version")
    assert r.status_code == 200 and r.json() == {"product": "Office Unbound", "version": ver.__version__.split(".")[0]}   # review 5 L5
    v, _ = login(mk_user("vera", "viewer"))
    assert v.get("/api/v1/version").json() == {"product": "Office Unbound", "version": ver.__version__.split(".")[0]}   # not an admin: minimal too
    c, _ = login(mk_user("vera-admin", "admin"))
    d = c.get("/api/v1/version").json()
    assert d["version"] == ver.__version__ and d["api"] == "v1" and "components" in d and "database" in d["schema"]
    assert d["components"]["ics"] == ver.__version__


def test_system_requires_auth_and_reports_updates(client, mk_user, login):
    assert client.get("/api/v1/system").status_code == 401
    c, _ = login(mk_user("vera2", "admin"))   # /system is admin-only (agent Y)
    d = c.get("/api/v1/system").json()
    assert d["updates"]["current"] == ver.__version__ and "no network" in d["updates"]["checked"]
    assert d["components"]["node_agent"]


def test_readyz_includes_version(client):
    assert client.get("/readyz").json()["version"] == ver.__version__.split(".")[0]
