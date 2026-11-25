"""0.13.7: services that read their configuration at start get it. cfg.volume_files restarts nothing, so a unit mounting a configured volume
carries a digest of those files (configure._with_config_digest); a changed digest changes the unit file and podman.deploy_unit restarts it.
And new documents in Files are Microsoft Office formats (owner 2026-11-25)."""
import sys
from pathlib import Path

import yaml

from ics.deploy import configure
from ics.deploy.catalog import load_catalog
from ics.deploy.plan import _install_params

ROOT = Path(__file__).resolve().parents[2]


def _files_install(content: str):
    c = load_catalog().components["files"]
    rbs = _install_params(c, "e.example")
    img = next(r["params"]["image"] for r in rbs if r["runbook"] == "podman.pull_verified")
    cfg = [{"runbook": "cfg.volume_files", "params": {"component": "files", "volume": "config", "image": img, "owner": "1000:1000",
                                                     "files": [{"path": "app-registry.yaml", "mode": 0o644, "content": content}]}}]
    return rbs, cfg


def _units(out):
    return [r for r in out if r["runbook"] == "podman.deploy_unit"]


def test_a_unit_mounting_configured_files_carries_their_digest_and_only_that(monkeypatch):
    rbs, cfg = _files_install("a: 1\n")
    monkeypatch.setitem(configure.BUILDERS, "files", lambda ctx, vm: cfg)
    u1 = _units(configure.expand(None, "vm", "files", rbs))
    assert u1 and all(configure.CONFIG_DIGEST_ENV in u["params"]["env"] for u in u1)   # opencloud and collaboration both mount config
    again = _units(configure.expand(None, "vm", "files", rbs))
    assert again == u1                                                                # same content: same unit, nothing restarts
    rbs2, cfg2 = _files_install("a: 2\n")
    monkeypatch.setitem(configure.BUILDERS, "files", lambda ctx, vm: cfg2)
    u2 = _units(configure.expand(None, "vm", "files", rbs2))
    assert [u["params"]["env"][configure.CONFIG_DIGEST_ENV] for u in u2] != [u["params"]["env"][configure.CONFIG_DIGEST_ENV] for u in u1]
    assert all("a: 2" not in str(u) for u in u2)                                      # a hash, never file content
    # the plan's own runbooks are not modified in place
    assert all(configure.CONFIG_DIGEST_ENV not in r["params"].get("env", {}) for r in rbs2 if r["runbook"] == "podman.deploy_unit")


def test_a_unit_that_mounts_no_configured_volume_is_unchanged(monkeypatch):
    rbs, cfg = _files_install("x\n")
    cfg[0]["params"]["volume"] = "not-mounted"
    monkeypatch.setitem(configure.BUILDERS, "files", lambda ctx, vm: cfg)
    assert _units(configure.expand(None, "vm", "files", rbs)) == _units(rbs)


def test_the_digest_passes_the_node_agents_own_unit_checks(monkeypatch):
    sys.path.insert(0, str(ROOT / "ics" / "agent"))
    from ou_agent import guestspec
    rbs, cfg = _files_install("a: 1\n")
    monkeypatch.setitem(configure.BUILDERS, "files", lambda ctx, vm: cfg)
    units = _units(configure.expand(None, "vm", "files", rbs))
    for u in units:
        p = u["params"]
        out = guestspec.check_deploy(p, {"registries": [p["image"].split("/", 1)[0]], "packages": []})   # raises Reject if refused
        assert out["env"][configure.CONFIG_DIGEST_ENV] == p["env"][configure.CONFIG_DIGEST_ENV]
    assert units


def test_new_documents_in_files_are_office_formats_and_every_upstream_type_is_kept():
    reg = yaml.safe_load((ROOT / "blueprints/catalog/templates/files/app-registry.yaml").read_text())["app_registry"]["mimetypes"]
    by = {m["extension"]: m for m in reg}
    # OpenCloud 9.1.0 services/app-registry/pkg/config/defaults: the configured list replaces this one entirely
    assert set(by) == {"pdf", "odt", "ods", "odp", "docx", "docxf", "xlsx", "pptx", "ipynb", "md", "zmd", "ggs"}
    assert {e for e, m in by.items() if m.get("allow_creation")} == {"docx", "xlsx", "pptx", "md"}
    assert [m["extension"] for m in reg[:3]] == ["docx", "xlsx", "pptx"]
    src = (ROOT / "ics/ics/deploy/configure.py").read_text()
    assert '"app-registry.yaml"' in src and '_template("files/app-registry.yaml")' in src
    assert load_catalog().components["files"].config_revision >= 2   # running deployments get it with their next change
