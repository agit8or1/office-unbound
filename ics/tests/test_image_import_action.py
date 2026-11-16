"""image.import as an approved typed action (Stage 2): release chosen by name under the configured root, Settings trust, DB floor, the previewed sha256
bound into the plan, re-verification at execution, catalog risk and role."""
import dataclasses
import hashlib
import os
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import text

from ics import actions, imageimport
from ics.actions import ActionType, PlanError
from ics.guest import golden
from .infra_fixtures import job, mutations, sim  # noqa: F401
from .test_golden_image import ATTESTOR_PUB_B64, make_release
from .test_image_import import BLOB, SCOPE, enable_import

NAME = "ou-golden-debian-12-20261115.qcow2"


def configure(rt, tmp_path, version=1, sub="r1"):
    root = tmp_path / "releases"
    root.mkdir(exist_ok=True)
    (root / sub).mkdir()
    d, pem, pin, _ = make_release(root / sub, name=NAME, image=BLOB, version=version)
    os.rename(d, root / sub / "x")                       # make_release writes <dir>/rel; flatten it into the release directory itself
    for f in os.listdir(root / sub / "x"):
        os.rename(root / sub / "x" / f, root / sub / f)
    os.rmdir(root / sub / "x")
    keyf = tmp_path / f"{sub}.pub"
    keyf.write_text(pem)
    rt.settings = dataclasses.replace(rt.settings, guest_golden_releases_dir=str(root), guest_golden_release_pubkey_file=str(keyf),
                                      guest_golden_release_pin_sha256=pin, guest_golden_attestor_pubkey=ATTESTOR_PUB_B64)
    return root


@pytest.fixture()
def floor(owner_engine):
    with owner_engine.begin() as c:
        c.execute(text("TRUNCATE image_floor"))
    yield


def model(**kw):
    d = dict(endpoint_id=str(uuid4()), pve_node="pve1", release="r1", expected_sha256=hashlib.sha256(BLOB).hexdigest(), import_storage="local",
             target_storage="local-lvm", pool="ou-lab")
    d.update(kw)
    return imageimport.ImageImport.model_validate(d)


class _DB:
    """precheck reads only the endpoint row"""
    def __init__(self, ep):
        self.ep = ep

    def execute(self, *a, **k):
        return SimpleNamespace(first=lambda: self.ep)


def ep_row(**kw):
    d = dict(id=uuid4(), name="pve06", detached_at=None, enabled=True, provision_token_id="officeunbound@pve!prov", allowed_nodes=["pve1"],
             allowed_pools=["ou-lab"], allowed_storage=["local", "local-lvm"], allowed_networks=["vmbr1"], allowed_templates=[])
    d.update(kw)
    return SimpleNamespace(**d)


def test_catalog_entry_is_high_risk_admin_only_and_has_no_secrets():
    spec = actions.CATALOG[ActionType.image_import]
    assert spec["risk"] == "high" and spec["admin_only"] is True and spec["secrets"] == ()
    assert ActionType.image_import in actions._EXEC and ActionType.image_import in actions._PRECHECK


@pytest.mark.parametrize("bad", ["../r1", "r1/..", "..", ".", "/etc", "r1/x", "R1", "a..b/c", ""])
def test_release_names_cannot_leave_the_root(rt, tmp_path, bad):
    configure(rt, tmp_path)
    with pytest.raises((ValueError, KeyError)):
        imageimport.release_dir(rt, bad)
    with pytest.raises(Exception):
        model(release=bad)                                # refused already by the plan model


def test_a_symlink_out_of_the_root_is_not_a_release(rt, tmp_path):
    root = configure(rt, tmp_path)
    (tmp_path / "elsewhere").mkdir()
    os.symlink(tmp_path / "elsewhere", root / "evil")
    with pytest.raises(KeyError):
        imageimport.release_dir(rt, "evil")
    assert imageimport.release_dir(rt, "r1") == os.path.realpath(root / "r1")


def test_unconfigured_root_is_refused(rt):
    rt.settings = dataclasses.replace(rt.settings, guest_golden_releases_dir=None)
    with pytest.raises(ValueError, match="not configured"):
        imageimport.release_dir(rt, "r1")


def test_list_releases_verifies_each_and_reports_unverifiable_ones(rt, tmp_path, floor):
    root = configure(rt, tmp_path)
    (root / "broken").mkdir()
    (root / "broken" / "junk").write_text("x")
    rels = {r["release"]: r for r in imageimport.list_releases(rt)}
    assert rels["r1"]["verified"] and rels["r1"]["sha256"] == hashlib.sha256(BLOB).hexdigest() and rels["r1"]["os"] == "debian-12"
    assert rels["r1"]["default_template"] == "ou-tpl-debian-12" and rels["r1"]["floor_version"] is None
    assert rels["broken"]["verified"] is False and rels["broken"]["reason"]


def test_precheck_shows_the_verified_image_and_binds_scope(rt, tmp_path, floor):
    configure(rt, tmp_path)
    x = imageimport.precheck(_DB(ep_row()), rt, model())
    assert x["image"]["sha256"] == hashlib.sha256(BLOB).hexdigest() and x["template_name"] == "ou-tpl-debian-12" and x["downgrade"] is False
    for kw, code in [(dict(pve_node="pve9"), 422), (dict(pool="other"), 422), (dict(import_storage="nfs"), 422), (dict(bridge="vmbr9"), 422),
                     (dict(release="nope"), 404), (dict(expected_sha256="0" * 64), 409)]:
        with pytest.raises(PlanError) as e:
            imageimport.precheck(_DB(ep_row()), rt, model(**kw))
        assert e.value.status == code, kw
    for ep, code in [(None, 404), (ep_row(enabled=False), 409), (ep_row(provision_token_id=None), 409)]:
        with pytest.raises(PlanError) as e:
            imageimport.precheck(_DB(ep), rt, model())
        assert e.value.status == code
    x = imageimport.precheck(_DB(ep_row(allowed_templates=["ou-debian12-template"])), rt, model())
    assert "not in the endpoint's allowed templates" in x["warning"]


def test_precheck_refuses_a_downgrade_unless_explicit(rt, tmp_path, floor):
    configure(rt, tmp_path, version=1)
    with rt.session() as db:
        db.execute(text("INSERT INTO image_floor (os, release_date, version, image_sha256, image_name) VALUES ('debian-12', '20261201', 5, :s, 'x')"),
                   {"s": "ab" * 32})
        db.commit()
    with pytest.raises(PlanError) as e:
        imageimport.precheck(_DB(ep_row()), rt, model())
    assert e.value.status == 422 and "rollback floor 5" in str(e.value)
    x = imageimport.precheck(_DB(ep_row()), rt, model(allow_downgrade=True))
    assert x["downgrade"] is True and x["floor_version"] == 5


def test_execution_imports_the_template_and_raises_the_db_floor(rt, tmp_path, floor, sim, job, monkeypatch):
    configure(rt, tmp_path, version=2)
    enable_import(sim)
    import ics.providers.proxmox as pmx
    monkeypatch.setattr(pmx, "open_mutations", lambda rt_, ep, known: mutations(sim, scope=SCOPE))
    r = imageimport.exec_import(rt, _DB(ep_row()), model(), None, [])
    vm = sim.sim.vms[r["vmid"]]
    assert vm["cfg"]["template"] == 1 and r["template"] == "ou-tpl-debian-12" and r["version"] == 2
    assert golden.get_floor(rt, "debian-12") == golden.Floor(2, hashlib.sha256(BLOB).hexdigest())


def test_a_release_swapped_after_approval_is_refused_before_upload(rt, tmp_path, floor, sim, job, monkeypatch):
    root = configure(rt, tmp_path)
    enable_import(sim)
    import ics.providers.proxmox as pmx
    monkeypatch.setattr(pmx, "open_mutations", lambda rt_, ep, known: mutations(sim, scope=SCOPE))
    with open(root / "r1" / NAME, "ab") as f:                # tampered on disk after the plan was approved
        f.write(b"x")
    with pytest.raises(golden.ReleaseError):
        imageimport.exec_import(rt, _DB(ep_row()), model(), None, [])
    assert getattr(sim.sim, "uploaded_bytes", 0) == 0 and not any(k.startswith("import/") for k in sim.sim.storages["local"].get("files", {}))
