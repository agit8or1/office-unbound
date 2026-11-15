"""`image.import` provider verb (bootstrap v2): upload a signed golden image to an `import` directory storage and turn it into a template. Against the
simulator, which models PVE 9's upload API (multipart, content=import, checksum, Datastore.AllocateTemplate) and `import-from` disk creation."""
import hashlib

import pytest

from ics.providers.base import ImageImportSpec, ProviderError, ScopeViolation
from ics.providers.proxmox import privileges as priv
from ics.providers.proxmox.provider import EndpointScope
from .infra_fixtures import LAB, job, mutations, sim  # noqa: F401

SCOPE = EndpointScope(pools=("ou-lab",), storage=("local-lvm", "local"), networks=("vmbr1",), nodes=("pve1", "pve2"))
BLOB = b"QFI\xfb" + b"\x00" * 4096 + b"golden"


@pytest.fixture()
def image(tmp_path):
    p = tmp_path / "ou-golden-debian12-20261115.qcow2"
    p.write_bytes(BLOB)
    return str(p), hashlib.sha256(BLOB).hexdigest()


def enable_import(sim, with_priv=True):
    sim.sim.storages["local"]["content"] += ",import"
    if with_priv:
        sim.sim.add_role("OUImport", {"Datastore.AllocateTemplate", "Datastore.AllocateSpace", "Datastore.Audit"})
        sim.sim.tokens[LAB[0]]["acl"].append(("/storage/local", "OUImport"))


def spec(image, **kw):
    path, sha = image
    d = dict(node="pve1", import_storage="local", target_storage="local-lvm", file_path=path, sha256=sha, name="ou-tpl-debian12-agent", pool="ou-lab")
    d.update(kw)
    return ImageImportSpec(**d)


def test_import_uploads_verifies_creates_and_templates(sim, job, image):
    enable_import(sim)
    m = mutations(sim, scope=SCOPE)
    r = m.import_image(spec(image))
    vm = sim.sim.vms[r.vmid]
    assert r.name == "ou-tpl-debian12-agent" and r.volid == "local:import/ou-golden-debian12-20261115.qcow2"
    assert vm["cfg"]["template"] == 1 and vm["pool"] == "ou-lab" and "ou-managed" in vm["cfg"]["tags"] and "ou-image" in vm["cfg"]["tags"]
    assert vm["cfg"]["scsi0"].startswith("local-lvm:vm-") and sim.sim.uploaded_bytes == len(BLOB)
    assert sim.sim.storages["local"]["files"]["import/ou-golden-debian12-20261115.qcow2"] == len(BLOB)
    assert not any("/upload" in p and m_ == "GET" for m_, p in sim.sim.seen)


def test_import_needs_datastore_allocate_template_on_the_import_storage(sim, job, image):
    enable_import(sim, with_priv=False)
    sim.sim.add_role("OUNoTpl", {"Datastore.AllocateSpace", "Datastore.Audit"})        # everything but AllocateTemplate
    sim.sim.tokens[LAB[0]]["acl"].append(("/storage/local", "OUNoTpl"))
    with pytest.raises(ProviderError) as e:
        mutations(sim, scope=SCOPE).import_image(spec(image))
    assert e.value.code == "permission" and "AllocateTemplate" in e.value.message
    assert not hasattr(sim.sim, "uploaded_bytes") and not any(v["cfg"].get("template") == 1 and v["vmid"] > 9100 for v in sim.sim.vms.values())


def test_import_refuses_a_storage_without_import_content_and_names_the_owner_command(sim, job, image):
    sim.sim.add_role("OUImport", {"Datastore.AllocateTemplate", "Datastore.AllocateSpace", "Datastore.Audit"})
    sim.sim.tokens[LAB[0]]["acl"].append(("/storage/local", "OUImport"))               # privileges but the storage has no `import` content (pve06's situation)
    with pytest.raises(ProviderError) as e:
        mutations(sim, scope=SCOPE).import_image(spec(image))
    assert e.value.code == "capability" and "pvesm set local --content" in e.value.message and "import" in e.value.message
    with pytest.raises(ProviderError, match="does not hold `images`"):
        enable_import(sim)
        mutations(sim, scope=SCOPE).import_image(spec(image, target_storage="local"))


def test_a_file_that_does_not_match_the_verified_checksum_is_never_uploaded(sim, job, image, tmp_path):
    enable_import(sim)
    path, sha = image
    with open(path, "ab") as f:
        f.write(b"tampered after signature verification")
    with pytest.raises(ProviderError) as e:
        mutations(sim, scope=SCOPE).import_image(spec(image))
    assert e.value.code == "integrity" and not hasattr(sim.sim, "uploaded_bytes")
    empty = tmp_path / "ou-golden-empty.qcow2"
    empty.write_bytes(b"")
    with pytest.raises(ProviderError):
        mutations(sim, scope=SCOPE).import_image(spec((str(empty), hashlib.sha256(b"").hexdigest())))


def test_proxmox_checks_the_checksum_too(sim, job, image, monkeypatch):
    enable_import(sim)
    m = mutations(sim, scope=SCOPE)
    from ics.providers.proxmox import provider as pv
    monkeypatch.setattr(pv, "_file_sha256", lambda p: (image[1], len(BLOB)))          # the local check passes, but the bytes on the wire differ from the digest
    bad = spec((image[0], image[1]), sha256="00" * 32)
    monkeypatch.setattr(pv, "hmac_equal", lambda a, b: True)
    with pytest.raises(ProviderError):
        m.import_image(bad)


def test_scope_and_naming_are_enforced_before_anything_is_sent(sim, job, image):
    enable_import(sim)
    m = mutations(sim, scope=SCOPE)
    for bad, exc in ((dict(import_storage="other-lvm"), ScopeViolation), (dict(target_storage="other-lvm"), ScopeViolation), (dict(pool="other"), ScopeViolation),
                     (dict(node="pve9"), ScopeViolation), (dict(bridge="vmbr9"), ScopeViolation), (dict(name="web01"), ProviderError),
                     (dict(name="ou-tpl-x; reboot"), ProviderError), (dict(sha256="zz"), ProviderError), (dict(cores=0), ProviderError)):
        with pytest.raises(exc):
            m.import_image(spec(image, **bad))
    import os
    import shutil
    other = os.path.join(os.path.dirname(image[0]), "evil.qcow2")
    shutil.copy(image[0], other)
    with pytest.raises(ProviderError, match="ou-golden"):
        m.import_image(spec((other, image[1])))
    assert not hasattr(sim.sim, "uploaded_bytes")


def test_import_privileges_are_documented_and_optional():
    assert "import_image" not in priv.PROVISION_VERBS and "import_image" in priv.VERB_PRIVS      # an owner-enabled capability, not part of the default probe
    assert "Datastore.AllocateTemplate" in priv.IMPORT_STORAGE_PRIVS
    assert ("/storage/local", ["Datastore.AllocateSpace"]) in priv.required("import_image", ["p"], ["local"], [], {})
