"""`image.import` provider verb (bootstrap v2): upload a signed golden image to an `import` directory storage and turn it into a template. Against the
simulator, which models PVE 9's upload API (multipart, content=import, checksum, Datastore.AllocateTemplate) and `import-from` disk creation."""
import hashlib
import os

import pytest

from ics.providers.base import ImageImportSpec, ProviderError, ScopeViolation
from ics.providers.proxmox import privileges as priv
from ics.providers.proxmox.provider import EndpointScope
from .infra_fixtures import LAB, job, mutations, sim  # noqa: F401


@pytest.fixture(autouse=True)
def _floor_store():
    from ics.guest import golden
    saved = (golden._FLOOR, golden._TRUST_SOURCE)  # a session-wide Runtime may have installed the real ones: put them back afterwards
    golden.set_floor_store(golden.MemoryFloor())   # production: runtime sets golden.DbFloor (image_floor table)
    yield
    golden.set_floor_store(saved[0])
    golden.set_trust_source(saved[1])

SCOPE = EndpointScope(pools=("ou-lab",), storage=("local-lvm", "local"), networks=("vmbr1",), nodes=("pve1", "pve2"))
BLOB = b"QFI\xfb" + b"\x00" * 4096 + b"golden"


def release(tmp_path, date="20261115", version=1):
    """a really signed release directory (ECDSA P-256 manifest) as the offline release host produces it"""
    from ics.guest import golden
    from .test_golden_image import ATTESTOR_PUB_B64, make_release
    sub = tmp_path / f"r{date}"
    sub.mkdir()
    d, pem, pin, _k = make_release(sub, name=f"ou-golden-debian-12-{date}.qcow2", image=BLOB, version=version)
    return (os.path.join(d, f"ou-golden-debian-12-{date}.qcow2"), hashlib.sha256(BLOB).hexdigest(),
            dict(release_dir=d, trust=golden.Trust(pem, pin, ATTESTOR_PUB_B64)))


@pytest.fixture()
def image(tmp_path):
    return release(tmp_path)


def enable_import(sim, with_priv=True):
    sim.sim.storages["local"]["content"] += ",import"
    if with_priv:
        sim.sim.add_role("OUImport", {"Datastore.AllocateTemplate", "Datastore.AllocateSpace", "Datastore.Audit"})
        sim.sim.tokens[LAB[0]]["acl"].append(("/storage/local", "OUImport"))


def spec(image, floor=None, **kw):
    """review 8 M-4: trust and floor are server state. The test installs the release's trust as the server trust (Settings in production) and the
    floor into the floor store (the image_floor table in production); the spec itself carries neither."""
    from ics.guest import golden
    path, sha = image[:2]
    extra = dict(image[2]) if len(image) > 2 else {}
    t = extra.pop("trust", None)
    golden.set_trust_source((lambda: t) if t is not None else None)
    if floor is not None:
        st = golden.MemoryFloor()
        st.v, st.d = {"debian-12": (floor.version, floor.image_sha256)}, ({"debian-12": floor.date} if floor.date else {})
        golden.set_floor_store(st)
    d = dict(node="pve1", import_storage="local", target_storage="local-lvm", file_path=path, sha256=sha, name="ou-tpl-debian12-agent", pool="ou-lab", **extra)
    d.update(kw)
    return ImageImportSpec(**d)


def test_import_uploads_verifies_creates_and_templates(sim, job, image):
    enable_import(sim)
    m = mutations(sim, scope=SCOPE)
    r = m.import_image(spec(image))
    vm = sim.sim.vms[r.vmid]
    assert r.name == "ou-tpl-debian12-agent" and r.volid == "local:import/ou-golden-debian-12-20261115.qcow2"
    assert vm["cfg"]["template"] == 1 and vm["pool"] == "ou-lab" and "ou-managed" in vm["cfg"]["tags"] and "ou-image" in vm["cfg"]["tags"]
    assert vm["cfg"]["scsi0"].startswith("local-lvm:vm-") and sim.sim.uploaded_bytes == len(BLOB)
    assert sim.sim.storages["local"]["files"]["import/ou-golden-debian-12-20261115.qcow2"] == len(BLOB)
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
    path, sha = image[:2]
    with open(path, "ab") as f:
        f.write(b"tampered after signature verification")
    with pytest.raises(ProviderError) as e:
        mutations(sim, scope=SCOPE).import_image(spec(image))
    assert e.value.code == "integrity" and not hasattr(sim.sim, "uploaded_bytes")
    empty = tmp_path / "ou-golden-empty.qcow2"
    empty.write_bytes(b"")
    with pytest.raises(ProviderError):
        mutations(sim, scope=SCOPE).import_image(spec((str(empty), hashlib.sha256(b"").hexdigest(), image[2])))


def test_a_claimed_checksum_that_differs_from_the_verified_release_is_refused(sim, job, image):
    enable_import(sim)
    with pytest.raises(ProviderError, match="differ from the verified release"):
        mutations(sim, scope=SCOPE).import_image(spec(image, sha256="00" * 32))
    assert not hasattr(sim.sim, "uploaded_bytes")


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
    with pytest.raises(ProviderError, match="verified release"):
        m.import_image(spec((other, image[1], image[2])))
    assert not hasattr(sim.sim, "uploaded_bytes")


def test_import_privileges_are_documented_and_optional():
    assert "import_image" not in priv.PROVISION_VERBS and "import_image" in priv.VERB_PRIVS      # an owner-enabled capability, not part of the default probe
    assert "Datastore.AllocateTemplate" in priv.IMPORT_STORAGE_PRIVS
    assert ("/storage/local", ["Datastore.AllocateSpace"]) in priv.required("import_image", ["p"], ["local"], [], {})


# ---- review 5 M7: the verb verifies the signed release itself and protects against rollback
def test_m7_an_unsigned_or_unpinned_import_is_refused(sim, job, image, tmp_path):
    enable_import(sim)
    m = mutations(sim, scope=SCOPE)
    with pytest.raises(ProviderError, match="signed release"):
        m.import_image(spec((image[0], image[1])))                                   # a bare path + caller-supplied checksum: the pre-fix import path
    with pytest.raises(ProviderError, match="trust configured"):
        m.import_image(spec((image[0], image[1], {"release_dir": image[2]["release_dir"]})))   # no server trust configured: refused
    from ics.guest import golden
    wrong_pin = dict(image[2], trust=golden.Trust(image[2]["trust"].release_pubkey_pem, "00" * 32, image[2]["trust"].attestor_pubkey_b64))
    with pytest.raises(ProviderError, match="release verification failed"):
        m.import_image(spec((image[0], image[1], wrong_pin)))
    assert not hasattr(sim.sim, "uploaded_bytes")


def test_m7_a_release_with_a_forged_manifest_is_refused(sim, job, image):
    enable_import(sim)
    open(os.path.join(image[2]["release_dir"], "manifest.json"), "a").write(" ")
    with pytest.raises(ProviderError, match="release verification failed"):
        mutations(sim, scope=SCOPE).import_image(spec(image))


def test_m7_older_releases_are_refused_unless_an_explicit_downgrade(sim, job, tmp_path):
    """review 7 M-4: the floor is the ICS database's (passed in the spec by the caller), not Proxmox tags"""
    from ics.guest import golden
    enable_import(sim)
    m = mutations(sim, scope=SCOPE)
    new = release(tmp_path, "20261115", version=5)
    floor = golden.Floor(5, new[1])
    r = m.import_image(spec(new, floor=floor))
    assert "ou-rel-debian-12-20261115" in sim.sim.vms[r.vmid]["cfg"]["tags"]
    old = release(tmp_path, "20261001", version=3)
    with pytest.raises(ProviderError) as e:
        m.import_image(spec(old, name="ou-tpl-debian12-agent2", floor=floor))
    assert "rollback floor 5" in e.value.message
    ok = m.import_image(spec(old, name="ou-tpl-debian12-agent2", floor=floor, allow_downgrade=True))     # the explicit (high-risk) downgrade plan
    assert sim.sim.vms[ok.vmid]["cfg"]["template"] == 1
    newer = release(tmp_path, "20261120", version=6)
    assert m.import_image(spec(newer, name="ou-tpl-debian12-agent3", floor=floor)).vmid                  # moving forward is fine
    # deleting every template in Proxmox does not lower anything: the floor is not read from there any more


def test_m4_trust_and_floor_are_not_spec_fields_and_caller_data_cannot_reach_the_verb(sim, job, image):
    """review 7 M-4 / review 8 M-4: the release key, pin, attestor key and the rollback floor are read by the verb from server state only
    (Settings via golden.server_trust, the DB via golden.floor_store). A spec cannot even carry them."""
    import dataclasses
    names = {f.name for f in dataclasses.fields(ImageImportSpec)}
    assert not names & {"trust", "floor"}
    with pytest.raises(TypeError):
        ImageImportSpec(node="pve1", import_storage="local", target_storage="local-lvm", file_path=image[0], sha256=image[1], name="ou-tpl-x",
                        pool="ou-lab", release_dir=image[2]["release_dir"], trust=image[2]["trust"])
    from ics.guest import golden
    enable_import(sim)
    m = mutations(sim, scope=SCOPE)
    other = golden.Trust(image[2]["trust"].release_pubkey_pem, "00" * 32, image[2]["trust"].attestor_pubkey_b64)
    golden.set_trust_source(lambda: other)                                             # the SERVER trust decides: wrong pin there -> refused
    d = dict(image[2]); d.pop("trust")
    with pytest.raises(ProviderError, match="release verification failed"):
        m.import_image(ImageImportSpec(node="pve1", import_storage="local", target_storage="local-lvm", file_path=image[0], sha256=image[1],
                                       name="ou-tpl-debian12-agent", pool="ou-lab", **d))
    assert not hasattr(sim.sim, "uploaded_bytes")


def test_a_release_dated_before_the_accepted_one_is_refused(sim, job, tmp_path):
    """review 8 M-4: the date floor is enforced as well as the version floor"""
    from ics.guest import golden
    enable_import(sim)
    old = release(tmp_path, "20261001", version=7)
    with pytest.raises(ProviderError, match="before the accepted release date"):
        mutations(sim, scope=SCOPE).import_image(spec(old, floor=golden.Floor(6, "ab" * 32, "20261115")))
