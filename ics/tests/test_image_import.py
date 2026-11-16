"""`image.import` provider verb (bootstrap v2): upload a signed golden image to an `import` directory storage and turn it into a template. Against the
simulator, which models PVE 9's upload API (multipart, content=import, checksum, Datastore.AllocateTemplate) and `import-from` disk creation."""
import hashlib
import os

import pytest

from ics.providers.base import ImageImportSpec, ProviderError, ScopeViolation
from ics.providers.proxmox import privileges as priv
from ics.providers.proxmox.provider import EndpointScope
from .infra_fixtures import LAB, job, mutations, sim  # noqa: F401

SCOPE = EndpointScope(pools=("ou-lab",), storage=("local-lvm", "local"), networks=("vmbr1",), nodes=("pve1", "pve2"))
BLOB = b"QFI\xfb" + b"\x00" * 4096 + b"golden"


_STATE: dict = {}


@pytest.fixture(autouse=True)
def server_trust():
    """review 7 M-4: the release key + pin are SERVER configuration (golden.configure) and the downgrade floor is the ICS database's (here: in memory)"""
    from ics.guest import golden
    _STATE.clear()
    golden.configure(None, None)
    golden.set_floor_store(golden.MemoryFloor())
    yield
    golden.configure(None, None)
    golden.set_floor_store(None)


def release(tmp_path, date="20261115"):
    """a really signed release directory (ECDSA P-256 manifest) as the offline release host produces it; the ICS is configured to trust ITS key"""
    from cryptography.hazmat.primitives.asymmetric import ec
    from ics.guest import golden
    from .test_golden_image import make_release
    sub = tmp_path / f"r{date}"
    sub.mkdir()
    _STATE.setdefault("key", ec.generate_private_key(ec.SECP256R1()))
    d, pem, pin, _k = make_release(sub, name=f"ou-golden-debian-12-{date}.qcow2", image=BLOB, key=_STATE["key"])
    golden.configure(pem, pin)
    return (os.path.join(d, f"ou-golden-debian-12-{date}.qcow2"), hashlib.sha256(BLOB).hexdigest(), dict(release_dir=d))


@pytest.fixture()
def image(tmp_path):
    return release(tmp_path)


def enable_import(sim, with_priv=True):
    sim.sim.storages["local"]["content"] += ",import"
    if with_priv:
        sim.sim.add_role("OUImport", {"Datastore.AllocateTemplate", "Datastore.AllocateSpace", "Datastore.Audit"})
        sim.sim.tokens[LAB[0]]["acl"].append(("/storage/local", "OUImport"))


def spec(image, **kw):
    path, sha = image[:2]
    d = dict(node="pve1", import_storage="local", target_storage="local-lvm", file_path=path, sha256=sha, name="ou-tpl-debian12-agent", pool="ou-lab",
             **(image[2] if len(image) > 2 else {}))
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
    from ics.guest import golden
    pem, _pin = golden.trust_root()
    golden.configure(pem, "00" * 32)                                                  # the SERVER's pin does not match the key: refused
    with pytest.raises(ProviderError, match="release verification failed"):
        m.import_image(spec(image))
    golden.configure(None, None)                                                     # no trust root configured at all: refused
    with pytest.raises(ProviderError, match="no golden-image release key"):
        m.import_image(spec(image))
    assert not hasattr(sim.sim, "uploaded_bytes")


def test_m4_the_caller_cannot_supply_the_key_or_the_pin(sim, job, image):
    """review 7 M-4: ImageImportSpec has no key/pin fields any more; a key the caller signs with is not trusted unless the server config says so"""
    import dataclasses
    import pathlib
    from cryptography.hazmat.primitives.asymmetric import ec
    from .test_golden_image import make_release
    assert not {"release_pubkey_pem", "release_pin_sha256"} & {f.name for f in dataclasses.fields(ImageImportSpec)}
    with pytest.raises(TypeError):
        spec(image, release_pubkey_pem="x", release_pin_sha256="y")
    other = pathlib.Path(os.path.dirname(image[0])).parent / "attacker"
    other.mkdir()
    d, pem, pin, _k = make_release(other, name="ou-golden-debian-12-20261115.qcow2", image=BLOB, key=ec.generate_private_key(ec.SECP256R1()))
    enable_import(sim)
    with pytest.raises(ProviderError, match="release verification failed"):                 # signed by a key the server does not trust
        mutations(sim, scope=SCOPE).import_image(spec((os.path.join(d, "ou-golden-debian-12-20261115.qcow2"), image[1], dict(release_dir=d))))


def test_m4_the_floor_is_database_state_and_survives_deleting_the_newest_template(sim, job, tmp_path):
    from ics.guest import golden
    enable_import(sim)
    m = mutations(sim, scope=SCOPE)
    r = m.import_image(spec(release(tmp_path, "20261115")))
    assert golden.floor_store().get("debian-12") == "20261115"
    sim.sim.vms.pop(r.vmid)                                    # an operator deletes (or re-tags) the newest template at the provider
    with pytest.raises(ProviderError) as e:
        m.import_image(spec(release(tmp_path, "20261001"), name="ou-tpl-debian12-agent2"))
    assert e.value.code == "downgrade"                         # the old code read the floor from the template tags and let this through
    m.import_image(spec(release(tmp_path, "20261002"), name="ou-tpl-debian12-agent3", allow_downgrade=True))
    assert golden.floor_store().get("debian-12") == "20261115"  # a separately approved downgrade never lowers it


def test_m4_db_floor_is_monotonic(rt, owner_engine):
    from sqlalchemy import text
    from sqlalchemy.exc import DBAPIError
    from ics.guest import golden
    f = golden.DbFloor(rt)
    assert f.get("debian-12") is None
    f.raise_to("debian-12", "20261115")
    f.raise_to("debian-12", "20261001")
    assert f.get("debian-12") == "20261115"
    with pytest.raises(DBAPIError, match="monotonic"):
        with rt.session() as db:
            db.execute(text("UPDATE image_floor SET release_date = '20200101' WHERE os = 'debian-12'"))
            db.commit()
    with owner_engine.connect() as c:
        c.execute(text("ALTER TABLE image_floor DISABLE TRIGGER image_floor_guard"))
        c.execute(text("DELETE FROM image_floor"))
        c.execute(text("ALTER TABLE image_floor ENABLE TRIGGER image_floor_guard"))


def test_m7_a_release_with_a_forged_manifest_is_refused(sim, job, image):
    enable_import(sim)
    open(os.path.join(image[2]["release_dir"], "SHA256SUMS"), "a").write("00" * 32 + "  ou-golden-debian-12-20261115.qcow2\n")
    with pytest.raises(ProviderError, match="release verification failed"):
        mutations(sim, scope=SCOPE).import_image(spec(image))


def test_m7_older_releases_are_refused_unless_an_explicit_downgrade(sim, job, tmp_path):
    enable_import(sim)
    m = mutations(sim, scope=SCOPE)
    new = release(tmp_path, "20261115")
    r = m.import_image(spec(new))
    assert f"ou-rel-debian-12-20261115" in sim.sim.vms[r.vmid]["cfg"]["tags"]
    old = release(tmp_path, "20261001")
    with pytest.raises(ProviderError) as e:
        m.import_image(spec(old, name="ou-tpl-debian12-agent2"))
    assert e.value.code == "downgrade" and "20261115" in e.value.message
    ok = m.import_image(spec(old, name="ou-tpl-debian12-agent2", allow_downgrade=True))     # the explicit (high-risk) downgrade plan
    assert sim.sim.vms[ok.vmid]["cfg"]["template"] == 1
    newer = release(tmp_path, "20261120")
    assert m.import_image(spec(newer, name="ou-tpl-debian12-agent3")).vmid                  # moving forward is fine


def test_m7_newest_imported_reads_only_the_verbs_own_tags():
    from ics.guest import golden
    tags = ["ou-managed;ou-image;ou-rel-debian-12-20261001", "ou-rel-debian-12-20261115;ou-image", "ou-rel-ubuntu-24.04-20270101", "evil;ou-rel-debian-12-99999999x"]
    assert golden.newest_imported(tags, "debian-12") == "20261115" and golden.newest_imported(tags, "ubuntu-24.04") == "20270101"
    assert golden.newest_imported([], "debian-12") is None
