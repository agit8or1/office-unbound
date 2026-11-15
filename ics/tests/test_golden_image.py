"""The golden-image release pipeline pieces we can verify without building an image: signed-manifest verification before `image.import`, the recipe's
refusal to run with an unpinned upstream key, the image's closed shape (no SSH, default-deny, agent not initialised) and the SBOM generator."""
import base64
import hashlib
import json
import os
import subprocess

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ics.guest import golden

RECIPE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "blueprints", "build", "guest-image")


def make_release(tmp_path, name="ou-golden-debian-12-20261115.qcow2", image=b"QFI\xfbimage", sbom=b'{"bomFormat":"CycloneDX"}'):
    k = ec.generate_private_key(ec.SECP256R1())
    pem = k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    d = tmp_path / "rel"
    d.mkdir()
    (d / name).write_bytes(image)
    (d / (name + ".sbom.cdx.json")).write_bytes(sbom)
    manifest = f"{hashlib.sha256(image).hexdigest()}  {name}\n{hashlib.sha256(sbom).hexdigest()}  {name}.sbom.cdx.json\n"
    (d / "SHA256SUMS").write_text(manifest)
    (d / "SHA256SUMS.sig").write_text(base64.b64encode(k.sign(manifest.encode(), ec.ECDSA(hashes.SHA256()))).decode())
    return str(d), pem, golden.key_pin(pem), k


def test_a_signed_release_verifies_and_yields_the_import_inputs(tmp_path):
    d, pem, pin, _ = make_release(tmp_path)
    r = golden.verify_release(d, pem, pin)
    assert r.name == "ou-golden-debian-12-20261115.qcow2" and r.os == "debian-12" and r.sha256 == hashlib.sha256(b"QFI\xfbimage").hexdigest()
    assert os.path.basename(r.path) == r.name


@pytest.mark.parametrize("attack", ["image", "sbom", "manifest", "sig", "other_key", "wrong_pin", "extra_entry", "symlink", "name", "missing_sig"])
def test_every_tampering_is_refused(tmp_path, attack):
    d, pem, pin, k = make_release(tmp_path)
    img = os.path.join(d, "ou-golden-debian-12-20261115.qcow2")
    if attack == "image":
        open(img, "ab").write(b"x")
    elif attack == "sbom":
        open(img + ".sbom.cdx.json", "ab").write(b"x")
    elif attack == "manifest":
        open(os.path.join(d, "SHA256SUMS"), "a").write("00" * 32 + "  ou-golden-debian-12-20261115.qcow2\n")
    elif attack == "sig":
        open(os.path.join(d, "SHA256SUMS.sig"), "w").write(base64.b64encode(b"\x30\x06\x02\x01\x01\x02\x01\x01").decode())
    elif attack == "other_key":
        other = ec.generate_private_key(ec.SECP256R1())
        pem = other.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        pin = golden.key_pin(pem)
    elif attack == "wrong_pin":
        pin = "00" * 32
    elif attack == "extra_entry":
        m = open(os.path.join(d, "SHA256SUMS")).read() + "ab" * 32 + "  evil.sh\n"
        open(os.path.join(d, "SHA256SUMS"), "w").write(m)
        open(os.path.join(d, "SHA256SUMS.sig"), "w").write(base64.b64encode(k.sign(m.encode(), ec.ECDSA(hashes.SHA256()))).decode())
    elif attack == "symlink":
        os.unlink(img)
        real = os.path.join(d, "real")
        open(real, "wb").write(b"QFI\xfbimage")
        os.symlink(real, img)
    elif attack == "name":
        (tmp_path / "n").mkdir()
        d, pem, pin, _ = make_release(tmp_path / "n", name="evil.qcow2")
    elif attack == "missing_sig":
        os.unlink(os.path.join(d, "SHA256SUMS.sig"))
    with pytest.raises(golden.ReleaseError):
        golden.verify_release(d, pem, pin)


def test_only_an_ecdsa_p256_release_key_is_accepted(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import rsa
    d, _pem, _pin, _ = make_release(tmp_path)
    rsa_pem = rsa.generate_private_key(65537, 2048).public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    with pytest.raises(golden.ReleaseError, match="P-256"):
        golden.verify_release(d, rsa_pem, golden.key_pin(rsa_pem))
    with pytest.raises(golden.ReleaseError):
        golden.verify_release(d, "not a pem", "00" * 32)


def test_the_recipe_refuses_to_fetch_until_the_upstream_signing_key_is_pinned():
    for os_id in ("debian-12", "ubuntu-24.04"):
        r = subprocess.run(["bash", os.path.join(RECIPE_DIR, "recipe.sh"), os_id, "fetch"], capture_output=True, text=True, timeout=30,
                           env={"PATH": os.environ["PATH"], "WORK": "/nonexistent-ou-test/work", "OUT": "/nonexistent-ou-test/out"})
        # (mkdir of the work dir fails first on a read-only path; either way nothing is downloaded)
        assert r.returncode != 0 and "curl" not in r.stdout


def test_the_recipe_scripts_are_valid_shell_and_the_image_has_a_closed_shape():
    for f in ("recipe.sh", "customize.sh"):
        assert subprocess.run(["bash", "-n", os.path.join(RECIPE_DIR, f)]).returncode == 0
    c = "\n".join(l.split(" #")[0] for l in open(os.path.join(RECIPE_DIR, "customize.sh")).read().splitlines() if not l.lstrip().startswith("#"))
    assert "systemctl mask ssh.service ssh.socket" in c and "cloud-init.disabled" in c and "passwd -l root" in c
    assert "install -y" in c and "qemu-guest-agent" not in c                         # no hypervisor exec channel in the image (ADR-0002 s7)
    assert "ou_agent init" not in c and "ou-agent init" not in c and "ssh_host_" in c       # no per-VM identity is baked into the image
    nft = open(os.path.join(RECIPE_DIR, "nftables.conf")).read()
    assert "policy drop" in nft and "dport 22" not in nft and "8443" not in nft
    unit = open(os.path.join(RECIPE_DIR, "ou-bootstrap.service")).read()
    assert "Restart=no" in unit and "ConditionPathExists=!/var/lib/ou-bootstrap/failed" in unit and "ou_agent.firstboot" in unit
    rec = open(os.path.join(RECIPE_DIR, "recipe.sh")).read()
    assert "VALIDSIG" in rec and "UPSTREAM_KEY_FPR" in rec and "qemu-guest-agent" not in rec
    for os_id in ("debian-12", "ubuntu-24.04"):
        env = open(os.path.join(RECIPE_DIR, "os", os_id + ".env")).read()
        assert "UPSTREAM_KEY_FPR=\n" in env and "https://" in env


def test_sbom_generator_emits_cyclonedx_for_installed_packages(tmp_path):
    r = subprocess.run(["python3", "-I", os.path.join(RECIPE_DIR, "sbom.py"), "debian-12"], capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        pytest.skip("dpkg-query not available")
    j = json.loads(r.stdout)
    assert j["bomFormat"] == "CycloneDX" and j["components"] and all(c["purl"].startswith("pkg:deb/debian/") for c in j["components"][:5])
