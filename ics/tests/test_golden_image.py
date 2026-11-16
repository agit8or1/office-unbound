"""The golden-image release pipeline pieces we can verify without building an image: signed-manifest verification before `image.import`, the recipe's
refusal to run with an unpinned upstream key, the image's closed shape (no SSH, default-deny, agent not initialised) and the SBOM generator."""
import base64
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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


PINS = {"debian-12": ("B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8", "4D64FEC119C2029067D6E791F8D2585B8783D481", "05AB90340C0C5E797F44A8C8254CF3B5AEC0A8F0"),
        "ubuntu-24.04": ("D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81",)}
needs_gpg = pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg not installed")


def _run(os_id, step, **env):
    w = env.pop("WORK")
    e = {"PATH": os.environ["PATH"], "WORK": w, "OUT": env.pop("OUT", w + "/out")}
    e.update(env)
    return subprocess.run(["bash", os.path.join(RECIPE_DIR, "recipe.sh"), os_id, step], capture_output=True, text=True, timeout=60, env=e)


def _primary_fprs(path, home):
    out = subprocess.run(["gpg", "--show-keys", "--with-colons", path], capture_output=True, text=True, env={"PATH": os.environ["PATH"], "HOME": str(home)}).stdout.splitlines()
    prim, want = [], False
    for l in out:
        if l.startswith("pub:"):
            want = True
        elif l.startswith("fpr:") and want:
            prim.append(l.split(":")[9])
            want = False
    return prim


@needs_gpg
def test_the_recipe_pins_the_authoritative_upstream_fingerprints_and_the_shipped_keys_match_them(tmp_path):
    """Agent AT (docs/status/golden-image-results.md s1): the pins are set and every key file in keys/ holds EXACTLY one pinned primary fingerprint."""
    for os_id, fprs in PINS.items():
        env = open(os.path.join(RECIPE_DIR, "os", os_id + ".env")).read()
        assert all(f in env for f in fprs)
    keys = os.path.join(RECIPE_DIR, "keys")
    seen = set()
    for f in sorted(os.listdir(keys)):
        prim = _primary_fprs(os.path.join(keys, f), tmp_path)
        assert len(prim) == 1
        seen.add(prim[0])
    assert seen == {x for v in PINS.values() for x in v}
    ok = _run("debian-12", "verify", WORK=str(tmp_path / "w"), HOME=str(tmp_path))
    assert ok.returncode == 0, ok.stderr
    bad = tmp_path / "keys"
    shutil.copytree(keys, bad)
    shutil.copy(os.path.join(keys, "ubuntu-uec-image-signing.asc"), bad / "debian-archive-bookworm-stable.asc")     # a key that is not pinned for Debian
    r = _run("debian-12", "verify", WORK=str(tmp_path / "w2"), HOME=str(tmp_path), KEYS=str(bad))
    assert r.returncode == 4 and "not pinned" in r.stderr


@needs_gpg
def test_the_ubuntu_profile_refuses_a_wrong_pin_a_tampered_checksum_file_and_a_wrong_image(tmp_path):
    """Offline: a locally generated key stands in for upstream; a signed checksum file + image verify, and each attack exits 4."""
    gh = tmp_path / "gh"
    gh.mkdir(mode=0o700)
    base = ["gpg", "--homedir", str(gh), "--batch", "--pinentry-mode", "loopback", "--passphrase", ""]
    subprocess.run(base + ["--quick-generate-key", "upstream test <t@example.invalid>", "ed25519", "sign", "1d"], check=True, capture_output=True)
    fpr = [l.split(":")[9] for l in subprocess.run(base + ["--list-keys", "--with-colons"], capture_output=True, text=True).stdout.splitlines() if l.startswith("fpr:")][0]
    up = tmp_path / "w" / "up"
    up.mkdir(parents=True)
    img = up / "noble-server-cloudimg-amd64.img"
    img.write_bytes(b"image bytes")
    sums = hashlib.sha256(b"image bytes").hexdigest() + " *noble-server-cloudimg-amd64.img\n"
    (up / "SHA256SUMS").write_text(sums)
    subprocess.run(base + ["--detach-sign", "-o", str(up / "SHA256SUMS.gpg"), str(up / "SHA256SUMS")], check=True, capture_output=True)
    key = tmp_path / "k.asc"
    key.write_bytes(subprocess.run(base + ["--export", "--armor", fpr], capture_output=True, check=True).stdout)
    rd = tmp_path / "recipe"
    shutil.copytree(RECIPE_DIR, rd, ignore=shutil.ignore_patterns("keys", "__pycache__"))
    shutil.copytree(os.path.join(RECIPE_DIR, "..", "keys"), tmp_path / "keys")
    envf = rd / "os" / "ubuntu-24.04.env"
    orig = envf.read_text()
    real = "D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81"

    def run():
        e = {"PATH": os.environ["PATH"], "WORK": str(tmp_path / "w"), "OUT": str(tmp_path / "o"), "UPSTREAM_KEY_FILE": str(key), "HOME": str(tmp_path), "UPSTREAM_SERIAL": "release-20261114", "OU_TODAY": "20261115"}
        return subprocess.run(["bash", str(rd / "recipe.sh"), "ubuntu-24.04", "verify"], capture_output=True, text=True, timeout=60, env=e)
    envf.write_text(orig.replace(real, fpr))
    r = run()
    assert r.returncode == 0 and "verified" in r.stdout, r.stderr
    envf.write_text(orig)                                            # the real pin is not this key: refused
    assert run().returncode == 4
    envf.write_text(orig.replace(real, fpr))
    (up / "SHA256SUMS").write_text(sums.replace("*", "#", 1))        # tampered checksum file: the signature no longer verifies
    assert run().returncode == 4
    (up / "SHA256SUMS").write_text(sums)
    img.write_bytes(b"other bytes")                                  # image differs from the signed checksum
    assert run().returncode == 4


def test_the_recipe_scripts_are_valid_shell_and_the_image_has_a_closed_shape():
    for f in ("recipe.sh", "customize.sh", "ou-bootcfg", "ou-growroot", os.path.join("agent-deb", "build-deb.sh"), os.path.join("agent-deb", "publish-dev.sh"),
              os.path.join("signer", "install-image-signer.sh")):
        assert subprocess.run(["bash", "-n", os.path.join(RECIPE_DIR, f)]).returncode == 0, f
    c = "\n".join(l.split(" #")[0] for l in open(os.path.join(RECIPE_DIR, "customize.sh")).read().splitlines() if not l.lstrip().startswith("#"))
    assert "systemctl mask ssh.service ssh.socket" in c and "cloud-init.disabled" in c and "passwd -l root" in c
    assert "install -y" in c and "qemu-guest-agent" not in c and "openssh-server" not in c      # no hypervisor exec channel (ADR-0002 s7), no SSH server
    assert "ou_agent init" not in c and "ou-agent init" not in c and "ssh_host_" in c           # no per-VM identity is baked into the image
    assert "apt-get install -y --no-install-recommends ou-node-agent" in c and "curl" not in c and "| sh" not in c   # the agent comes from the signed repo only
    nft = open(os.path.join(RECIPE_DIR, "nftables.conf")).read()
    assert "policy drop" in nft and "dport 22" not in nft and "8443" not in nft
    unit = open(os.path.join(RECIPE_DIR, "ou-bootstrap.service")).read()
    assert "Restart=no" in unit and "ConditionPathExists=!/var/lib/ou-bootstrap/failed" in unit and "ou_agent.firstboot" in unit
    rec = open(os.path.join(RECIPE_DIR, "recipe.sh")).read()
    assert "VALIDSIG" in rec and "UPSTREAM_KEY_FPR" in rec and "qemu-guest-agent" not in rec and "NOPASSWD" not in rec
    for os_id in ("debian-12", "ubuntu-24.04"):
        assert "https://" in open(os.path.join(RECIPE_DIR, "os", os_id + ".env")).read()


def test_the_licence_scan_denies_non_free_and_reports_unknown_licences(tmp_path):
    bom = {"bomFormat": "CycloneDX", "components": [
        {"type": "library", "name": "a", "version": "1", "licenses": [{"license": {"id": "MIT"}}]},
        {"type": "library", "name": "b", "version": "1", "licenses": [{"license": {"name": "GPL-2+"}}]},
        {"type": "library", "name": "c", "version": "1", "licenses": [{"license": {"name": "Weird-Custom"}}]},
        {"type": "file", "name": "/boot/x"}]}
    (tmp_path / "in.json").write_text(json.dumps(bom))
    args = ["python3", "-I", os.path.join(RECIPE_DIR, "licensescan.py"), str(tmp_path / "in.json"), os.path.join(RECIPE_DIR, "license-policy.yaml"), "debian-12",
            str(tmp_path / "o.json"), str(tmp_path / "r.json")]
    assert subprocess.run(args, capture_output=True).returncode == 0
    rep = json.loads((tmp_path / "r.json").read_text())
    assert rep["summary"] == {"components": 3, "allowed": 2, "review": 1, "denied": 0} and "c@1" in rep["review"]
    bom["components"].append({"type": "library", "name": "d", "version": "1", "licenses": [{"license": {"name": "Proprietary EULA"}}]})
    (tmp_path / "in.json").write_text(json.dumps(bom))
    assert subprocess.run(args, capture_output=True).returncode == 5


KEYGEN = os.path.join(RECIPE_DIR, "..", "repo", "ou-test-attest")
ATT = os.path.join(RECIPE_DIR, "..", "oci", "signer", "ou-artifact-attest")


def _runner(tmp_path, st, env):
    """a sandbox test runner: its own key, whose public half is the signer's trust anchor"""
    renv = {**env, "OU_TESTRUNNER_STATE": str(tmp_path / "runner")}
    pub = subprocess.run([sys.executable, KEYGEN, "keygen"], env=renv, capture_output=True, text=True, check=True).stdout.strip()
    (st / "trust").mkdir()
    (st / "trust" / "test-runner.pub").write_text(pub)
    os.chmod(st / "trust", 0o755)
    os.chmod(st / "trust" / "test-runner.pub", 0o644)

    def attest(args, evidence):
        return subprocess.run([sys.executable, ATT, *args], input=json.dumps(evidence).encode(), env=renv, capture_output=True, check=True).stdout
    return attest


def test_the_image_signer_sudoers_names_exact_commands_and_the_runner_validates_its_inputs():
    inst = open(os.path.join(RECIPE_DIR, "signer", "install-image-signer.sh")).read()
    rules = [ln for ln in inst.splitlines() if "NOPASSWD" in ln and "printf" in ln]
    assert len(rules) == 3 and not any("*" in r for r in rules)
    assert [r.split("ou-image-sign ")[1].split("\\n")[0] for r in rules] == ["sign", "record-test", "pubkey"]


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")
def test_the_image_signer_needs_a_passing_boot_record_recomputes_hashes_and_signs_what_the_ics_verifies(tmp_path):
    st = tmp_path / "state"
    (st / "records").mkdir(parents=True)
    (st / "passphrase").write_text("pp-" + "x" * 20)
    subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-aes-256-cbc", "-pass", f"file:{st}/passphrase", "-out", str(st / "key.pem")],
                   check=True, capture_output=True)
    prog = os.path.join(RECIPE_DIR, "signer", "ou-image-sign")
    env = {"PATH": os.environ["PATH"], "OU_IMGSIGN_STATE": str(st), "OU_IMGSIGN_SANDBOX": "1"}
    attest = _runner(tmp_path, st, env)
    name = "ou-golden-debian-12-20261115.qcow2"
    image = b"QFI\xfb" + b"img" * 100
    sbom = json.dumps({"bomFormat": "CycloneDX", "components": [{"name": f"p{i}"} for i in range(60)]}).encode()

    def mk(img=image, sb=sbom, extra=False):
        bio = io.BytesIO()
        with tarfile.open(fileobj=bio, mode="w") as tf:
            for n, b in ((name, img), (name + ".sbom.cdx.json", sb)) + ((("evil", b"x"),) if extra else ()):
                ti = tarfile.TarInfo(n)
                ti.size = len(b)
                tf.addfile(ti, io.BytesIO(b))
        return bio.getvalue()

    def sign(data):
        return subprocess.run([prog, "sign"], input=data, capture_output=True, env=env)
    first = sign(mk())
    assert first.returncode == 3 and b"no test record" in first.stderr                          # no boot proof recorded: refused
    h = hashlib.sha256(image).hexdigest()
    # review 6 H1: the build user can not type a record any more
    assert subprocess.run([prog, "record-test", h, "first-boot", "pass", "0" * 64], env=env, capture_output=True).returncode == 2          # old argument form: refused
    forged = subprocess.run([prog, "record-test"], input=json.dumps({"attestation": {"v": 1, "kind": "image-first-boot", "sha256": h, "name": "first-boot", "result": "pass",
                            "log_sha256": "0" * 64, "at": 1}, "sig": base64.b64encode(b"x" * 64).decode()}).encode(), env=env, capture_output=True)
    assert forged.returncode == 3 and b"not signed by the registered test runner" in forged.stderr
    own = Ed25519PrivateKey.generate()                                                                                                       # a record signed by ANY other key
    att = {"v": 1, "kind": "image-first-boot", "sha256": h, "name": "first-boot", "result": "pass", "log_sha256": "0" * 64, "at": 1}
    sig = base64.b64encode(own.sign(b"ou-test-attestation-v1\n" + json.dumps(att, sort_keys=True, separators=(",", ":")).encode())).decode()
    assert subprocess.run([prog, "record-test"], input=json.dumps({"attestation": att, "sig": sig}).encode(), env=env, capture_output=True).returncode == 3
    assert not (st / "records" / (h + ".json")).exists()
    assert sign(mk()).returncode == 3                                                                                                         # still no record
    bad_ev = {"image_sha256": h, "enrolled": True, "final_state": "enrolled", "secrets_wiped": False, "agent_key_matches_report": True}
    good_ev = {**bad_ev, "secrets_wiped": True}
    r = attest(["image"], bad_ev)
    assert json.loads(r)["attestation"]["result"] == "fail"
    subprocess.run([prog, "record-test"], input=r, check=True, env=env, capture_output=True)
    assert b"did not pass" in sign(mk()).stderr
    assert subprocess.run([sys.executable, ATT, "image", h], input=json.dumps(good_ev).encode(), env={**env, "OU_TESTRUNNER_STATE": str(tmp_path / "runner")}, capture_output=True).returncode == 2   # no argv: only stdin
    assert subprocess.run([sys.executable, ATT, "image"], input=json.dumps({**good_ev, "image_sha256": "zz"}).encode(), env={**env, "OU_TESTRUNNER_STATE": str(tmp_path / "runner")}, capture_output=True).returncode == 3

    subprocess.run([prog, "record-test"], input=attest(["image"], good_ev), check=True, env=env, capture_output=True)
    rec = json.loads((st / "records" / (h + ".json")).read_text())
    rec["results"]["first-boot"]["attestation"]["result"] = "pass"                                                                          # tampered record file: re-verified at sign time
    rec["results"]["first-boot"]["attestation"]["log_sha256"] = "1" * 64
    (st / "records" / (h + ".json")).write_text(json.dumps(rec))
    assert b"no valid test-runner attestation" in sign(mk()).stderr
    subprocess.run([prog, "record-test"], input=attest(["image"], good_ev), check=True, env=env, capture_output=True)
    assert sign(mk(extra=True)).returncode == 3 and sign(mk(sb=b"{}")).returncode == 3         # extra member / not a CycloneDX inventory
    assert sign(mk(img=image + b"x")).returncode == 3                                             # a different image has no record
    r = sign(mk())
    assert r.returncode == 0, r.stderr
    tarfile.open(fileobj=io.BytesIO(r.stdout)).extractall(tmp_path / "rel", filter="data")
    (tmp_path / "rel" / name).write_bytes(image)
    (tmp_path / "rel" / (name + ".sbom.cdx.json")).write_bytes(sbom)
    key, pin = subprocess.run([prog, "pubkey"], capture_output=True, text=True, env=env, check=True).stdout.split("# spki-sha256 pin: ")
    rel = golden.verify_release(str(tmp_path / "rel"), key, pin.strip())                         # exactly what the ICS runs before image.import
    assert rel.sha256 == h and rel.os == "debian-12"
