"""The golden-image release pipeline pieces we can verify without building an image: signed-manifest verification before `image.import`, the recipe's
refusal to run with an unpinned upstream key, the image's closed shape (no SSH, default-deny, agent not initialised) and the SBOM generator."""
import base64
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ics.guest import golden

RECIPE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "blueprints", "build", "guest-image")


ATTESTOR_KEY = Ed25519PrivateKey.generate()
ATTESTOR_PUB_B64 = base64.b64encode(ATTESTOR_KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def make_release(tmp_path, name="ou-golden-debian-12-20261115.qcow2", image=b"QFI\xfbimage", sbom=None, version=1, created_at=None, mutate=None, attest_key=None, att_over=None):
    """a really signed v2 release directory (ECDSA P-256 manifest + Ed25519 test-runner attestation) as the release host produces it"""
    created_at = int(time.time()) - 3600 if created_at is None else created_at
    sbom = sbom or json.dumps({"bomFormat": "CycloneDX", "components": [{"name": f"p{i}"} for i in range(60)]}).encode()
    k = ec.generate_private_key(ec.SECP256R1())
    pem = k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    d = tmp_path / "rel"
    d.mkdir()
    pkgs = "".join(f"pkg{i:03d}=1.{i}\n" for i in range(80)).encode()
    os_id = (golden.IMAGE_RE.match(name) or golden.IMAGE_RE.match("ou-golden-debian-12-20261115.qcow2")).group(1)
    prov = json.dumps({"os": os_id, "source_date_epoch": created_at, "recipe_sha256": "ab" * 32, "package_lock_sha256": hashlib.sha256(pkgs).hexdigest(),
                       "archive_inrelease_sha256": {"x_InRelease": "cd" * 32}}).encode()
    files = {name: image, name + ".sbom.cdx.json": sbom, name + ".packages.lock": pkgs, name + ".provenance.json": prov}
    for n, b in files.items():
        (d / n).write_bytes(b)
    att = {"v": 2, "kind": "image-first-boot", "name": "first-boot", "sha256": hashlib.sha256(image).hexdigest(), "result": "pass", "log_sha256": "ee" * 32,
           "at": created_at + 600, "run_id": "0f" * 16}
    att.update(att_over or {})
    m = {"schema": golden.SCHEMA, "name": name, "os": os_id, "version": version, "created_at": created_at,
         "image": {"file": name, "sha256": hashlib.sha256(image).hexdigest(), "size": len(image)},
         "packages": {"file": name + ".packages.lock", "sha256": hashlib.sha256(pkgs).hexdigest(), "count": 80},
         "sbom": {"file": name + ".sbom.cdx.json", "sha256": hashlib.sha256(sbom).hexdigest()},
         "provenance": {"file": name + ".provenance.json", "sha256": hashlib.sha256(prov).hexdigest(), "source_date_epoch": created_at, "recipe_sha256": "ab" * 32,
                        "package_lock_sha256": hashlib.sha256(pkgs).hexdigest()},
         "boot_test": {"attestation": att, "sig": base64.b64encode((attest_key or ATTESTOR_KEY).sign(golden.ATT_PREFIX + canon(att))).decode(),
                       "attestation_sha256": hashlib.sha256(canon(att)).hexdigest()}}
    if mutate:
        mutate(m)
    raw = canon(m) + b"\n"
    (d / "manifest.json").write_bytes(raw)
    (d / "manifest.json.sig").write_text(base64.b64encode(k.sign(raw, ec.ECDSA(hashes.SHA256()))).decode())
    return str(d), pem, golden.key_pin(pem), k


def verify(d, pem, pin, **kw):
    kw.setdefault("attestor_pubkey_b64", ATTESTOR_PUB_B64)
    return golden.verify_release(d, pem, pin, **kw)


PINS = {"debian-12": ("B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8", "4D64FEC119C2029067D6E791F8D2585B8783D481", "05AB90340C0C5E797F44A8C8254CF3B5AEC0A8F0"),
        "ubuntu-24.04": ("D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81", "F6ECB3762474EDA9D21B7022871920D1991BC93C")}
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
    ok2 = _run("ubuntu-24.04", "verify", WORK=str(tmp_path / "wu"), HOME=str(tmp_path))
    assert ok2.returncode == 0, ok2.stderr
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
        e = {"PATH": os.environ["PATH"], "WORK": str(tmp_path / "w"), "OUT": str(tmp_path / "o"), "UPSTREAM_KEY_FILE": str(key), "HOME": str(tmp_path), "UPSTREAM_SERIAL": "release-20261110", "OU_TODAY": "20261116"}
        return subprocess.run(["bash", str(rd / "recipe.sh"), "ubuntu-24.04", "verify-upstream"], capture_output=True, text=True, timeout=60, env=e)
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


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")
def test_the_image_signer_needs_a_passing_boot_record_recomputes_hashes_and_signs_what_the_ics_verifies(tmp_path):
    st = tmp_path / "state"
    (st / "records").mkdir(parents=True)
    (st / "passphrase").write_text("pp-" + "x" * 20)
    subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-aes-256-cbc", "-pass", f"file:{st}/passphrase", "-out", str(st / "key.pem")],
                   check=True, capture_output=True)
    prog = os.path.join(RECIPE_DIR, "signer", "ou-image-sign")
    env = {"PATH": os.environ["PATH"], "OU_IMGSIGN_STATE": str(st)}
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
    subprocess.run([prog, "record-test", h, "first-boot", "fail", "0" * 64], check=True, env=env, capture_output=True)
    assert b"did not pass" in sign(mk()).stderr
    subprocess.run([prog, "record-test", h, "first-boot", "pass", "0" * 64], check=True, env=env, capture_output=True)
    assert sign(mk(extra=True)).returncode == 3 and sign(mk(sb=b"{}")).returncode == 3         # extra member / not a CycloneDX inventory
    assert sign(mk(img=image + b"x")).returncode == 3                                             # a different image has no record
    r = sign(mk())
    assert r.returncode == 0, r.stderr
    tarfile.open(fileobj=io.BytesIO(r.stdout)).extractall(tmp_path / "rel", filter="data")
    (tmp_path / "rel" / name).write_bytes(image)
    (tmp_path / "rel" / (name + ".sbom.cdx.json")).write_bytes(sbom)
    # legacy v1 signer output (SHA256SUMS): manifest v2 signing is the signer agent's integration (docs/status/golden-image-prod-results.md "Signer contract")
    sums = (tmp_path / "rel" / "SHA256SUMS").read_text()
    assert sums == f"{h}  {name}\n{hashlib.sha256(sbom).hexdigest()}  {name}.sbom.cdx.json\n"
