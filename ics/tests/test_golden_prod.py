"""Golden image production pieces (agent BV): manifest v2 verification (all fields, rollback floor in the ICS DB), the independent boot-test suite's own logic
(static hardening checks on synthetic trees, callback simulator pinned to the real ICS callback functions), and the builder's manifest tool."""
import base64
import dataclasses
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import time

import pytest
from sqlalchemy import text

from ics.guest import callback, golden
from .test_golden_image import ATTESTOR_KEY, ATTESTOR_PUB_B64, canon, make_release, verify

GI = os.path.join(os.path.dirname(__file__), "..", "..", "blueprints", "build", "guest-image")
TESTS = os.path.join(GI, "tests")
sys.path.insert(0, TESTS)
import icssim  # noqa: E402
import staticchecks  # noqa: E402


def good(tmp_path, **kw):
    return make_release(tmp_path, **kw)


def test_v2_release_verifies_and_returns_every_bound_field(tmp_path):
    d, pem, pin, _ = good(tmp_path, version=7)
    r = verify(d, pem, pin)
    assert r.version == 7 and r.os == "debian-12" and r.attestation_run_id == "0f" * 16 and os.path.isfile(r.packages_path) and os.path.isfile(r.provenance_path)


def _resign(d, k, mutate):
    m = json.load(open(os.path.join(d, "manifest.json")))
    mutate(m)
    raw = canon(m) + b"\n"
    open(os.path.join(d, "manifest.json"), "wb").write(raw)
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    open(os.path.join(d, "manifest.json.sig"), "w").write(base64.b64encode(k.sign(raw, ec.ECDSA(hashes.SHA256()))).decode())


def _att(m, **over):
    m["boot_test"]["attestation"].update(over)


ATTACKS = {
    # file-level tampering after signing
    "image": lambda d, k, m: open(os.path.join(d, m["name"]), "ab").write(b"x"),
    "sbom": lambda d, k, m: open(os.path.join(d, m["name"] + ".sbom.cdx.json"), "ab").write(b" "),
    "packages": lambda d, k, m: open(os.path.join(d, m["name"] + ".packages.lock"), "ab").write(b"evil=1\n"),
    "provenance": lambda d, k, m: open(os.path.join(d, m["name"] + ".provenance.json"), "ab").write(b" "),
    "manifest-bytes": lambda d, k, m: open(os.path.join(d, "manifest.json"), "ab").write(b" "),
    "missing-sig": lambda d, k, m: os.unlink(os.path.join(d, "manifest.json.sig")),
    "missing-packages": lambda d, k, m: os.unlink(os.path.join(d, m["name"] + ".packages.lock")),
    # signed but wrong content (the signer's key signs it, so only the checks of golden.py stand between it and an import)
    "extra-field": lambda d, k, m: _resign(d, k, lambda x: x.update({"x": 1})),
    "wrong-schema": lambda d, k, m: _resign(d, k, lambda x: x.update({"schema": "v1"})),
    "os-mismatch": lambda d, k, m: _resign(d, k, lambda x: x.update({"os": "ubuntu-24.04"})),
    "version-zero": lambda d, k, m: _resign(d, k, lambda x: x.update({"version": 0})),
    "version-string": lambda d, k, m: _resign(d, k, lambda x: x.update({"version": "9"})),
    "future": lambda d, k, m: _resign(d, k, lambda x: x.update({"created_at": int(time.time()) + 10 ** 7})),
    "image-size": lambda d, k, m: _resign(d, k, lambda x: x["image"].update({"size": 1})),
    "pkg-count": lambda d, k, m: _resign(d, k, lambda x: x["packages"].update({"count": 3})),
    "prov-epoch": lambda d, k, m: _resign(d, k, lambda x: x["provenance"].update({"source_date_epoch": x["created_at"] + 1})),
    "prov-lockhash": lambda d, k, m: _resign(d, k, lambda x: x["provenance"].update({"package_lock_sha256": "00" * 32})),
    "att-other-image": lambda d, k, m: _resign(d, k, lambda x: _att(x, sha256="00" * 32)),
    "att-fail": lambda d, k, m: _resign(d, k, lambda x: _att(x, result="fail")),
    "att-kind": lambda d, k, m: _resign(d, k, lambda x: _att(x, kind="deb-install-smoke")),
    "att-stale": lambda d, k, m: _resign(d, k, lambda x: _att(x, at=int(time.time()) - 200 * 86400)),
    "att-before-build": lambda d, k, m: _resign(d, k, lambda x: _att(x, at=x["created_at"] - 10)),
    "att-hash": lambda d, k, m: _resign(d, k, lambda x: x["boot_test"].update({"attestation_sha256": "00" * 32})),
    "att-extra": lambda d, k, m: _resign(d, k, lambda x: _att(x, extra=1)),
    "non-canonical": lambda d, k, m: _resign_raw(d, k, json.dumps(m, indent=1).encode() + b"\n"),
    "duplicate-key": lambda d, k, m: _resign_raw(d, k, open(os.path.join(d, "manifest.json"), "rb").read().replace(b'{"boot_test"', b'{"version":9,"boot_test"', 1)),
}


def _resign_raw(d, k, raw):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    open(os.path.join(d, "manifest.json"), "wb").write(raw)
    open(os.path.join(d, "manifest.json.sig"), "w").write(base64.b64encode(k.sign(raw, ec.ECDSA(hashes.SHA256()))).decode())


@pytest.mark.parametrize("attack", sorted(ATTACKS))
def test_every_tampering_and_every_bad_field_is_refused(tmp_path, attack):
    d, pem, pin, k = good(tmp_path)
    m = json.load(open(os.path.join(d, "manifest.json")))
    ATTACKS[attack](d, k, m)
    with pytest.raises(golden.ReleaseError):
        verify(d, pem, pin)


def test_wrong_keys_and_pins_are_refused(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    d, pem, pin, _ = good(tmp_path)
    other = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    for args in ((other, golden.key_pin(other)), (pem, "00" * 32)):
        with pytest.raises(golden.ReleaseError):
            verify(d, *args)
    with pytest.raises(golden.ReleaseError, match="test runner"):      # attestation signed by another key than the configured runner's (e.g. the BUILDER's own)
        golden.verify_release(d, pem, pin, attestor_pubkey_b64=base64.b64encode(Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode())
    with pytest.raises(golden.ReleaseError):
        golden.verify_release(d, pem, pin, attestor_pubkey_b64="")


def test_a_self_attested_boot_test_is_refused(tmp_path):
    """the builder fabricating its own evidence: a well-formed attestation signed with a key the ICS does not trust"""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    d, pem, pin, _ = good(tmp_path, attest_key=Ed25519PrivateKey.generate())
    with pytest.raises(golden.ReleaseError, match="test runner"):
        verify(d, pem, pin)


def test_rollback_floor_rules(tmp_path):
    d, pem, pin, _ = good(tmp_path, version=5)
    sha = json.load(open(os.path.join(d, "manifest.json")))["image"]["sha256"]
    assert verify(d, pem, pin, floor=golden.Floor(5, sha)).version == 5                  # the very release already accepted
    assert verify(d, pem, pin, floor=golden.Floor(4, "00" * 32)).version == 5            # newer than the floor
    with pytest.raises(golden.ReleaseError, match="rollback floor 6"):
        verify(d, pem, pin, floor=golden.Floor(6, "00" * 32))
    with pytest.raises(golden.ReleaseError, match="different image"):
        verify(d, pem, pin, floor=golden.Floor(5, "00" * 32))                            # same version number, other bytes
    assert verify(d, pem, pin, floor=golden.Floor(6, "00" * 32), allow_downgrade=True).version == 5


# ---- the floor lives in the ICS database and only ever rises
def test_floor_in_the_database_is_monotonic_and_drives_verify_for_import(rt, owner_engine, tmp_path):
    with owner_engine.begin() as c:     # the owner role resets the shared test DB; the application role cannot delete (asserted below)
        c.execute(text("TRUNCATE image_floor"))   # owner-only reset; the row trigger refuses DELETE by design
    d, pem, pin, _ = good(tmp_path, version=5)
    keyf = tmp_path / "rel.pub"
    keyf.write_text(pem)
    rt.settings = dataclasses.replace(rt.settings, guest_golden_release_pubkey_file=str(keyf), guest_golden_release_pin_sha256=pin, guest_golden_attestor_pubkey=ATTESTOR_PUB_B64)
    r = golden.verify_for_import(rt, d)
    assert golden.get_floor(rt, "debian-12") is None and golden.advance_floor(rt, r) is True
    assert golden.get_floor(rt, "debian-12") == golden.Floor(5, r.sha256)
    assert golden.advance_floor(rt, r) is False                                           # same version: no movement
    (tmp_path / "old").mkdir()
    d2, pem2, pin2, _ = good(tmp_path / "old", version=3)
    keyf.write_text(pem2)
    rt.settings = dataclasses.replace(rt.settings, guest_golden_release_pin_sha256=pin2)
    with pytest.raises(golden.ReleaseError, match="rollback floor 5"):
        golden.verify_for_import(rt, d2)
    assert golden.verify_for_import(rt, d2, allow_downgrade=True).version == 3
    assert golden.advance_floor(rt, golden.verify_for_import(rt, d2, allow_downgrade=True)) is False and golden.get_floor(rt, "debian-12").version == 5
    with rt.session() as db:                                                              # even raw SQL cannot lower it (trigger) and the app role cannot delete
        with pytest.raises(Exception, match="version is monotonic"):
            db.execute(text("UPDATE image_floor SET version = 1 WHERE os = 'debian-12'"))
        db.rollback()
        with pytest.raises(Exception):
            db.execute(text("DELETE FROM image_floor"))
        db.rollback()


def test_import_is_refused_when_settings_are_incomplete(rt, tmp_path):
    d, *_ = good(tmp_path)
    rt.settings = dataclasses.replace(rt.settings, guest_golden_release_pubkey_file=None, guest_golden_release_pin_sha256=None, guest_golden_attestor_pubkey=None)
    with pytest.raises(golden.ReleaseError, match="not configured"):
        golden.verify_for_import(rt, d)


# ---- builder-side manifest tool agrees with the ICS verifier
def test_manifest_tool_output_verifies_in_the_ics(tmp_path):
    name = "ou-golden-debian-12-20261116.qcow2"
    out = tmp_path / "o"
    out.mkdir()
    image = b"QFI\xfb" + b"i" * 5000
    pkgs = "".join(f"pkg{i:03d}=1.{i}\n" for i in range(80)).encode()
    sbom = json.dumps({"bomFormat": "CycloneDX", "components": [{"name": f"p{i}"} for i in range(60)]}).encode()
    epoch = int(time.time()) - 3600
    (out / name).write_bytes(image)
    (out / (name + ".packages.lock")).write_bytes(pkgs)
    (out / (name + ".sbom.cdx.json")).write_bytes(sbom)
    (tmp_path / "inr").write_text("%s  x_noble_InRelease\n" % ("ab" * 32))
    recipe = tmp_path / "recipe"
    recipe.mkdir()
    (recipe / "recipe.sh").write_text("#!/bin/sh\n")
    run = lambda *a: subprocess.run([sys.executable, "-I", os.path.join(GI, "manifest.py"), *a], capture_output=True, check=True)
    (out / (name + ".provenance.json")).write_bytes(run("provenance", "--os", "debian-12", "--epoch", str(epoch), "--recipe-dir", str(recipe), "--lock", str(out / (name + ".packages.lock")),
                                                         "--inrelease", str(tmp_path / "inr"), "--commit", "abc", "--tool", "mmdebstrap=mmdebstrap 1.4.3").stdout)
    att = {"v": 2, "kind": "image-first-boot", "name": "first-boot", "sha256": hashlib.sha256(image).hexdigest(), "result": "pass", "log_sha256": "11" * 32, "at": epoch + 100, "run_id": "22" * 16}
    (out / (name + ".attestation.json")).write_text(json.dumps({"attestation": att, "sig": base64.b64encode(ATTESTOR_KEY.sign(golden.ATT_PREFIX + canon(att))).decode()}))
    p = lambda s: str(out / (name + s))
    man = run("build", "--image", str(out / name), "--sbom", p(".sbom.cdx.json"), "--packages", p(".packages.lock"), "--provenance", p(".provenance.json"),
              "--attestation", p(".attestation.json"), "--version", "20261116").stdout
    (out / "manifest.json").write_bytes(man)
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    k = ec.generate_private_key(ec.SECP256R1())
    (tmp_path / "k.pem").write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (out / "manifest.json.sig").write_bytes(run("lab-sign", "--manifest", str(out / "manifest.json"), "--key", str(tmp_path / "k.pem")).stdout)
    pem = k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    r = verify(str(out), pem, golden.key_pin(pem))
    assert r.version == 20261116 and r.name == name
    # the tool refuses an attestation that is not for this image / not passing
    bad = dict(att, sha256="00" * 32)
    (out / "bad.json").write_text(json.dumps({"attestation": bad, "sig": "x"}))
    assert subprocess.run([sys.executable, "-I", os.path.join(GI, "manifest.py"), "build", "--image", str(out / name), "--sbom", p(".sbom.cdx.json"), "--packages", p(".packages.lock"),
                           "--provenance", p(".provenance.json"), "--attestation", str(out / "bad.json"), "--version", "1"], capture_output=True).returncode != 0


# ---- the simulator used by the independent boot test speaks the REAL protocol (drift guard) and the real guest code accepts it
def test_icssim_protocol_equals_the_real_callback_and_guest_code():
    secret, nonce = os.urandom(32).hex(), os.urandom(16).hex()
    args = ("ab" * 8, nonce, 1700000000, "10.0.2.15", 8443, "cd" * 32, "ef" * 32, "t" * 43)
    assert icssim.canonical(*args) == callback.canonical(*args)
    assert icssim.proof(secret, b"m") == callback.proof(secret, b"m") and icssim.ack(secret, nonce) == callback.ack(secret, nonce)
    conf = {"b": [1, 2], "a": "x"}
    assert icssim.config_mac(secret, nonce, conf) == callback.config_mac(secret, nonce, conf) and icssim.PATH == callback.PATH
    from ou_agent import firstboot
    cfg = {"bid": "ab" * 8, "secret": secret}
    agent = {"address": "10.0.2.15", "port": 8443, "tls_fingerprint_sha256": "cd" * 32, "agent_key_fingerprint_sha256": "ef" * 32}
    rep = firstboot.build_report(cfg, agent, "t" * 43, nonce=nonce, ts=1700000000)
    assert rep["proof"] == icssim.proof(secret, icssim.canonical("ab" * 8, nonce, 1700000000, "10.0.2.15", 8443, "cd" * 32, "ef" * 32, "t" * 43))
    conf = {"v": 1, "hostname": "h", "agent_port": 8443, "mgmt_sources": ["10.0.2.2/32"], "ports": [], "agent_config": {"listen": {"address": "0.0.0.0", "port": 8443}, "runbooks": {}},
            "image_registries": [], "insecure_registries": [], "signing_pubkey_pem": None, "signing_key_sha256": None, "enroll_ttl_seconds": 3600}
    resp = {"ok": True, "ack": icssim.ack(secret, nonce), "config": conf, "config_mac": icssim.config_mac(secret, nonce, conf)}
    assert firstboot.verify_response(cfg, nonce, resp)["agent_port"] == 8443          # the real guest accepts the simulator's answer
    with pytest.raises(firstboot.Refused):
        firstboot.verify_response(cfg, nonce, dict(resp, ack=icssim.ack(os.urandom(32).hex(), nonce)))      # ... and refuses the impostor mode


def test_icssim_end_to_end_with_the_real_guest_post_pinned(tmp_path):
    """the real guest HTTP client (pin check + HMAC) against the simulator on loopback: right pin works once, wrong pin sends nothing, replay is refused"""
    from ou_agent import firstboot
    sim = icssim.Sim(str(tmp_path), icssim.free_port())
    sim.start()
    try:
        cfg = {"bid": sim.bid, "secret": sim.secret, "host": "127.0.0.1", "port": sim.port, "pin": sim.pin}
        agent = {"address": "10.0.2.15", "port": 8443, "tls_fingerprint_sha256": "cd" * 32, "agent_key_fingerprint_sha256": "ef" * 32}
        body = firstboot.build_report(cfg, agent, "t" * 43)
        resp = firstboot.post_pinned(cfg, body)
        assert firstboot.verify_response(cfg, body["nonce"], resp)["hostname"] == "ou-imgtest" and sim.valid_reports == 1
        with pytest.raises(firstboot.Refused):
            firstboot.post_pinned(cfg, firstboot.build_report(cfg, agent, "t" * 43))      # replay with the same secret: 401
        assert sim.replays == 1
        sim2 = icssim.Sim(str(tmp_path), icssim.free_port())
        sim2.start()
        try:
            c2 = dict(cfg, port=sim2.port, bid=sim2.bid, secret=sim2.secret, pin="00" * 32)
            with pytest.raises(firstboot.Refused, match="pin"):
                firstboot.post_pinned(c2, firstboot.build_report(c2, agent, "t" * 43))
            for _ in range(50):
                if sim2.handshakes >= 1:
                    break
                time.sleep(0.1)
            assert sim2.requests == 0 and sim2.handshakes >= 1
            c3 = dict(c2, pin=sim2.pin, secret=os.urandom(32).hex())                         # wrong secret: the simulator rejects the proof
            with pytest.raises(firstboot.Refused):
                firstboot.post_pinned(c3, firstboot.build_report(c3, agent, "t" * 43))
            for _ in range(50):
                if sim2.rejected >= 1:
                    break
                time.sleep(0.1)
            assert sim2.rejected == 1 and sim2.valid_reports == 0
        finally:
            sim2.stop()
    finally:
        sim.stop()


# ---- static hardening checks on synthetic trees
def build_tree(root, **over):
    def w(p, s="", mode=None):
        f = os.path.join(root, p.lstrip("/"))
        os.makedirs(os.path.dirname(f), exist_ok=True)
        open(f, "w").write(s)
    files = {
        "/var/lib/dpkg/status": "".join("Package: p%d\nStatus: install ok installed\nVersion: 1\n\n" % i for i in range(120)),
        "/etc/shadow": "root:*:20000:0:99999:7:::\nou-svc:!:20000:0:99999:7:::\ndaemon:*:20000:0:99999:7:::\n",
        "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nou-svc:x:100:100::/var/lib/ou-svc:/usr/sbin/nologin\n",
        "/etc/nftables.conf": "table inet t {\n chain input { type filter hook input priority 0; policy drop;\n ct state established,related accept\n udp sport 67 udp dport 68 accept }\n chain forward { type filter hook forward priority 0; policy drop; } }\n",
        "/etc/machine-id": "",
        "/etc/systemd/system/ou-bootstrap.service": "[Unit]\nConditionPathExists=!/var/lib/ou-bootstrap/done\nConditionPathExists=!/var/lib/ou-bootstrap/sealed\n[Service]\nExecStartPost=/usr/local/sbin/ou-seal\nRestart=no\n",
        "/usr/local/sbin/ou-seal": "#!/bin/sh\n: > x\nsystemctl disable ou-bootstrap.service\n",
        "/etc/systemd/system/multi-user.target.wants/ou-bootstrap.service": "x",
        "/etc/systemd/system/multi-user.target.wants/nftables.service": "x",
    }
    files.update(over)
    for p, s in files.items():
        if s is not None:
            w(p, s)
    os.makedirs(os.path.join(root, "etc/ou-agent"), exist_ok=True)
    os.makedirs(os.path.join(root, "var/lib/ou-agent"), exist_ok=True)
    return root


def results(root):
    return {i: ok for i, ok, _ in staticchecks.check_tree(root)}


def test_static_checks_pass_on_a_clean_tree(tmp_path):
    r = results(build_tree(str(tmp_path)))
    assert r and all(r.values()), [k for k, v in r.items() if not v]


@pytest.mark.parametrize("over,check", [
    ({"/var/lib/dpkg/status": "Package: openssh-server\nStatus: install ok installed\nVersion: 1\n\n" + "".join("Package: p%d\nStatus: install ok installed\nVersion: 1\n\n" % i for i in range(120))}, "S02"),
    ({"/usr/sbin/sshd": "x"}, "S03"),
    ({"/etc/ssh/ssh_host_ed25519_key": "k"}, "S04"),
    ({"/root/.ssh/authorized_keys": "ssh-ed25519 AAAA"}, "S05"),
    ({"/etc/shadow": "root:$6$abc$def:20000::::::\n"}, "S07"),
    ({"/etc/shadow": "root:*:1::::::\nbob::1::::::\n"}, "S08"),
    ({"/etc/passwd": "root:x:0:0::/root:/bin/sh\nevil:x:0:0::/:/bin/sh\n"}, "S09"),
    ({"/etc/pam.d/sshd": "auth sufficient pam_permit.so\n"}, "S10"),
    ({"/etc/nftables.conf": "table inet t { chain input { type filter hook input priority 0; policy accept; } }"}, "S11"),
    ({"/etc/nftables.conf": "table inet t { chain input { type filter hook input priority 0; policy drop; tcp dport 22 accept } chain forward { type filter hook forward priority 0; policy drop; } }"}, "S12"),
    ({"/etc/systemd/system/multi-user.target.wants/nftables.service": None}, "S13"),
    ({"/etc/systemd/system/multi-user.target.wants/ou-agent.service": "x"}, "S14"),
    ({"/etc/ou-agent/agent_key.pem": "k"}, "S15"),
    ({"/var/lib/ou-bootstrap/done": "1"}, "S16"),
    ({"/etc/systemd/system/ou-bootstrap.service": "[Service]\nRestart=on-failure\n"}, "S17"),
    ({"/var/lib/dpkg/status": "Package: cloud-init\nStatus: install ok installed\nVersion: 1\n\n" + "".join("Package: p%d\nStatus: install ok installed\nVersion: 1\n\n" % i for i in range(120))}, "S19"),
    ({"/var/lib/dpkg/status": "Package: qemu-guest-agent\nStatus: install ok installed\nVersion: 1\n\n" + "".join("Package: p%d\nStatus: install ok installed\nVersion: 1\n\n" % i for i in range(120))}, "S20"),
    ({"/etc/machine-id": "0123456789abcdef0123456789abcdef\n"}, "S21"),
])
def test_static_checks_catch_each_regression(tmp_path, over, check):
    r = results(build_tree(str(tmp_path), **over))
    assert [k for k, v in r.items() if not v and k.startswith(check)], r


def test_static_checks_do_not_follow_symlinks_out_of_the_image(tmp_path):
    root = build_tree(str(tmp_path / "t"))
    os.unlink(os.path.join(root, "etc/shadow"))
    host = tmp_path / "hostfile"
    host.write_text("root:*:1::::::\n")
    os.symlink(str(host), os.path.join(root, "etc/shadow"))
    assert staticchecks.read(root, "/etc/shadow") is None and not results(root)["S07-root-locked"]


def test_the_runner_program_has_the_documented_contract():
    src = open(os.path.join(TESTS, "image-boot-suite")).read()
    assert "sys.exit(0 if not failed and complete else 1)" in src and "infra(" in src and "image-first-boot" in open(os.path.join(GI, "tests", "README")).read()
    for stage in ("OFFLINE", "A", "B", "C", "D", "E"):
        assert f'"{stage}"' in src or f'st = "{stage}"' in src
    assert os.access(os.path.join(TESTS, "image-boot-suite"), os.X_OK)
