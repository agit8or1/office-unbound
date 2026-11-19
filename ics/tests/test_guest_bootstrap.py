"""Guest bootstrap (agent C): cloud-init rendering, typed runbook parameters, Quadlet generation, node-side helper with stubbed tools."""
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ics.guest import cloudinit as ci
from ics.guest.unitspec import UnitSpec

AGENT_DIR = os.path.join(os.path.dirname(__file__), "..", "agent")
sys.path.insert(0, AGENT_DIR)
from ou_agent import guesthelper as gh  # noqa: E402
from ou_agent import guestspec as gs  # noqa: E402
from ou_agent import runbooks  # noqa: E402
from ou_agent.proto import Reject  # noqa: E402

DIGEST = "sha256:" + "ab" * 32
IMG = "reg.lab:5000/ou/whoami@" + DIGEST
CFG = {"registries": ["reg.lab:5000"]}
TOKEN_HASH = hashlib.sha256(b"never-in-user-data-token").hexdigest()


_PUB = []


def _pub():
    if _PUB:
        return _PUB[0]
    _PUB.append(_pub2())
    return _PUB[0]


def _pub2():
    pem = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    der = serialization.load_pem_public_key(pem.encode()).public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return pem, hashlib.sha256(der).hexdigest()


def spec(**kw):
    bundle = ci.build_agent_bundle(AGENT_DIR)
    pem, fp = _pub()
    base = dict(hostname="gw-app1", domain="cust1.example.com", mgmt_sources=["192.168.22.167/32"], enroll_token_sha256=TOKEN_HASH,
                agent_bundle_b64=base64.b64encode(bundle).decode(), agent_bundle_sha256=hashlib.sha256(bundle).hexdigest(),
                image_registries=["reg.lab:5000"], image_signing_pubkey_pem=pem, image_signing_key_sha256=fp,
                declared_ports=[{"port": 443, "sources": ["0.0.0.0/0"]}, {"port": 8080, "sources": ["10.0.0.0/24"]}])
    base.update(kw)
    return ci.GuestSpec(**base)


# ---------------------------------------------------------------- cloud-init
def test_render_is_deterministic_and_contains_no_secret():
    a, b = ci.render(spec()), ci.render(spec())
    assert a == b and a.startswith("#cloud-config\n")
    assert TOKEN_HASH in a and "never-in-user-data-token" not in a
    for bad in ("password:", " passwd:", "chpasswd", "plain_text_passwd", "hashed_passwd"):
        assert bad not in a


def test_render_structure_ssh_disabled_by_default():
    doc = yaml.safe_load(ci.render(spec()))
    assert doc["ssh_pwauth"] is False and doc["disable_root"] is True
    assert [u["name"] for u in doc["users"]] == ["ou-svc"] and doc["users"][0]["lock_passwd"] is True
    boot = next(f for f in doc["write_files"] if f["path"] == "/usr/local/sbin/ou-guest-bootstrap")["content"]
    assert "mask ssh.socket ssh.service" in boot and "enable-linger ou-svc" in boot and "ou-svc:100000:65536" in boot
    assert "OU_ENROLL_TOKEN_SHA256=" + TOKEN_HASH in boot
    assert {"podman", "uidmap", "passt", "slirp4netns", "systemd-container"} <= set(doc["packages"]) and "openssh-server" not in doc["packages"]


def test_break_glass_key_enables_key_only_ssh():
    key = "ssh-ed25519 " + base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + b"k" * 32).decode() + " ops@x"
    doc = yaml.safe_load(ci.render(spec(break_glass_ssh_key=key)))
    adm = next(u for u in doc["users"] if u["name"] == "ou-admin")
    assert adm["ssh_authorized_keys"] == [key] and adm["lock_passwd"] is True
    boot = next(f for f in doc["write_files"] if f["path"] == "/usr/local/sbin/ou-guest-bootstrap")["content"]
    assert "PasswordAuthentication no" in boot and "AllowUsers ou-admin" in boot
    nft = next(f for f in doc["write_files"] if f["path"] == "/etc/nftables.conf")["content"]
    assert "tcp dport 22 " in nft and "192.168.22.167/32" in nft


@pytest.mark.parametrize("kw", [{"hostname": "Bad_Host"}, {"hostname": "a;b"}, {"domain": "x y"}, {"timezone": "../etc"},
                                {"break_glass_ssh_key": "command=\"id\" ssh-ed25519 AAAA"}, {"enroll_token_sha256": "plaintext"},
                                {"mgmt_sources": []}, {"mgmt_sources": ["not-a-cidr"]}, {"extra_packages": ["x; rm -rf /"]},
                                {"image_signing_key_sha256": "0" * 64}, {"image_signing_pubkey_pem": None},
                                {"pkg_allowlist": ["gromox"]}, {"agent_bundle_sha256": "1" * 64}, {"agent_port": 80}, {"bogus": 1}])
def test_spec_rejects_bad_input(kw):
    with pytest.raises(Exception):
        spec(**kw)


def test_firewall_default_deny_only_declared_ports():
    nft = ci.nftables_ruleset(spec())
    assert "policy drop" in nft and nft.count("policy drop") == 2
    assert "tcp dport 8443" in nft and "tcp dport 443 accept" in nft and "ip saddr { 10.0.0.0/24 } tcp dport 8080 accept" in nft
    assert "dport 22" not in nft and "dport 5432" not in nft
    if shutil.which("nft"):
        r = subprocess.run(["sudo", "-n", "nft", "-c", "-f", "/dev/stdin"], input=nft, text=True, capture_output=True)
        assert r.returncode == 0, r.stderr


def test_unattended_policy():
    on = yaml.safe_load(ci.render(spec()))
    assert 'Unattended-Upgrade "1"' in next(f for f in on["write_files"] if f["path"].endswith("20auto-upgrades"))["content"]
    off = yaml.safe_load(ci.render(spec(unattended="none")))
    assert 'Unattended-Upgrade "0"' in next(f for f in off["write_files"] if f["path"].endswith("20auto-upgrades"))["content"]
    uu = next(f for f in on["write_files"] if f["path"].endswith("52ou-unattended-upgrades"))["content"]
    assert 'Automatic-Reboot "false"' in uu and "-security" in uu


def test_ou_repo_pinned_and_separate_from_system_apt():
    r = ci.OU_REPO_PLACEHOLDER
    s = spec(ou_repo={**r, "key_armored": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nxx\n-----END PGP PUBLIC KEY BLOCK-----"}, pkg_allowlist=["gromox"])
    doc = yaml.safe_load(ci.render(s))
    paths = {f["path"]: f["content"] for f in doc["write_files"]}
    assert "ou-repo.asc" in paths["/etc/ou-agent/apt/sources.list"] and "/etc/apt/sources.list.d" not in " ".join(paths)
    assert "0" * 40 in paths["/etc/ou-agent/apt/pinned-fingerprints"]
    assert json.loads(paths["/etc/ou-agent/agent.src.json"])["runbooks"]["pkg.install_pinned"] == {"packages": ["gromox"]}
    with pytest.raises(Exception):
        ci.OuRepo(**{**r, "key_armored": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n-----END PGP PUBLIC KEY BLOCK-----", "url": "http://insecure.example/apt"})


def test_agent_config_rendered_by_installer_is_valid_for_the_agent():
    s = spec(ou_repo={**ci.OU_REPO_PLACEHOLDER, "key_armored": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nxx\n-----END PGP PUBLIC KEY BLOCK-----"},
             pkg_allowlist=["gromox", "gromox-web"])
    cfg = ci.agent_config(s)
    runbooks.validate_config(cfg)
    assert cfg["runbooks"]["podman.deploy_unit"] == {"registries": ["reg.lab:5000"]}


@pytest.mark.skipif(not shutil.which("cloud-init"), reason="cloud-init not installed")
def test_output_validates_with_cloud_init_schema(tmp_path):
    p = tmp_path / "user-data"
    p.write_text(ci.render(spec(break_glass_ssh_key=None, ntp_servers=["pool.ntp.org"])))
    r = subprocess.run(["cloud-init", "schema", "--config-file", str(p)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_agent_bundle_is_deterministic():
    assert ci.build_agent_bundle(AGENT_DIR) == ci.build_agent_bundle(AGENT_DIR)


# ---------------------------------------------------------------- typed params + Quadlet
GOOD = {"component": "web", "name": "whoami", "type": "container", "image": IMG, "env": {"A": "b"},
        "ports": [{"bind": "127.0.0.1", "host": 8080, "container": 80, "proto": "tcp"}],
        "volumes": [{"name": "data", "path": "/var/lib/app"}], "memory_mib": 128}


def test_ics_unitspec_params_accepted_by_agent():
    p = UnitSpec(**{**GOOD, "ports": GOOD["ports"]}).params()
    assert gs.check_deploy(p, CFG)["image"] == IMG


def test_quadlet_is_confined():
    s = gs.check_deploy(GOOD, CFG)
    files = gs.render(s)
    c = files["ou-web-whoami.container"]
    assert "Image=" + IMG in c and "NoNewPrivileges=true" in c and "DropCapability=ALL" in c and "ReadOnly=true" in c
    assert "Volume=ou-web-data.volume:/var/lib/app" in c and "Network=ou-web.network" in c and "PublishPort=127.0.0.1:8080:80/tcp" in c
    for forbidden in ("Privileged", "Network=host", "AddCapability", "Device", "/run/podman", "docker.sock", "SecurityLabelDisable", "PodmanArgs=--privileged"):
        assert forbidden not in c
    assert set(files) == {"ou-web-whoami.container", "ou-web-data.volume", "ou-web.network"}
    h = gs.render(gs.check_deploy({**GOOD, "type": "container-hostnet", "ports": []}, CFG))["ou-web-whoami.container"]
    assert "Network=host" in h


BAD = [
    ({"image": "reg.lab:5000/ou/whoami:latest"}, "bad_params"),                       # tag, no digest
    ({"image": "reg.lab:5000/ou/whoami:1.0@" + DIGEST}, "bad_params"),                # tag + digest
    ({"image": "whoami@" + DIGEST}, "bad_params"),                                    # implicit registry
    ({"image": "evil.example/ou/whoami@" + DIGEST}, "not_allowed"),                   # registry not allowlisted
    ({"image": "reg.lab:5000/ou/whoami@sha256:abc"}, "bad_params"),
    ({"privileged": True}, "bad_params"), ({"args": ["--privileged"]}, "bad_params"), ({"cmd": ["sh"]}, "bad_params"),
    ({"type": "container-privileged"}, "bad_params"),
    ({"volumes": [{"name": "d", "path": "/run/podman/podman.sock"}]}, "bad_params"),
    ({"volumes": [{"name": "d", "path": "/var/../etc"}]}, "bad_params"),
    ({"volumes": [{"name": "d", "path": "/etc"}]}, "bad_params"),
    ({"volumes": [{"name": "d", "path": "/data", "host": "/"}]}, "bad_params"),       # host path field does not exist
    ({"volumes": [{"name": "/etc", "path": "/data"}]}, "bad_params"),                 # volume name is not a path
    ({"env": {"lower": "x"}}, "bad_params"), ({"env": {"A": "x\nExec=/bin/sh"}}, "bad_params"), ({"env": {"A": "$(id)"}}, "bad_params"),
    ({"env": {"A": "a b"}}, "bad_params"), ({"ports": [{"bind": "0.0.0.0", "host": 80, "container": 80, "proto": "tcp"}]}, "bad_params"),
    ({"type": "container-hostnet", "ports": GOOD["ports"]}, "bad_params"),
    ({"component": "Web"}, "bad_params"), ({"name": "a;b"}, "bad_params"), ({"memory_mib": 1}, "bad_params"), ({"read_only": "yes"}, "bad_params"),
    ({"user": "root"}, "bad_params"),
    ({"capabilities": ["SYS_ADMIN"]}, "bad_params"), ({"capabilities": ["ALL"]}, "bad_params"), ({"capabilities": "SYS_CHROOT"}, "bad_params"),
    ({"capabilities": ["SYS_CHROOT", "SYS_CHROOT"]}, "bad_params"), ({"capabilities": ["sys_chroot"]}, "bad_params"),
]


@pytest.mark.parametrize("patch,code", BAD)
def test_deploy_params_refused(patch, code):
    with pytest.raises(Reject) as e:
        gs.check_deploy({**GOOD, **patch}, CFG)
    assert e.value.code == code


def test_ics_unitspec_refuses_unknown_fields():
    with pytest.raises(Exception):
        UnitSpec(**{**GOOD, "privileged": True})


def test_pkg_params_exact_versions_and_allowlist():
    cfg = {"packages": ["gromox"]}
    assert gs.check_pkg({"packages": [{"name": "gromox", "version": "3.13-1"}]}, cfg)["packages"][0]["version"] == "3.13-1"
    for bad in ({"name": "gromox", "version": "*"}, {"name": "gromox", "version": ">=3"}, {"name": "gromox", "version": "3.13; id"},
                {"name": "gromox", "version": ""}, {"name": "gromox", "version": "3", "extra": 1}):
        with pytest.raises(Reject):
            gs.check_pkg({"packages": [bad]}, cfg)
    with pytest.raises(Reject) as e:
        gs.check_pkg({"packages": [{"name": "openssh-server", "version": "1.0"}]}, cfg)
    assert e.value.code == "not_allowed"


# ---------------------------------------------------------------- agent integration (allowlist / polkit)
def test_agent_allowlist_applies_to_guest_runbooks():
    cfg = {"runbooks": {"podman.deploy_unit": CFG, "guest.facts": {"enabled": True}}}
    runbooks.validate_config(cfg)
    assert runbooks.check_allowed(cfg, "guest.facts", {}) == {}
    with pytest.raises(Reject) as e:
        runbooks.check_allowed(cfg, "podman.pull_verified", {"image": IMG})      # runbook not enabled on this node
    assert e.value.code == "not_allowed"
    with pytest.raises(Reject):
        runbooks.check_allowed(cfg, "guest.facts", {"x": 1})
    with pytest.raises(ValueError):
        runbooks.validate_config({"runbooks": {"podman.deploy_unit": {"enabled": True}}})
    assert runbooks.capabilities(cfg)["podman.deploy_unit"] == CFG


def test_polkit_rule_allows_only_template_starts():
    d = os.path.join(AGENT_DIR, "deploy")
    cfgp = os.path.join(os.environ.get("TMPDIR", "/tmp"), "ou-polkit-test.json")
    json.dump({"runbooks": {"podman.status": {"enabled": True}, "pkg.install_pinned": {"packages": ["x"]}}}, open(cfgp, "w"))
    try:
        out = subprocess.run([sys.executable, os.path.join(d, "render_polkit.py"), cfgp], capture_output=True, text=True, check=True).stdout
    finally:
        os.unlink(cfgp)
    assert 'var tmpl = ["ou-rb-pkg", "ou-rb-podman"]' in out and "polkit.Result.NO" in out


def test_image_policy_default_reject_with_pinned_key():
    sys.path.insert(0, os.path.join(AGENT_DIR, "deploy"))
    import render_image_policy as rp
    p = rp.policy({"reg.lab:5000"}, "/etc/ou-agent/image-signing.pub")
    assert p["default"] == [{"type": "reject"}]
    req = p["transports"]["docker"]["reg.lab:5000"][0]
    assert req["type"] == "sigstoreSigned" and req["keyPath"] == "/etc/ou-agent/image-signing.pub" and set(p["transports"]) == {"docker"}
    assert "use-sigstore-attachments: true" in rp.registries_d({"reg.lab:5000"})


# ---------------------------------------------------------------- node helper with stubbed podman / systemctl
@pytest.fixture()
def node(tmp_path, monkeypatch):
    log = tmp_path / "calls.log"
    stub = tmp_path / "stub"
    stub.write_text(f'#!/bin/sh\necho "$0 $*" >> {log}\ncase "$*" in *"image exists"*) exit 0;; *"--format {{{{.Digest}}}}"*) echo {DIGEST};; '
                    f'*show*) echo ActiveState=active; echo SubState=running;; esac\nexit 0\n')
    stub.chmod(0o755)
    monkeypatch.setattr(gh, "PODMAN", str(stub))
    monkeypatch.setattr(gh, "SYSTEMCTL", str(stub))
    monkeypatch.setattr(gs, "SERVICE_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(gh, "quadlet_available", lambda: True)   # (the plain-unit fallback has its own tests below)
    return tmp_path, log


FULL = {"runbooks": {"podman.pull_verified": CFG, "podman.deploy_unit": CFG, "podman.remove_unit": {"enabled": True}, "podman.status": {"enabled": True},
                     "guest.facts": {"enabled": True}}}


def test_deploy_refuses_image_not_pulled_by_verified_runbook(node):
    with pytest.raises(Reject) as e:
        gh.deploy_unit(GOOD, FULL)
    assert e.value.code == "image_not_verified"


def test_pull_deploy_status_remove_cycle(node):
    tmp, log = node
    assert gh.pull_verified({"image": IMG}, FULL)["verified"] is True
    assert "--signature-policy /etc/ou-agent/image-policy.json " + IMG in log.read_text()
    r = gh.deploy_unit(GOOD, FULL)
    assert r["started"] is True and r["unit"] == "ou-web-whoami"
    cdir = tmp / "home/.config/containers/systemd"
    assert sorted(os.listdir(cdir)) == ["ou-web-data.volume", "ou-web-whoami.container", "ou-web.network"]
    assert gh.deploy_unit(GOOD, FULL)["changed"] is False                      # idempotent
    st = gh.status({}, FULL)["units"]
    assert st[0]["unit"] == "ou-web-whoami" and st[0]["active_state"] == "active"
    rm = gh.remove_unit({"component": "web", "name": "whoami", "purge_volumes": True}, FULL)
    assert rm["removed"] is True and rm["purged_volumes"] == ["ou-web-data"] and os.listdir(cdir) == []
    assert gh.remove_unit({"component": "web", "name": "whoami", "purge_volumes": False}, FULL)["removed"] is False


def test_pull_failure_is_reported_not_verified(node, tmp_path):
    tmp, log = node
    stub = tmp / "failstub"
    stub.write_text("#!/bin/sh\necho 'Source image rejected: signature verification failed' >&2\nexit 125\n")
    stub.chmod(0o755)
    gh.PODMAN = str(stub)
    r = gh.pull_verified({"image": IMG}, FULL)
    assert r["verified"] is False and "rejected" in r["error"]
    assert not os.path.exists(os.path.join(gs.SERVICE_HOME, ".local/share/ou-agent/verified"))


def test_helper_main_revalidates_spool_and_writes_result(node, monkeypatch, tmp_path):
    spool, res = tmp_path / "spool", tmp_path / "run"
    spool.mkdir()
    cfgf = tmp_path / "agent.json"
    cfgf.write_text(json.dumps(FULL))
    monkeypatch.setattr(gh, "SPOOL_DIR", str(spool))
    monkeypatch.setattr(gh, "RESULT_ROOT", str(res))
    monkeypatch.setattr(gh, "CONFIG", str(cfgf))
    rid = "r" + "0" * 16
    (spool / (rid + ".json")).write_text(json.dumps({"action": "podman.deploy_unit", "params": {**GOOD, "privileged": True}}))
    assert gh.main(["podman", rid]) == 0
    out = json.load(open(res / "ou-rb-podman" / (rid + ".json")))
    assert out["rejected"]["code"] == "bad_params"                              # a tampered spool is refused by the helper itself
    (spool / (rid + ".json")).write_text(json.dumps({"action": "pkg.install_pinned", "params": {}}))
    gh.main(["podman", rid])
    assert json.load(open(res / "ou-rb-podman" / (rid + ".json")))["rejected"]["code"] == "not_allowed"   # wrong family
    assert gh.main(["podman", "../etc/passwd"]) == 2


def test_only_sys_chroot_can_be_given_back_and_only_explicitly():
    # real VM e2e-fo6: with DropCapability=ALL the document engine's per-document chroot fails (EPERM), no document process starts and coolwsd
    # never answers HTTP; the lab run with --cap-drop=ALL --cap-add=SYS_CHROOT --security-opt=no-new-privileges answered discovery (2026-11-19)
    assert gs.UNIT_CAPS == ("SYS_CHROOT",)
    plain = gs.check_deploy(GOOD, CFG)
    assert "capabilities" not in plain and gs.spec_hash(plain) == gs.spec_hash(gs.check_deploy({**GOOD, "capabilities": []}, CFG))
    s = gs.check_deploy({**GOOD, "capabilities": ["SYS_CHROOT"]}, CFG)
    c = gs.render(s)["ou-web-whoami.container"]
    assert "DropCapability=ALL" in c and "NoNewPrivileges=true" in c and c.count("AddCapability=") == 1 and "AddCapability=SYS_CHROOT" in c
    t = gs.render_service(s)["ou-web-whoami.service"]
    assert "--cap-drop=ALL --security-opt=no-new-privileges" in t and t.count("--cap-add=") == 1 and "--cap-add=SYS_CHROOT" in t
    assert "--cap-add" not in gs.render_service(plain)["ou-web-whoami.service"]


def test_facts_shape(node):
    f = gh.facts({}, FULL)
    assert f["cpus"] >= 1 and f["mem_total_bytes"] > 0 and "/" in f["disks"] and f["os"]["id"] and f["units"] == []


# ---------------------------------------------------------------- real-VM lessons (Debian 12: podman 4.3.1, no Quadlet, no sigstore)
def test_plain_unit_rendering_is_confined_and_has_no_user_defined_network():
    spec = gs.CHECKS["podman.deploy_unit"](GOOD, CFG)
    files = gs.render_service(spec)
    assert list(files) == ["ou-web-whoami.service"]
    t = files["ou-web-whoami.service"]
    assert "ExecStart=/usr/bin/podman --cgroup-manager=cgroupfs run --rm --name ou-web-whoami --cap-drop=ALL --security-opt=no-new-privileges --read-only=true" in t
    assert "--network=ou-web" not in t and "network create" not in t          # `podman run --network=<user-defined>` fails on podman 4.3.1 (real VM)
    assert "--privileged" not in t and "--volume=ou-web-data:" in t and "volume create --label ou.component=web ou-web-data" in t
    assert t.count("\n[Service]") == 1 and "\n" + "Environment=" not in t


def test_deploy_without_quadlet_uses_a_plain_user_unit_and_enables_it(node, monkeypatch):
    tmp, log = node
    monkeypatch.setattr(gh, "quadlet_available", lambda: False)
    assert gh.pull_verified({"image": IMG}, FULL)["verified"] is True
    assert gh.deploy_unit(GOOD, FULL)["started"] is True
    udir = tmp / "home/.config/systemd/user"
    assert os.listdir(udir) == ["ou-web-whoami.service"] and not (tmp / "home/.config/containers/systemd").exists()
    assert "--user --no-ask-password enable ou-web-whoami.service" in log.read_text()
    rm = gh.remove_unit({"component": "web", "name": "whoami", "purge_volumes": True}, FULL)
    assert rm["removed"] is True and os.listdir(udir) == []


def _registry(tmp_path, key, digest_ok=True, repo="ou/echo", reg="127.0.0.1:0"):
    """Tiny in-process OCI registry serving a manifest and its cosign-style signature (the layout of scripts/lab_registry.py)."""
    import base64, hashlib, http.server, threading
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    blobs = {}
    man = json.dumps({"schemaVersion": 2, "layers": []}).encode()
    md = "sha256:" + hashlib.sha256(man).hexdigest()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), type("H", (http.server.BaseHTTPRequestHandler,), {
        "log_message": lambda *a: None, "do_GET": lambda self: self._go()}))
    host = f"127.0.0.1:{srv.server_address[1]}"
    payload = json.dumps({"critical": {"identity": {"docker-reference": f"{host}/{repo}"}, "image": {"docker-manifest-digest": md},
                                       "type": "cosign container image signature"}, "optional": None}, sort_keys=True).encode()
    sig = base64.b64encode(key.sign(payload, ec.ECDSA(hashes.SHA256()))).decode()
    pd = "sha256:" + hashlib.sha256(payload).hexdigest()
    sigman = json.dumps({"schemaVersion": 2, "layers": [{"mediaType": "application/vnd.dev.cosign.simplesigning.v1+json", "digest": pd,
                                                          "size": len(payload), "annotations": {"dev.cosignproject.cosign/signature": sig}}]}).encode()
    routes = {f"/v2/{repo}/manifests/{md}": man if digest_ok else b"tampered", f"/v2/{repo}/manifests/sha256-{md[7:]}.sig": sigman,
              f"/v2/{repo}/blobs/{pd}": payload}

    def go(self):
        body = routes.get(self.path)
        self.send_response(200 if body is not None else 404)
        self.end_headers()
        self.wfile.write(body or b"")
    srv.RequestHandlerClass._go = go
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, host, md


def test_python_sigstore_verification_matches_the_policy_rules():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    other = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    srv, host, md = _registry(None, key)
    try:
        assert gh.verify_sigstore_attachment(host, "ou/echo", md, pem, [host]) == (True, "signature verified")
        ok, why = gh.verify_sigstore_attachment(host, "ou/echo", md, other, [host])           # signed by a different key
        assert not ok and "no valid signature" in why
        assert not gh.verify_sigstore_attachment(host, "ou/echo", "sha256:" + "1" * 64, pem, [host])[0]    # a digest nobody signed
        assert not gh.verify_sigstore_attachment(host, "ou/other", md, pem, [host])[0]       # signature of another repository
        assert not gh.verify_sigstore_attachment(host, "ou/echo", md, pem, [])[0]            # plain HTTP only for operator-listed registries
    finally:
        srv.shutdown()
    srv, host, md = _registry(None, key, digest_ok=False)                                     # registry serves other bytes under the digest
    try:
        ok, why = gh.verify_sigstore_attachment(host, "ou/echo", md, pem, [host])
        assert not ok and "does not hash" in why
    finally:
        srv.shutdown()


def test_pull_falls_back_to_python_verification_when_podman_has_no_sigstore(node, monkeypatch):
    tmp, log = node
    calls = []

    def fake_run(argv, env=None, timeout=120):
        calls.append(argv)
        if "image" in argv and "inspect" in argv:
            return type("R", (), {"returncode": 0, "stdout": DIGEST, "stderr": ""})()
        if "image-policy.json" in " ".join(argv):
            return type("R", (), {"returncode": 125, "stdout": "", "stderr": "Error: Source image rejected: Debian-local change: sigstore disabled"})()
        return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
    monkeypatch.setattr(gh, "run", fake_run)
    monkeypatch.setattr(gh, "verify_sigstore_attachment", lambda *a: (True, "ok"))
    pk = tmp / "pub"
    pk.write_text("x")
    monkeypatch.setattr(gs, "PUBKEY_FILE", str(pk))
    r = gh.pull_verified({"image": IMG}, FULL)
    assert r["verified"] is True and r["policy"] == "python-sigstore"
    assert any(gs.PULLONLY_POLICY_FILE in " ".join(a) for a in calls)                          # the second pull uses the pull-only policy
    monkeypatch.setattr(gh, "verify_sigstore_attachment", lambda *a: (False, "no valid signature"))
    calls.clear()
    r = gh.pull_verified({"image": IMG}, FULL)
    assert r["verified"] is False and not any(gs.PULLONLY_POLICY_FILE in " ".join(a) for a in calls)   # unsigned image: never pulled


def test_a_failed_start_reports_the_units_redacted_log(node, monkeypatch):
    # first real VM (e2e-id3, 2026-11-19): the step said only "control process exited with error code"; the cause was on the node
    tmp, log = node
    assert gh.pull_verified({"image": IMG}, FULL)["verified"] is True
    secret = "Zq3_" + "x" * 40
    seen = []
    real = gh.run

    def run(argv, env=None, timeout=120):
        if argv[0] == gh.JOURNALCTL:
            seen.append(argv)
            return subprocess.CompletedProcess(argv, 0, f"ERROR: Failed to start server\nFATAL: password authentication failed (pw {secret})\n\x1b[0mdone\n", "")
        if "show" in argv:
            return subprocess.CompletedProcess(argv, 0, "ActiveState=failed\nSubState=failed\n", "")
        return real(argv, env=env, timeout=timeout)
    monkeypatch.setattr(gh, "run", run)
    r = gh.deploy_unit(GOOD, FULL)
    assert r["started"] is False and seen[0][1:4] == ["--user", "-u", "ou-web-whoami.service"]
    assert "password authentication failed" in r["log"] and secret not in r["log"] and "***" in r["log"] and "\x1b" not in r["log"]
    monkeypatch.setattr(gh, "run", lambda argv, env=None, timeout=120: subprocess.CompletedProcess(argv, 0, "ActiveState=active\n", ""))
    assert "log" not in gh.deploy_unit(GOOD, FULL)


def test_an_apt_timeout_reports_apts_own_output(node, monkeypatch):
    # real VM e2e-fo2 (2026-11-19): `apt update` stalled 300 s and the step said only "pkg.install_pinned failed: TimeoutExpired"
    def stalled(argv, env=None, timeout=120):
        raise subprocess.TimeoutExpired(argv, timeout, output=b"Hit:1 http://security.ubuntu.com/ubuntu noble-security InRelease\r0% [Connecting to archive.ubuntu.com (2001:db8::1)]\x1b")
    monkeypatch.setattr(gh, "run", stalled)
    msg = gh._apt_run(["apt-get", "update"], {}, 300, "apt update")
    assert msg.startswith("apt update timed out after 300 s; last output: ")
    assert "Hit:1 http://security.ubuntu.com/ubuntu noble-security InRelease | 0% [Connecting to archive.ubuntu.com (2001:db8::1)]?" in msg
    monkeypatch.setattr(gh, "run", lambda argv, env=None, timeout=120: (_ for _ in ()).throw(subprocess.TimeoutExpired(argv, timeout)))
    assert gh._apt_run(["apt-get", "update"], {}, 300, "apt update").endswith("last output: (none)")


def test_package_match_is_exact_or_floor():
    cfg = {"packages": ["nginx"]}
    assert gs.check_pkg({"packages": [{"name": "nginx", "version": "1.24.0-2ubuntu7.19"}]}, cfg)["packages"][0]["match"] == "exact"
    assert gs.check_pkg({"packages": [{"name": "nginx", "version": "1.24.0-2ubuntu7.19", "match": "floor"}]}, cfg)["packages"][0]["match"] == "floor"
    for bad in ({"name": "nginx", "version": "1.24.0", "match": "latest"}, {"name": "nginx", "version": "1.24.0", "match": "floor", "x": 1}):
        with pytest.raises(Reject):
            gs.check_pkg({"packages": [bad]}, cfg)


# `apt-cache policy nginx` as a guest saw it on 2026-11-19 after the 7.20 security update (7.19 still in noble-updates), plus our repository line
POLICY = """nginx:
  Installed: (none)
  Candidate: 1.24.0-2ubuntu7.20
  Version table:
     1.24.0-2ubuntu7.20 500
        500 http://security.ubuntu.com/ubuntu noble-security/main amd64 Packages
     1.24.0-2ubuntu7.19 500
        500 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages
     1.24.0-2ubuntu7 500
        500 http://archive.ubuntu.com/ubuntu noble/main amd64 Packages
"""


def _policy_stub(monkeypatch, tmp_path, policy, cmp_rc=0):
    apt = tmp_path / "apt"
    apt.mkdir(exist_ok=True)
    (apt / "sources.list").write_text("deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] http://archive.ubuntu.com/ubuntu noble main\n"
                                      f"deb [{gh.OU_KEYRING}] https://artifacts.ou.test:8446/apt dev main\n")
    monkeypatch.setattr(gh, "APT_DIR", str(apt))
    calls = []

    def run(argv, env=None, timeout=120):
        calls.append(argv)
        out = policy if argv[0] == gh.APT_CACHE else ""
        return subprocess.CompletedProcess(argv, cmp_rc if argv[0] == gh.DPKG else 0, out, "")
    monkeypatch.setattr(gh, "run", run)
    return calls


def test_floor_installs_the_archives_current_security_update(monkeypatch, tmp_path):
    calls = _policy_stub(monkeypatch, tmp_path, POLICY)
    assert gh._floor_candidate("nginx", "1.24.0-2ubuntu7.19", {}) == "=1.24.0-2ubuntu7.20"
    assert calls[-1] == [gh.DPKG, "--compare-versions", "1.24.0-2ubuntu7.20", "ge", "1.24.0-2ubuntu7.19"]


def test_floor_refuses_older_absent_or_own_repository_versions(monkeypatch, tmp_path):
    _policy_stub(monkeypatch, tmp_path, POLICY, cmp_rc=1)
    assert "older than the catalog floor" in gh._floor_candidate("nginx", "1.26.0-1", {})
    _policy_stub(monkeypatch, tmp_path, "nginx:\n  Installed: (none)\n  Candidate: (none)\n  Version table:\n")
    assert "no installable version" in gh._floor_candidate("nginx", "1.24.0", {})
    own = "ou-x:\n  Candidate: 2.0-ou1\n  Version table:\n     2.0-ou1 500\n        500 https://artifacts.ou.test:8446/apt dev/main amd64 Packages\n"
    _policy_stub(monkeypatch, tmp_path, own)
    assert "must come from a distribution archive" in gh._floor_candidate("ou-x", "1.0-ou1", {})
