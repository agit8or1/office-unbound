"""Artifact distribution (ADR-0015): operator configuration + pins, plan injection, server config rendering, guest bootstrap metadata (per-channel
apt keys, CA scoped to the artifact hosts, per-repository signed identity), first-boot validation/apply, and the publisher's verification rules.
Pure tests (no DB, no network); the live proof is docs/status/artifact-dist-results.md."""
import base64
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ics import artifacts as art
from ics.deploy.catalog import load_catalog
from ics.deploy.plan import generate_plan
from ics.guest import cloudinit as ci

sys.path.insert(0, os.path.dirname(__file__))
from test_deploy_plan import DIGEST, cap, codes, inp, pinned

ROOT = Path(__file__).resolve().parents[2]
KEYS = ROOT / "blueprints" / "build" / "keys"
AGENT_DIR = str(ROOT / "ics" / "agent")
sys.path.insert(0, AGENT_DIR)
from ou_agent import firstboot  # noqa: E402

LAB_KEY = (KEYS / "ou-release-lab.pub.asc").read_text()
LAB_FPR = (KEYS / "ou-release-lab.FINGERPRINT").read_text().split()[0].upper()


def _real_ca():
    """A real self-signed CA certificate for the pin checks (generated, not a fixture file)."""
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.x509.oid import NameOID
    k = ec.generate_private_key(ec.SECP256R1())
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test CA")])
    now = datetime.now(timezone.utc)
    c = x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key()).serial_number(1).not_valid_before(now) \
        .not_valid_after(now + timedelta(days=30)).sign(k, hashes.SHA256())
    return c.public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture()
def ca(tmp_path):
    pem = _real_ca()
    f = tmp_path / "ca.crt"
    f.write_text(pem)
    return f, art.ca_sha256(pem)


def env(tmp_path, ca, **kw):
    d = tmp_path / "keys"
    d.mkdir(exist_ok=True)
    (d / "ou-release-stable.pub.asc").write_text(LAB_KEY)
    e = {"OU_ARTIFACT_BASE": "10.64.255.2:8444", "OU_ARTIFACT_CA_FILE": str(ca[0]), "OU_ARTIFACT_CA_SHA256": ca[1], "OU_ARTIFACT_KEYS_DIR": str(d),
         "OU_ARTIFACT_CHANNEL_FPRS": f"stable={LAB_FPR}"}
    e.update(kw)
    return e


# ------------------------------------------------------------------------------------------------ configuration and pins
def test_pgp_fingerprint_matches_the_recorded_release_key_fingerprint():
    assert art.pgp_fingerprint(LAB_KEY) == LAB_FPR
    with pytest.raises(art.ArtifactError):
        art.pgp_fingerprint("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----")


def test_unset_is_none_and_broken_config_raises(tmp_path, ca):
    assert art.load_map({}) is None
    m = art.load_map(env(tmp_path, ca))
    assert m.apt_url == "https://10.64.255.2:8444/apt" and m.registry_host == "10.64.255.2:8444" and m.key("stable")[1] == LAB_FPR and m.key("dev") is None
    for bad in ({"OU_ARTIFACT_BASE": "registry.ou.invalid"}, {"OU_ARTIFACT_BASE": "Bad Host"}, {"OU_ARTIFACT_BASE": "x:99999999"},
                {"OU_ARTIFACT_CA_SHA256": "0" * 64}, {"OU_ARTIFACT_CA_FILE": ""}, {"OU_ARTIFACT_CHANNEL_FPRS": "stable=" + "A" * 40},
                {"OU_ARTIFACT_CHANNEL_FPRS": "nightly=" + LAB_FPR}, {"OU_ARTIFACT_SIGNED_REGISTRY": "no good"}):
        with pytest.raises(art.ArtifactError):
            art.load_map(env(tmp_path, ca, **bad))


def test_apt_and_registry_hosts_can_differ(tmp_path, ca):
    m = art.load_map(env(tmp_path, ca, OU_ARTIFACT_APT_HOST="apt.ou.example:8444", OU_ARTIFACT_REGISTRY_HOST="reg.ou.example:8444"))
    assert m.apt_url == "https://apt.ou.example:8444/apt" and m.registry_host == "reg.ou.example:8444"


# ------------------------------------------------------------------------------------------------ plan injection
def test_catalog_images_point_at_the_configured_registry_and_the_catalog_is_untouched(tmp_path, ca):
    m = art.load_map(env(tmp_path, ca))
    cat = pinned()
    new = art.rewrite_catalog(cat, m)
    img = [a.image for a in new.components["office"].artifacts if a.kind == "oci"]
    assert img == ["10.64.255.2:8444/ou/office"]
    assert [a.image for a in cat.components["office"].artifacts if a.kind == "oci"] == ["registry.ou.invalid/ou/office"]   # reviewed source unchanged
    assert new.digest == cat.digest
    assert art.rewrite_catalog(cat, None) is cat


def test_plan_carries_the_artifact_section_in_its_hash_and_warns_when_unset(tmp_path, ca):
    m = art.load_map(env(tmp_path, ca))
    cat = pinned()
    p_unset = generate_plan(inp(), cap(), cat)
    assert "artifact_base_unset" in codes(p_unset["warnings"]) and "artifacts" not in p_unset
    p = generate_plan(inp(), cap(), art.rewrite_catalog(cat, m), artifacts=m)
    assert "artifact_base_unset" not in codes(p["warnings"])
    assert p["artifacts"]["registry"] == "10.64.255.2:8444" and p["artifacts"]["channels"] == {"stable": LAB_FPR}
    assert not any(c["image"].startswith("registry.ou.invalid") for c in p["containers"]) and any(c["image"].startswith("10.64.255.2:8444/") for c in p["containers"])
    pulls = [rb["params"]["image"] for s in p["steps"] if s["kind"] == "agent_runbook" for rb in s["params"]["runbooks"] if rb["runbook"] == "podman.pull_verified"]
    assert pulls and not any(x.startswith("registry.ou.invalid") for x in pulls) and any(x.startswith("10.64.255.2:8444/") for x in pulls)
    other = art.load_map(env(tmp_path, ca, OU_ARTIFACT_BASE="10.64.255.3:8444"))
    assert generate_plan(inp(), cap(), art.rewrite_catalog(cat, other), artifacts=other)["plan_hash"] != p["plan_hash"]


def test_channels_needed_maps_catalog_repos_to_suites():
    plan = {"services": [{"vm": "a", "repo": "ob-apt-stable"}, {"vm": "a", "repo": "ubuntu-noble"}, {"vm": "b", "repo": "ob-apt-dev"}]}
    assert art.channels_needed(plan) == ["dev", "stable"] and art.channels_needed(plan, "a") == ["stable"] and art.channels_needed(plan, "c") == []


# ------------------------------------------------------------------------------------------------ server rendering
def srv(**kw):
    d = dict(listen_ip="192.168.22.167", server_names=("artifacts.ou.example",))
    d.update(kw)
    return art.ServerConfig(**d)


def test_nginx_is_read_only_rate_limited_and_lists_nothing():
    t = art.render_nginx(srv())
    assert "listen 192.168.22.167:8446 ssl;" in t and "if ($request_method !~ ^(GET|HEAD)$) { return 405; }" in t
    assert "autoindex off;" in t and "autoindex on" not in t
    assert "location = /v2/_catalog { return 403; }" in t and "tags/list$ { return 403; }" in t
    assert "limit_req zone=ou_art_req" in t and "limit_conn ou_art_conn" in t and "ou-artifacts.access.log" in t
    assert "allow 10.64.0.0/16;" in t and "deny all;" in t and "allow 192.168.22.167;" in t
    assert "proxy_pass http://127.0.0.1:5001;" in t and "push.sock" not in t and "unix:" not in t and "client_max_body_size 1k;" in t
    assert "TLSv1.2 TLSv1.3" in t and "ssl_certificate " in t
    assert "location = /healthz { alias /var/lib/office-unbound/artifacts/healthz;" in t and "{ return 200" not in t   # return would bypass allow/deny (rewrite phase)


@pytest.mark.parametrize("bad", [dict(allow_cidrs=("0.0.0.0/0",)), dict(allow_cidrs=("8.0.0.0/7",)), dict(allow_cidrs=()), dict(listen_ip="0.0.0.0"),
                                 dict(listen_ip="::1"), dict(port=80), dict(server_names=("a b",)), dict(cert="/etc/x;y"), dict(data_dir="relative")])
def test_server_config_fails_closed(bad):
    with pytest.raises((art.ArtifactError, ValueError)):
        srv(**bad)


def test_registry_configs_reader_is_readonly_and_push_has_no_network_listener():
    ro, push = art.render_registry(srv(), "ro"), art.render_registry(srv(), "push")
    assert "readonly:\n      enabled: true" in ro and "addr: 127.0.0.1:5001" in ro and "unix" not in ro
    assert "net: unix" in push and "/run/ou-artifacts/push.sock" in push and "readonly" not in push and "127.0.0.1" not in push
    for t in (ro, push):
        assert "delete:\n    enabled: false" in t
    nft = art.render_nft(srv())
    assert "tcp dport 8446 ip saddr { 127.0.0.1, 192.168.22.167, 10.64.0.0/16 } accept" in nft and "tcp dport 8446 drop" in nft


def test_render_server_cli_writes_all_files(tmp_path):
    cfg = tmp_path / "server.json"
    cfg.write_text(json.dumps({"listen_ip": "192.168.22.167", "port": 8444, "server_names": [], "allow_cidrs": ["10.64.0.0/16"], "data_dir": "/var/lib/office-unbound/artifacts",
                               "channel_fprs": {"dev": "A" * 40}, "push_socket": "/run/ou-artifacts/push.sock"}))
    assert art.main(["render-server", str(cfg), str(tmp_path / "out")]) == 0
    assert sorted(p.name for p in (tmp_path / "out").rglob("*") if p.is_file()) == ["ou-artifacts-fw.nft", "ou-artifacts.conf", "registry-push.yml", "registry-ro.yml"]


def test_probe_never_raises_and_reports_unreachable(tmp_path, ca):
    m = art.load_map(env(tmp_path, ca, OU_ARTIFACT_BASE="127.0.0.1:9"))
    r = art.probe(m, ("stable",))
    assert r["ok"] is False and all(not c["ok"] for c in r["checks"].values())


# ------------------------------------------------------------------------------------------------ guest bootstrap metadata
def _pub():
    k = ec.generate_private_key(ec.SECP256R1()).public_key()
    pem = k.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    der = k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return pem, hashlib.sha256(der).hexdigest()


def guest(tmp_path, ca, **kw):
    m = art.load_map(env(tmp_path, ca, OU_ARTIFACT_CHANNEL_FPRS=f"stable={LAB_FPR}", **kw.pop("env", {})))
    pem, fp = _pub()
    raw = b"golden-image"
    k = m.key("stable")
    base = dict(hostname="gw-app1", os="ubuntu-24.04", mgmt_sources=["192.168.22.167/32"], image_registries=[m.registry_host], image_signing_pubkey_pem=pem,
                image_signing_key_sha256=fp, ou_repos=[{"url": m.apt_url, "suite": "stable", "components": ["main"], "key_armored": k[0], "key_fingerprint": k[1]}],
                pkg_allowlist=["ou-gromox"], artifact_ca_pem=m.ca_pem, artifact_ca_sha256=m.ca_sha256, artifact_tls_hosts=sorted({m.apt_host, m.registry_host}),
                enroll_token_sha256="0" * 64, agent_bundle_b64=base64.b64encode(raw).decode(), agent_bundle_sha256=hashlib.sha256(raw).hexdigest())
    base.update(kw)
    return ci.GuestSpec(**base)


def test_cloud_init_files_per_channel_keys_and_scoped_ca(tmp_path, ca):
    s = guest(tmp_path, ca)
    files = {f["path"]: f["content"] for f in ci.build(s)["write_files"]}
    src = files["/etc/ou-agent/apt/sources.list"]
    assert f"deb [signed-by=/etc/ou-agent/apt/keyrings/ou-stable.asc] https://10.64.255.2:8444/apt stable main" in src
    assert "ou-repo.asc" not in src and "/etc/ou-agent/apt/keyrings/ou-stable.asc" in files
    assert LAB_FPR in files["/etc/ou-agent/apt/pinned-fingerprints"]
    assert files["/etc/ou-agent/apt/apt-extra.conf"].count("CaInfo") == 1 and 'Acquire::https::10.64.255.2::CaInfo "/etc/ou-agent/artifact-ca.crt";' in files["/etc/ou-agent/apt/apt-extra.conf"]
    assert files["/etc/containers/certs.d/10.64.255.2:8444/ca.crt"] == files["/etc/ou-agent/artifact-ca.crt"]
    assert "/usr/local/share/ca-certificates" not in "".join(files)      # never added to the system trust store


def test_spec_validation_pins_and_exclusions(tmp_path, ca):
    s = guest(tmp_path, ca)
    with pytest.raises(ValueError):
        guest(tmp_path, ca, artifact_ca_sha256="0" * 64)                       # CA does not match its pin
    with pytest.raises(ValueError):
        guest(tmp_path, ca, artifact_tls_hosts=[])                              # CA without hosts
    with pytest.raises(ValueError):
        guest(tmp_path, ca, ou_repo=s.ou_repos[0].model_dump())                 # single and multi form are exclusive
    with pytest.raises(ValueError):
        guest(tmp_path, ca, ou_repos=[s.ou_repos[0].model_dump()] * 2)          # one line per channel
    with pytest.raises(ValueError):
        guest(tmp_path, ca, signed_registry="signer.lab:5000")                   # signed_registry needs the repository list
    with pytest.raises(ValueError):
        guest(tmp_path, ca, image_repos=["ou/x"])
    with pytest.raises(ValueError):
        guest(tmp_path, ca, pkg_allowlist=["x"], ou_repos=[])


def test_identity_file_pins_every_allowed_repository(tmp_path, ca):
    s = guest(tmp_path, ca, signed_registry="signer.lab:5000", image_repos=["ou/office", "ou/synapse"])
    files = {f["path"]: f["content"] for f in ci.build(s)["write_files"]}
    assert json.loads(files["/etc/ou-agent/image-identity.json"]) == {"10.64.255.2:8444": {"signed": "signer.lab:5000", "repos": ["ou/office", "ou/synapse"]}}


# ------------------------------------------------------------------------------------------------ first boot (the golden image applies exactly this)
def _conf(tmp_path, ca, **kw):
    s = guest(tmp_path, ca, **kw)
    return ci.callback_config(s, "gw-app1", 8443, ["192.168.22.167/32"], [])


def test_firstboot_validates_and_applies_the_trust_files(tmp_path, ca):
    conf = firstboot.validate_config(_conf(tmp_path, ca, signed_registry="signer.lab:5000", image_repos=["ou/office"]))
    assert [r["suite"] for r in conf["ou_repos"]] == ["stable"] and conf["artifact_tls_hosts"] == ["10.64.255.2:8444"] and conf["image_repos"] == ["ou/office"]
    root = tmp_path / "root"

    def runner(argv, **kw):
        argv = [sys.executable if a == "python3" else a for a in argv]
        argv = [str(ROOT / "ics/agent/deploy/render_image_policy.py") if a == "/opt/ou-agent/deploy/render_image_policy.py" else a for a in argv]
        return subprocess.run(argv, check=True, capture_output=True)
    firstboot.apply_trust(firstboot.Guest(str(root), runner=runner), conf)
    p = lambda x: (root / x.lstrip("/"))  # noqa: E731
    assert "ou-stable.asc" in p("/etc/ou-agent/apt/sources.list").read_text() and LAB_FPR in p("/etc/ou-agent/apt/pinned-fingerprints").read_text()
    assert p("/etc/ou-agent/artifact-ca.crt").read_text().startswith("-----BEGIN CERTIFICATE-----")
    assert p("/etc/containers/certs.d/10.64.255.2:8444/ca.crt").exists()
    pol = json.loads(p("/etc/ou-agent/image-policy.json").read_text())["transports"]["docker"]
    assert pol["10.64.255.2:8444"] == [{"type": "reject"}]
    ent = pol["10.64.255.2:8444/ou/office"][0]
    assert ent["type"] == "sigstoreSigned" and ent["signedIdentity"] == {"type": "exactRepository", "dockerRepository": "signer.lab:5000/ou/office"}
    assert "use-sigstore-attachments: true" in p("/etc/containers/registries.d/ou-agent.yaml").read_text()


def test_policy_without_identity_remap_is_match_repository(tmp_path, ca):
    conf = firstboot.validate_config(_conf(tmp_path, ca))
    sys.path.insert(0, str(ROOT / "ics/agent/deploy"))
    import render_image_policy as rip
    pol = rip.policy(["r.example:8444"], "/k.pub")
    assert pol["transports"]["docker"]["r.example:8444"][0]["signedIdentity"] == {"type": "matchRepository"} and conf["signed_registry"] is None


@pytest.mark.parametrize("mutate", [
    lambda c: c["ou_repos"][0].update(key_fingerprint="A" * 40),                       # key block does not hash to the pinned fingerprint
    lambda c: c["ou_repos"][0].update(url="http://10.64.255.2:8444/apt"),               # plain http
    lambda c: c["ou_repos"][0].update(suite="evil"),
    lambda c: c["ou_repos"].append(dict(c["ou_repos"][0])),                             # duplicate channel
    lambda c: c.update(artifact_ca_sha256="0" * 64),
    lambda c: c.update(artifact_tls_hosts=["a b"]),
    lambda c: c["ou_repos"][0].update(extra="x"),
    lambda c: c.update(apt_base_sources="deb [trusted=yes] http://x/ y z"),
    lambda c: c.update(unknown_field=1),
])
def test_firstboot_refuses_malformed_artifact_metadata(tmp_path, ca, mutate):
    c = _conf(tmp_path, ca)
    mutate(c)
    with pytest.raises(firstboot.Refused):
        firstboot.validate_config(c)


def test_agent_apt_reads_the_scoped_ca_config(tmp_path, monkeypatch):
    from ou_agent import guesthelper as helper
    d = tmp_path / "apt"
    d.mkdir()
    monkeypatch.setattr(helper, "APT_DIR", str(d))
    assert "-c" not in helper._apt_opts()
    (d / "apt-extra.conf").write_text("x")
    assert helper._apt_opts()[:2] == ["-c", str(d / "apt-extra.conf")]


# ------------------------------------------------------------------------------------------------ the publisher
def _publisher():
    path = str(ROOT / "ics/deploy/artifacts/ou-artifact-publish")
    spec = importlib.util.spec_from_loader("ou_artifact_publish", importlib.machinery.SourceFileLoader("ou_artifact_publish", path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.skipif(not shutil.which("gpg"), reason="gpg not installed")
def test_publisher_apt_verification(tmp_path):
    pub = _publisher()
    gh = tmp_path / "gh"
    gh.mkdir(mode=0o700)
    e = {**os.environ, "GNUPGHOME": str(gh)}

    def gpg(*a, inp_=None):
        return subprocess.run(["gpg", "--batch", "--no-tty", "--pinentry-mode", "loopback", "--passphrase", "", *a], env=e, capture_output=True, text=True, input=inp_)
    for who in ("a", "b"):
        assert gpg("--quick-generate-key", f"{who} <{who}@example.org>", "ed25519", "sign", "1d").returncode == 0
    fprs = {w: next(ln.split(":")[9] for ln in gpg("--list-keys", "--with-colons", f"{w}@example.org").stdout.splitlines() if ln.startswith("fpr")) for w in "ab"}
    keyfile = {w: tmp_path / f"{w}.asc" for w in "ab"}
    for w in "ab":
        keyfile[w].write_text(gpg("--armor", "--export", f"{w}@example.org").stdout)

    def make(root, ch="dev", signer="a", tamper_deb=False, expired=False):
        deb = b"!<arch>\nfake deb"
        (root / "pool" / ch / "x").mkdir(parents=True)
        (root / "pool" / ch / "x" / "x_1_all.deb").write_bytes(deb)
        pk = f"Package: x\nVersion: 1\nFilename: pool/{ch}/x/x_1_all.deb\nSize: {len(deb)}\nSHA256: {hashlib.sha256(deb).hexdigest()}\n\n".encode()
        d = root / "dists" / ch
        (d / "main" / "binary-amd64").mkdir(parents=True)
        (d / "main" / "binary-amd64" / "Packages").write_bytes(pk)
        until = time.strftime("%a, %d %b %Y %H:%M:%S UTC", time.gmtime(time.time() + (-3600 if expired else 86400)))
        rel = (f"Origin: t\nSuite: {ch}\nCodename: {ch}\nValid-Until: {until}\nSHA256:\n {hashlib.sha256(pk).hexdigest()} {len(pk)} main/binary-amd64/Packages\n")
        (d / "Release").write_text(rel)
        r = gpg("--local-user", f"{signer}@example.org", "--clearsign", "-o", str(d / "InRelease"), str(d / "Release"))
        assert r.returncode == 0, r.stderr
        if tamper_deb:
            (root / "pool" / ch / "x" / "x_1_all.deb").write_bytes(deb + b"evil")

    ok = tmp_path / "ok"
    make(ok)
    assert pub.check_channel(str(ok), "dev", str(keyfile["a"]), fprs["a"], time.time())["files_checked"] == 2
    with pytest.raises(pub.Refused, match="not signed by the pinned key"):
        pub.check_channel(str(ok), "dev", str(keyfile["a"]), fprs["b"], time.time())          # right key file, wrong pinned fingerprint
    wrong = tmp_path / "wrong"
    make(wrong, signer="b")
    with pytest.raises(pub.Refused):
        pub.check_channel(str(wrong), "dev", str(keyfile["a"]), fprs["a"], time.time())       # signed by another channel's key
    bad = tmp_path / "bad"
    make(bad, tamper_deb=True)
    with pytest.raises(pub.Refused, match="does not match the signed index"):
        pub.check_channel(str(bad), "dev", str(keyfile["a"]), fprs["a"], time.time())
    old = tmp_path / "old"
    make(old, expired=True)
    with pytest.raises(pub.Refused, match="expired"):
        pub.check_channel(str(old), "dev", str(keyfile["a"]), fprs["a"], time.time())
    other = tmp_path / "other"
    make(other, ch="stable")
    with pytest.raises(pub.Refused):                                                          # a stable tree offered as dev (suite mismatch)
        shutil.copytree(other / "dists" / "stable", other / "dists" / "dev")
        pub.check_channel(str(other), "dev", str(keyfile["a"]), fprs["a"], time.time())


def test_publisher_oci_signature_verification():
    pub = _publisher()
    k = ec.generate_private_key(ec.SECP256R1())
    pem = k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    digest = "sha256:" + "ab" * 32
    payload = json.dumps({"critical": {"identity": {"docker-reference": "r/ou/x"}, "image": {"docker-manifest-digest": digest}, "type": "cosign container image signature"},
                          "optional": None}).encode()
    sig = base64.b64encode(k.sign(payload, ec.ECDSA(hashes.SHA256()))).decode()
    pub.verify_signature(payload, sig, pem, digest)
    with pytest.raises(pub.Refused, match="another image"):
        pub.verify_signature(payload, sig, pem, "sha256:" + "cd" * 32)
    with pytest.raises(pub.Refused, match="does not verify"):
        pub.verify_signature(payload + b" ", sig, pem, digest)
    other = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    with pytest.raises(pub.Refused, match="does not verify"):
        pub.verify_signature(payload, sig, other, digest)            # signed by another channel's key
    with pytest.raises(pub.Refused):
        pub.verify_signature(payload, "!!!notbase64", pem, digest)


def test_system_page_reports_artifact_health_without_raising(monkeypatch, tmp_path, ca):
    from ics import sysinfo
    for k in list(os.environ):
        if k.startswith("OU_ARTIFACT_"):
            monkeypatch.delenv(k)
    sysinfo._ART_CACHE.update(at=0.0, value=None)
    assert sysinfo._artifacts() == {"configured": False}
    for k, v in env(tmp_path, ca, OU_ARTIFACT_BASE="127.0.0.1:9").items():
        monkeypatch.setenv(k, v)
    sysinfo._ART_CACHE.update(at=0.0, value=None)
    v = sysinfo._artifacts()
    assert v["configured"] is True and v["ok"] is False and v["registry"] == "127.0.0.1:9" and sysinfo._artifacts() is v       # cached
    monkeypatch.setenv("OU_ARTIFACT_CA_SHA256", "0" * 64)
    sysinfo._ART_CACHE.update(at=0.0, value=None)
    assert sysinfo._artifacts() == {"configured": True, "ok": False, "error": "invalid OU_ARTIFACT_* configuration"}
