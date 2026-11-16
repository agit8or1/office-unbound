"""OCI image signing (agent BI): ou-oci-sign (sigstore-format signatures, one key per channel) and ou-artifact-attest (the runner that builds the SBOM and
scans the image itself). Sandbox only: own keys/state in tmp, a fake HTTP registry, fake syft/osv-scanner; nothing outside the temp directory is touched."""
import base64
import hashlib
import http.server
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import threading
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

OCI = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "blueprints", "build", "oci", "signer"))
SIGNER, ATTEST, INSTALL = (os.path.join(OCI, n) for n in ("ou-oci-sign", "ou-artifact-attest", "install-oci-signer.sh"))
KEYGEN = os.path.join(OCI, "..", "..", "repo", "ou-test-attest")
pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="needs openssl")
REPO, TAG = "ou/synapse", "1.165.0"
PFX_ATT, PFX_PROMO = b"ou-test-attestation-v1\n", b"ou-release-promotion-v1\n"


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def sha(b):
    return hashlib.sha256(b).hexdigest()


def b64pub(k):
    return base64.b64encode(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


def tar_of(files):
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w") as tf:
        for n, b in files.items():
            ti = tarfile.TarInfo(n)
            ti.size = len(b)
            tf.addfile(ti, io.BytesIO(b))
    return bio.getvalue()


class Registry:
    """serves one image: manifest by digest and by tag, config blob, one layer; `lie` makes it answer a manifest whose bytes do not hash to the digest"""

    def __init__(self):
        self.layer = b"layer-bytes"
        self.config = json.dumps({"architecture": "amd64", "os": "linux", "rootfs": {"type": "layers", "diff_ids": []}}).encode()
        self.cfg_d = "sha256:" + sha(self.config)
        self.manifest = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                                    "config": {"mediaType": "application/vnd.docker.container.image.v1+json", "digest": self.cfg_d, "size": len(self.config)},
                                    "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "digest": "sha256:" + sha(self.layer), "size": len(self.layer)}]}).encode()
        self.digest = "sha256:" + sha(self.manifest)
        self.tag_to = self.digest
        self.lie = False
        self.have_layer = True
        reg = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_HEAD(self):
                self.do_GET(head=True)

            def do_GET(self, head=False):
                p = self.path
                body, code = b"", 404
                if p == "/v2/%s/manifests/%s" % (REPO, reg.digest) or (p == "/v2/%s/manifests/%s" % (REPO, TAG) and reg.tag_to == reg.digest):
                    body, code = (reg.manifest + b" " if reg.lie else reg.manifest), 200
                elif p == "/v2/%s/manifests/%s" % (REPO, TAG):
                    body, code = b'{"schemaVersion":2,"config":{},"layers":[],"x":1}', 200
                elif p == "/v2/%s/blobs/%s" % (REPO, reg.cfg_d):
                    body, code = reg.config, 200
                elif p == "/v2/%s/blobs/sha256:%s" % (REPO, sha(reg.layer)) and reg.have_layer:
                    body, code = reg.layer, 200
                self.send_response(code)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if not head:
                    self.wfile.write(body)
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.addr = "127.0.0.1:%d" % self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()


class Box:
    def __init__(self, tmp):
        self.tmp = tmp
        self.state = tmp / "ocisign"
        (self.state / "trust").mkdir(parents=True)
        for c in ("dev", "staging", "stable"):
            (self.state / ("passphrase-" + c)).write_text("pw-" + c)
            subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-aes-256-cbc", "-pass", "file:%s" % (self.state / ("passphrase-" + c)),
                            "-out", str(self.state / ("key-%s.pem" % c))], check=True, capture_output=True)
        self.reg = Registry()
        self.runner = Ed25519PrivateKey.generate()
        self.ics = Ed25519PrivateKey.generate()
        t = self.state / "trust"
        (t / "test-runner.pub").write_text(b64pub(self.runner))
        (t / "ics-promotion.pub").write_text(b64pub(self.ics))
        (t / "registry").write_text("registry.lab:5000\n")
        for p in (t, t / "test-runner.pub", t / "ics-promotion.pub", t / "registry"):
            os.chmod(p, 0o755 if p == t else 0o644)
        self.env = {"PATH": os.environ["PATH"], "OU_OCISIGN_STATE": str(self.state), "OU_OCISIGN_SANDBOX": "1", "OU_OCISIGN_REGISTRY_URL": "http://" + self.reg.addr}
        self.sbom = self.make_sbom(self.reg.cfg_d)

    @staticmethod
    def make_sbom(version, n=12):
        return json.dumps({"bomFormat": "CycloneDX", "metadata": {"component": {"type": "container", "version": version}}, "components": [{"name": "p%d" % i} for i in range(n)]}).encode()

    def attestation(self, sbom=None, key=None, **over):
        att = {"v": 1, "kind": "oci-scan", "name": "osv-scan", "sha256": self.reg.digest[7:], "repo": REPO, "config_digest": self.reg.cfg_d,
               "sbom_sha256": sha(sbom or self.sbom), "result": "pass", "vuln_ids": 3, "max_cvss": 7.5, "log_sha256": "0" * 64, "at": int(time.time())}
        att.update(over)
        k = key or self.runner
        return json.dumps({"attestation": att, "sig": base64.b64encode(k.sign(PFX_ATT + canon(att))).decode()}).encode(), att

    def manifest(self, att, to="staging", approvers=2, requester="r1", **over):
        frm = {"staging": "dev", "stable": "staging"}[to]
        now = int(time.time())
        m = {"v": 1, "plan_id": "p1", "from": frm, "to": to, "component": "oci-synapse", "requested_by_id": requester,
             "approvers": [{"id": "a%d" % i, "username": "ap%d" % i} for i in range(approvers)], "approvals_required": 2 if to == "stable" else 1,
             "packages": [{"file": "oci:ou~synapse:%s" % TAG, "sha256": self.reg.digest[7:], "name": None, "version": None}],
             "evidence": [{"sha256": self.reg.digest[7:], "attestation_sha256": sha(canon(att))}], "nonce": "n" * 8 + os.urandom(8).hex(), "issued_at": now, "expires_at": now + 900}
        m.update(over)
        return json.dumps({"manifest": m, "sig": base64.b64encode(self.ics.sign(PFX_PROMO + canon(m))).decode()}).encode()

    def request(self, channel="dev", **over):
        r = {"repo": REPO, "tag": TAG, "digest": self.reg.digest, "channel": channel}
        r.update(over)
        return json.dumps(r).encode()

    def sign(self, files, args=("sign",)):
        return subprocess.run([sys.executable, "-I", SIGNER, *args], input=tar_of(files), env=self.env, capture_output=True)

    def dev_files(self, **kw):
        sc, att = self.attestation()
        return {"request.json": self.request(), "sbom.cdx.json": self.sbom, "scan.attestation.json": sc}, att

    def pub(self, channel):
        r = subprocess.run([sys.executable, "-I", SIGNER, "pubkey", channel], env=self.env, capture_output=True, text=True, check=True)
        pem = r.stdout.split("# spki")[0]
        f = self.tmp / ("pub-%s.pem" % channel)
        f.write_text(pem)
        return str(f)

    def verifies(self, out, channel):
        files = {m.name: tarfile.open(fileobj=io.BytesIO(out)).extractfile(m).read() for m in tarfile.open(fileobj=io.BytesIO(out))}
        (self.tmp / "sig.bin").write_bytes(base64.b64decode(files["signature.b64"]))
        (self.tmp / "payload.bin").write_bytes(files["payload.json"])
        return subprocess.run(["openssl", "dgst", "-sha256", "-verify", self.pub(channel), "-signature", str(self.tmp / "sig.bin"), str(self.tmp / "payload.bin")],
                              capture_output=True).returncode == 0, json.loads(files["payload.json"])


@pytest.fixture()
def box(tmp_path):
    b = Box(tmp_path)
    yield b
    b.reg.srv.shutdown()


def refused(r, text=None):
    assert r.returncode == 3, (r.returncode, r.stderr)
    if text:
        assert text.encode() in r.stderr, r.stderr


def test_dev_signature_is_sigstore_format_bound_to_the_digest_and_verifies_only_with_the_dev_key(box):
    files, att = box.dev_files()
    r = box.sign(files)
    assert r.returncode == 0, r.stderr
    ok, payload = box.verifies(r.stdout, "dev")
    assert ok
    assert payload["critical"]["image"]["docker-manifest-digest"] == box.reg.digest
    assert payload["critical"]["identity"]["docker-reference"] == "registry.lab:5000/ou/synapse" and payload["critical"]["type"] == "cosign container image signature"
    assert payload["optional"]["io.officeunbound.sbom-sha256"] == att["sbom_sha256"] and payload["optional"]["io.officeunbound.channel"] == "dev"
    assert not box.verifies(r.stdout, "staging")[0] and not box.verifies(r.stdout, "stable")[0]        # one key per channel: a dev signature is worthless on a stable host


def test_the_signer_takes_no_arguments_and_the_sudoers_rules_are_exact():
    inst = open(INSTALL).read()
    rules = [ln for ln in inst.splitlines() if "NOPASSWD" in ln]
    assert rules and not any("*" in r for r in rules)
    assert any("ou-oci-sign sign\\n" in r for r in rules) and any("pubkey %s" in r for r in rules)


def test_extra_arguments_and_unexpected_members_are_refused(box):
    files, _ = box.dev_files()
    assert box.sign(files, args=("sign", "--channel", "stable")).returncode == 2
    assert box.sign({**files, "evil": b"x"}).returncode == 3
    assert box.sign({k: v for k, v in files.items() if k != "sbom.cdx.json"}).returncode == 3
    for bad in ({"repo": "library/alpine"}, {"repo": "ou/../x"}, {"tag": "a/b"}, {"digest": "sha256:" + "A" * 64}, {"channel": "prod"}, {"extra": 1}):
        f2 = dict(files, **{"request.json": box.request(**bad)})
        refused(box.sign(f2))


def test_registry_checks_digest_must_exist_hash_must_match_blobs_present_tag_not_moved(box):
    files, _ = box.dev_files()
    other = "sha256:" + "1" * 64
    refused(box.sign(dict(files, **{"request.json": box.request(digest=other)})), "no manifest")
    box.reg.lie = True
    refused(box.sign(files), "do not hash")
    box.reg.lie = False
    box.reg.have_layer = False
    refused(box.sign(files), "layer blob is missing")
    box.reg.have_layer = True
    box.reg.tag_to = "elsewhere"
    refused(box.sign(files), "tag")
    box.reg.tag_to = box.reg.digest
    assert box.sign(files).returncode == 0


def test_sbom_must_describe_this_image_and_be_bound_by_hash(box):
    files, att = box.dev_files()
    refused(box.sign(dict(files, **{"sbom.cdx.json": box.sbom + b" "})), "hash mismatch")                         # not the SBOM the scan was made on
    other = Box.make_sbom("sha256:" + "2" * 64)
    sc, _ = box.attestation(sbom=other)
    refused(box.sign(dict(files, **{"sbom.cdx.json": other, "scan.attestation.json": sc})), "describes")           # a (scanned) SBOM of another image
    thin = Box.make_sbom(box.reg.cfg_d, n=2)
    sc, _ = box.attestation(sbom=thin)
    refused(box.sign(dict(files, **{"sbom.cdx.json": thin, "scan.attestation.json": sc})), "inventory")
    refused(box.sign(dict(files, **{"sbom.cdx.json": b"{}"})))


def test_scan_attestation_must_come_from_the_runner_for_this_digest_pass_and_be_fresh(box):
    files, _ = box.dev_files()
    forged, _ = box.attestation(key=Ed25519PrivateKey.generate())                                                   # the build user's own key
    refused(box.sign(dict(files, **{"scan.attestation.json": forged})), "not signed by the registered test runner")
    failed, _ = box.attestation(result="fail")
    refused(box.sign(dict(files, **{"scan.attestation.json": failed})), "did not pass")
    stale, _ = box.attestation(at=int(time.time()) - 15 * 86400)
    refused(box.sign(dict(files, **{"scan.attestation.json": stale})), "stale")
    other, _ = box.attestation(sha256="3" * 64)
    refused(box.sign(dict(files, **{"scan.attestation.json": other})), "another image")
    kind, _ = box.attestation(kind="image-first-boot")
    refused(box.sign(dict(files, **{"scan.attestation.json": kind})), "oci-scan")
    refused(box.sign(dict(files, **{"scan.attestation.json": b"{}"})))
    tampered = json.loads(files["scan.attestation.json"])
    tampered["attestation"]["max_cvss"] = 0.0
    refused(box.sign(dict(files, **{"scan.attestation.json": json.dumps(tampered).encode()})), "not signed by the registered test runner")


def test_staging_and_stable_need_the_previous_channel_and_an_ics_signed_manifest(box):
    files, att = box.dev_files()
    sc = files["scan.attestation.json"]

    def promo(to, manifest=None, **kw):
        return {"request.json": box.request(to), "sbom.cdx.json": box.sbom, "scan.attestation.json": sc, **({"promotion-manifest.json": manifest} if manifest else {})}
    refused(box.sign(promo("staging")), "promotion manifest is required")                                             # no manifest
    refused(box.sign(promo("staging", box.manifest(att))), "never signed for dev")                                    # dev was never signed here
    assert box.sign(files).returncode == 0
    refused(box.sign({**files, "promotion-manifest.json": box.manifest(att)}), "not accepted for dev")
    good = box.manifest(att)
    forged = json.loads(good)
    forged["sig"] = base64.b64encode(Ed25519PrivateKey.generate().sign(b"x")).decode()
    refused(box.sign(promo("staging", json.dumps(forged).encode())), "not signed by the ICS")
    refused(box.sign(promo("staging", box.manifest(att, to="stable", approvers=2))), "manifest is for")
    refused(box.sign(promo("staging", box.manifest(att, approvers=0))), "approvers")
    refused(box.sign(promo("staging", box.manifest(att, requester="a0"))), "requester")
    refused(box.sign(promo("staging", box.manifest(att, expires_at=int(time.time()) - 5))), "expired")
    refused(box.sign(promo("staging", box.manifest(att, packages=[{"file": "oci:ou~synapse:9.9", "sha256": box.reg.digest[7:], "name": None, "version": None}]))), "approved set")
    refused(box.sign(promo("staging", box.manifest({**att, "max_cvss": 1.0}))), "evidence")
    r = box.sign(promo("staging", good))
    assert r.returncode == 0, r.stderr
    assert box.verifies(r.stdout, "staging")[0] and not box.verifies(r.stdout, "dev")[0]
    refused(box.sign(promo("staging", good)), "replay")                                                               # single use
    refused(box.sign(promo("stable", box.manifest(att, to="stable", approvers=1))), "2 distinct")                   # stable needs two approvers
    r = box.sign(promo("stable", box.manifest(att, to="stable", approvers=2)))
    assert r.returncode == 0, r.stderr
    assert box.verifies(r.stdout, "stable")[0]


def test_pubkey_needs_a_channel(box):
    assert subprocess.run([sys.executable, "-I", SIGNER, "pubkey"], env=box.env, capture_output=True).returncode == 2
    assert subprocess.run([sys.executable, "-I", SIGNER, "pubkey", "prod"], env=box.env, capture_output=True).returncode == 2
    assert "BEGIN PUBLIC KEY" in open(box.pub("dev")).read() and open(box.pub("dev")).read() != open(box.pub("stable")).read()


# ---------------------------------------------------------------------------------------------------------------- the runner
def runner_env(box, tools):
    rs = box.tmp / "runner"
    subprocess.run([sys.executable, KEYGEN, "keygen"], env={**os.environ, "OU_TESTRUNNER_STATE": str(rs)}, capture_output=True, check=True)
    return {"PATH": os.environ["PATH"], "OU_TESTRUNNER_STATE": str(rs), "OU_ATTEST_SANDBOX": "1", "OU_ATTEST_TOOLS": str(tools), "OU_ATTEST_REGISTRY_FILE": str(box.state / "trust" / "registry"),
            "OU_ATTEST_REGISTRY_ADDR": box.reg.addr}


def fake_tools(tmp, version, ncomp=12, cvss="7.5"):
    d = tmp / "tools"
    d.mkdir()
    (d / "syft").write_text("#!/bin/sh\necho '%s'\n" % Box.make_sbom(version, ncomp).decode())
    (d / "osv-scanner").write_text("#!/bin/sh\necho '{\"results\":[{\"packages\":[{\"vulnerabilities\":[{\"id\":\"CVE-1\"}],\"groups\":[{\"max_severity\":\"%s\"}]}]}]}'\nexit 1\n" % cvss)
    for n in ("syft", "osv-scanner"):
        os.chmod(d / n, 0o755)
    return d


def run_scan(box, env, rq):
    return subprocess.run([sys.executable, "-I", ATTEST, "scan"], input=json.dumps(rq).encode(), env=env, capture_output=True)


def test_runner_pulls_and_scans_by_reference_only_and_its_attestation_is_accepted_by_the_signer(box):
    env = runner_env(box, fake_tools(box.tmp, box.reg.cfg_d))
    (box.state / "trust" / "test-runner.pub").write_text(subprocess.run([sys.executable, KEYGEN, "keygen"], env=env, capture_output=True, text=True).stdout.strip())
    assert subprocess.run([sys.executable, "-I", ATTEST, "scan", "ou/synapse", box.reg.digest], env=env, capture_output=True).returncode == 2         # no argv, no results
    assert run_scan(box, env, {"repo": REPO, "digest": box.reg.digest, "result": "pass"}).returncode == 3                                             # no caller-supplied fields
    assert run_scan(box, env, {"repo": "library/x", "digest": box.reg.digest}).returncode == 3
    r = run_scan(box, env, {"repo": REPO, "digest": box.reg.digest})
    assert r.returncode == 0, r.stderr
    doc = json.loads(r.stdout)
    assert doc["attestation"]["result"] == "pass" and doc["attestation"]["sbom_sha256"] == sha(doc["sbom"].encode())
    files = {"request.json": box.request(), "sbom.cdx.json": doc["sbom"].encode(), "scan.attestation.json": json.dumps({"attestation": doc["attestation"], "sig": doc["sig"]}).encode()}
    assert box.sign(files).returncode == 0                                                                                                         # runner output -> signer
    box.reg.lie = True
    assert run_scan(box, env, {"repo": REPO, "digest": box.reg.digest}).returncode == 3                                                              # registry bytes are re-hashed


def test_runner_fails_the_attestation_for_a_critical_finding_or_an_sbom_of_another_image(box):
    env = runner_env(box, fake_tools(box.tmp, box.reg.cfg_d, cvss="9.8"))
    r = run_scan(box, env, {"repo": REPO, "digest": box.reg.digest})
    assert r.returncode == 0 and json.loads(r.stdout)["attestation"]["result"] == "fail"
    shutil.rmtree(box.tmp / "tools")
    env = runner_env(box, fake_tools(box.tmp, "sha256:" + "4" * 64))
    r = run_scan(box, env, {"repo": REPO, "digest": box.reg.digest})
    assert json.loads(r.stdout)["attestation"]["result"] == "fail"


def test_the_runner_sudoers_rules_would_be_exact():
    src = open(os.path.join(OCI, "install-oci-runner.sh")).read()
    rules = [ln for ln in src.splitlines() if "NOPASSWD" in ln and ln.lstrip().startswith("printf")]
    assert len(rules) == 2 and not any("*" in r for r in rules)
