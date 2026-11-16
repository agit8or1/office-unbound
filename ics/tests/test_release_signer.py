"""Security review 5 H1/H2: the release signer computes what it signs, and promotions need an ICS-signed manifest + runner attestations.
Self-contained sandbox (own gpg key with passphrase, own state dir); nothing outside the temp directory is touched."""
import base64
import gzip
import hashlib
import io
import json
import lzma
import os
import shutil
import subprocess
import sys
import tarfile
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "blueprints", "build", "repo"))
SIGNER = os.path.join(REPO, "ou-release-sign")
ATTEST = os.path.join(REPO, "ou-test-attest")
pytestmark = pytest.mark.skipif(not (shutil.which("gpg") and shutil.which("dpkg-deb")), reason="needs gpg and dpkg-deb")


def b64pub(k):
    return base64.b64encode(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def tar_of(files):
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w") as tf:
        for n, b in sorted(files.items()):
            ti = tarfile.TarInfo(n)
            ti.size = len(b)
            tf.addfile(ti, io.BytesIO(b))
    return bio.getvalue()


class Box:
    def __init__(self, tmp):
        self.state = str(tmp / "signer")
        self.runner = str(tmp / "runner")
        self.lib = str(tmp / "lib")
        gh = os.path.join(self.state, "gnupg")
        os.makedirs(gh, mode=0o700)
        os.makedirs(os.path.join(self.state, "trust"))
        os.makedirs(self.lib)
        # the fixed test program of the sandbox runner: fails for packages whose Description says "failme" (a real install smoke runs in nspawn-smoke)
        smoke = os.path.join(self.lib, "smoke-deb")
        open(smoke, "w").write('#!/bin/bash\necho "smoke of $(dpkg-deb -f "$1" Package)"\nif dpkg-deb -f "$1" Description | grep -q failme; then exit 1; fi\nexit 0\n')
        os.chmod(smoke, 0o755)
        os.chmod(self.lib, 0o755)
        open(os.path.join(self.state, "passphrase"), "w").write("pw\n")
        open(os.path.join(gh, "gpg-agent.conf"), "w").write("default-cache-ttl 1\nmax-cache-ttl 1\n")
        self.env = {**os.environ, "OU_RELEASE_STATE": self.state, "OU_TESTRUNNER_STATE": self.runner, "OU_RELEASE_SANDBOX": "1", "GNUPGHOME": gh,
                    "OU_TESTRUNNER_LIB": self.lib}
        self.fprs = {}
        for suite in ("dev", "staging", "stable"):     # ONE KEY PER CHANNEL (review 7 H-2)
            subprocess.run(["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase-file", os.path.join(self.state, "passphrase"), "--quick-generate-key",
                            "Sandbox %s <s@s>" % suite, "ed25519", "sign", "1d"], env=self.env, capture_output=True, check=True)
            out = subprocess.run(["gpg", "--list-secret-keys", "--with-colons", "Sandbox %s" % suite], env=self.env, capture_output=True, text=True).stdout
            self.fprs[suite] = [ln for ln in out.splitlines() if ln.startswith("fpr")][0].split(":")[9]
            open(os.path.join(self.state, "FINGERPRINT-" + suite), "w").write(self.fprs[suite])
        self.ics = Ed25519PrivateKey.generate()
        open(os.path.join(self.state, "trust", "ics-promotion.pub"), "w").write(b64pub(self.ics))
        rp = subprocess.run([sys.executable, ATTEST, "keygen"], env=self.env, capture_output=True, text=True, check=True).stdout.strip()
        open(os.path.join(self.state, "trust", "test-runner.pub"), "w").write(rp)
        os.chmod(os.path.join(self.state, "trust"), 0o755)
        for n in ("ics-promotion.pub", "test-runner.pub"):
            os.chmod(os.path.join(self.state, "trust", n), 0o644)
        self.tmp = tmp

    def run(self, args, stdin=b"", prog=SIGNER):
        return subprocess.run([sys.executable, "-I", prog, *args], input=stdin, env=self.env, capture_output=True)

    def deb(self, name, ver, content="x", desc="t", extra=""):
        d = self.tmp / f"d-{name}-{ver}-{content}"
        (d / "DEBIAN").mkdir(parents=True)
        (d / "usr").mkdir()
        (d / "usr" / "f").write_text(content)
        (d / "DEBIAN" / "control").write_text(f"Package: {name}\nVersion: {ver}\nArchitecture: amd64\nMaintainer: t <t@t>\n{extra}Description: {desc}\n")
        out = self.tmp / f"{name}_{ver}_amd64.deb"
        subprocess.run(["dpkg-deb", "--root-owner-group", "-Znone", "--build", str(d), str(out)], check=True, capture_output=True)
        return out.name, out.read_bytes()

    def admit(self, files):
        r = self.run(["admit", "dev"], tar_of(files))
        assert r.returncode == 0, r.stderr

    def attest(self, blob):
        """ask the runner to RUN the install smoke for this artifact (a caller can not hand it a result)"""
        h = hashlib.sha256(blob).hexdigest()
        r = self.run(["run", "deb-install-smoke", h], prog=ATTEST)
        assert r.returncode == 0, r.stderr
        return r.stdout

    def manifest(self, frm, to, files, evidence, approvers=("a1", "a2"), requester="r", **kw):
        m = {"v": 1, "plan_id": "p1", "from": frm, "to": to, "component": "c", "requested_by_id": requester,
             "approvers": [{"id": a, "username": a} for a in approvers], "approvals_required": 2 if to == "stable" else 1,
             "packages": [{"file": n, "sha256": hashlib.sha256(b).hexdigest(), "name": n.split("_")[0], "version": n.split("_")[1]} for n, b in files.items() if n.endswith(".deb")],
             "evidence": evidence, "nonce": base64.urlsafe_b64encode(os.urandom(18)).decode().rstrip("="), "issued_at": int(time.time()), "expires_at": int(time.time()) + 600}
        m.update(kw)
        return json.dumps({"manifest": m, "sig": base64.b64encode(self.ics.sign(b"ou-release-promotion-v1\n" + canon(m))).decode()}).encode()


@pytest.fixture()
def box(tmp_path):
    return Box(tmp_path)


def control_of(blob):
    p = subprocess.run(["dpkg-deb", "-f", "/dev/stdin"], input=blob, capture_output=True)
    if p.returncode != 0:      # dpkg-deb needs a file
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".deb") as t:
            t.write(blob)
            t.flush()
            p = subprocess.run(["dpkg-deb", "-f", t.name], capture_output=True, check=True)
    return p.stdout.decode()


def stanza(suite, fn, blob, comp="c", **over):
    """a Packages stanza as apt-ftparchive writes it: the control fields + Filename/Size/hashes (over: replace or add fields)"""
    f = {}
    for ln in control_of(blob).strip("\n").split("\n"):
        if ln[0] not in " \t":
            k, v = ln.split(":", 1)
            f[k] = v.strip()
    f.update({"Filename": f"pool/{suite}/{comp}/{fn}", "Size": str(len(blob)), "MD5sum": hashlib.md5(blob).hexdigest(), "SHA1": hashlib.sha1(blob).hexdigest(),
              "SHA256": hashlib.sha256(blob).hexdigest()})
    f.update(over)
    return "".join(f"{k}: {v}\n" for k, v in f.items() if v is not None) + "\n"


def index_set(suite, debs):
    pk = "".join(stanza(suite, n, b) for n, b in debs.items())
    return pk, ""


def release(files, suite="dev", extra_hdr="", extra_lines=()):
    lines = [f" {hashlib.sha256(b).hexdigest()} {len(b):16d} {p}" for p, b in sorted(files.items())] + list(extra_lines)
    return f"Origin: x\nSuite: {suite}\nCodename: {suite}\n{extra_hdr}SHA256:\n" + "\n".join(lines) + "\n"


def dists(suite, debs, pk_gz=None, with_xz=False):
    pk, src = index_set(suite, debs)
    f = {"main/binary-amd64/Packages": pk.encode(), "main/binary-amd64/Packages.gz": gzip.compress((pk_gz or pk).encode()),
         "main/source/Sources": src.encode(), "main/source/Sources.gz": gzip.compress(src.encode())}
    if with_xz:
        f["main/binary-amd64/Packages.xz"] = lzma.compress(pk.encode())
    return f


# ------------------------------------------------------------------------------------------------ H1
def test_sign_happy_path_rebuilds_release(box):
    deb = dict([box.deb("ou-a", "1")])
    box.admit(deb)
    f = dists("dev", deb)
    r = box.run(["sign", "dev"], tar_of({**f, "Release": release(f, "stable", "Valid-Until: Fri, 01 Jan 2100 00:00:00 UTC\n").encode()}))
    assert r.returncode == 0, r.stderr
    out = tarfile.open(fileobj=io.BytesIO(r.stdout)).extractfile("Release").read().decode()
    assert "Suite: dev\nCodename: dev\n" in out and "stable" not in out and "2100" not in out   # the caller's header is not kept
    assert "Packages.gz" in out and "Valid-Until:" in out


def test_h1_listed_but_not_supplied_index_refused(box):
    deb = dict([box.deb("ou-a", "1")])
    box.admit(deb)
    f = dists("dev", deb)
    rel = release(f, extra_lines=[" " + "0" * 64 + " 10 main/binary-amd64/Packages.xz"])
    r = box.run(["sign", "dev"], tar_of({**f, "Release": rel.encode()}))
    assert r.returncode != 0 and b"not supplied" in r.stderr


def test_h1_compressed_index_with_unadmitted_package_refused(box):
    good = dict([box.deb("ou-a", "1")])
    evil = dict([box.deb("ou-x", "2", "evil")])
    box.admit(good)
    f = dists("dev", good, pk_gz=index_set("dev", {**good, **evil})[0])      # Packages.gz lists an unadmitted .deb the uncompressed index hides
    r = box.run(["sign", "dev"], tar_of({**f, "Release": release(f).encode()}))
    assert r.returncode != 0 and b"decompresses" in r.stderr
    f2 = dists("dev", {**good, **evil})                                          # consistent variants, but the unadmitted file is named
    r = box.run(["sign", "dev"], tar_of({**f2, "Release": release(f2).encode()}))
    assert r.returncode != 0 and b"never admitted" in r.stderr


def test_h1_xz_variant_is_parsed(box):
    good = dict([box.deb("ou-a", "1")])
    evil = dict([box.deb("ou-x", "2", "evil")])
    box.admit(good)
    f = dists("dev", good, with_xz=True)
    f["main/binary-amd64/Packages.xz"] = lzma.compress(index_set("dev", {**good, **evil})[0].encode())
    r = box.run(["sign", "dev"], tar_of({**f, "Release": release(f).encode()}))
    assert r.returncode != 0


def test_h1_unlisted_extra_file_and_odd_path_refused(box):
    deb = dict([box.deb("ou-a", "1")])
    box.admit(deb)
    f = dists("dev", deb)
    r = box.run(["sign", "dev"], tar_of({**f, "main/binary-amd64/Packages.bz2": b"x", "Release": release(f).encode()}))
    assert r.returncode != 0 and b"does not list" in r.stderr
    r = box.run(["sign", "dev"], tar_of({**f, "evil/Packages": b"x", "Release": release({**f, "evil/Packages": b"x"}).encode()}))
    assert r.returncode != 0 and b"not an allowed index" in r.stderr


def test_h1_wrong_hash_refused(box):
    deb = dict([box.deb("ou-a", "1")])
    box.admit(deb)
    f = dists("dev", deb)
    rel = release(f).replace(hashlib.sha256(f["main/source/Sources"]).hexdigest(), "1" * 64)
    r = box.run(["sign", "dev"], tar_of({**f, "Release": rel.encode()}))
    assert r.returncode != 0


def test_h1_stanza_outside_suite_pool_refused(box):
    deb = dict([box.deb("ou-a", "1")])
    box.admit(deb)
    pk, src = index_set("dev", deb)
    f = {"main/binary-amd64/Packages": pk.replace("pool/dev/c/", "pool/stable/c/").encode(), "main/source/Sources": src.encode()}
    r = box.run(["sign", "dev"], tar_of({**f, "Release": release(f).encode()}))
    assert r.returncode != 0 and b"outside pool/dev" in r.stderr


def test_h1_dev_content_cannot_be_signed_as_stable(box):
    deb = dict([box.deb("ou-a", "1")])
    box.admit(deb)
    f = dists("stable", deb)
    r = box.run(["sign", "stable"], tar_of({**f, "Release": release(f, "stable").encode()}))
    assert r.returncode != 0 and b"never admitted" in r.stderr


# ------------------------------------------------------------------------------------------------ H2
def promote(box, frm, to, files, manifest):
    return box.run(["promote", frm, to], tar_of({**files, "promotion-manifest.json": manifest}))


def full_flow(box):
    deb = dict([box.deb("ou-a", "1")])
    box.admit(deb)
    blob = list(deb.values())[0]
    att = box.attest(blob)
    assert box.run(["record-test"], att).returncode == 0
    ev = [{"sha256": hashlib.sha256(blob).hexdigest(), "attestation_sha256": hashlib.sha256(canon(json.loads(att)["attestation"])).hexdigest()}]
    return deb, ev


def test_h2_legacy_cli_promote_without_manifest_refused(box):
    deb = dict([box.deb("ou-a", "1")])
    box.admit(deb)
    assert box.run(["promote", "dev", "staging", "Some Name"], tar_of(deb)).returncode != 0
    r = box.run(["promote", "dev", "staging"], tar_of(deb))
    assert r.returncode != 0 and b"manifest" in r.stderr


def test_h2_typed_record_refused_attestation_needed(box):
    deb = dict([box.deb("ou-a", "1")])
    box.admit(deb)
    blob = list(deb.values())[0]
    h = hashlib.sha256(blob).hexdigest()
    assert box.run(["record-test", h, "install-smoke", "pass", "0" * 64]).returncode != 0
    forged = json.dumps({"attestation": {"v": 1, "sha256": h, "name": "install-smoke", "result": "pass", "log_sha256": "0" * 64, "at": 1},
                         "sig": base64.b64encode(b"x" * 64).decode()}).encode()
    r = box.run(["record-test"], forged)
    assert r.returncode != 0 and b"not signed by the registered test runner" in r.stderr
    assert box.run(["record-test"], box.attest(blob)).returncode == 0


def test_h2_promotion_with_ics_manifest_works_and_is_single_use(box):
    deb, ev = full_flow(box)
    mf = box.manifest("dev", "staging", deb, ev, approvers=("a1",))
    r = promote(box, "dev", "staging", deb, mf)
    assert r.returncode == 0, r.stderr
    assert box.run(["status"]).stdout.decode().split() == ["dev", "1", "staging", "1", "stable", "0"]
    r = promote(box, "dev", "staging", deb, mf)
    assert r.returncode != 0 and b"replay" in r.stderr


@pytest.mark.parametrize("what", ["badsig", "requester", "oneapprover", "extra", "swap", "expired", "noevidence", "wrongpair"])
def test_h2_manifest_attacks_refused(box, what):
    deb, ev = full_flow(box)
    to = "stable" if what == "oneapprover" else "staging"
    frm = "staging" if to == "stable" else "dev"
    files = deb
    if to == "stable":   # get it into staging first, legitimately
        assert promote(box, "dev", "staging", deb, box.manifest("dev", "staging", deb, ev, approvers=("a1",))).returncode == 0
    if what == "badsig":
        mf = json.loads(box.manifest(frm, to, deb, ev, approvers=("a1",)))
        mf["manifest"]["approvers"].append({"id": "zz", "username": "zz"})
        mf = json.dumps(mf).encode()
    elif what == "requester":
        mf = box.manifest(frm, to, deb, ev, approvers=("r",))
    elif what == "oneapprover":
        mf = box.manifest(frm, to, deb, ev, approvers=("a1",))
    elif what == "extra":
        other = dict([box.deb("ou-b", "1", "other")])
        box.admit(other)
        files = {**deb, **other}
        mf = box.manifest(frm, to, deb, ev, approvers=("a1",))
    elif what == "swap":
        other = dict([box.deb("ou-a", "1", "swapped")])
        box.admit(other)
        files = other
        mf = box.manifest(frm, to, deb, ev, approvers=("a1",))
    elif what == "expired":
        mf = box.manifest(frm, to, deb, ev, approvers=("a1",), expires_at=int(time.time()) - 5)
    elif what == "noevidence":
        mf = box.manifest(frm, to, deb, [], approvers=("a1",))
    else:
        mf = box.manifest("staging", "stable", deb, ev, approvers=("a1", "a2"))   # a stable manifest presented for dev>staging
    assert promote(box, frm, to, files, mf).returncode != 0, "accepted: " + what


def test_h2_stable_needs_two_approvers_and_works_with_two(box):
    deb, ev = full_flow(box)
    assert promote(box, "dev", "staging", deb, box.manifest("dev", "staging", deb, ev, approvers=("a1",))).returncode == 0
    assert promote(box, "staging", "stable", deb, box.manifest("staging", "stable", deb, ev, approvers=("a1",))).returncode != 0
    r = promote(box, "staging", "stable", deb, box.manifest("staging", "stable", deb, ev, approvers=("a1", "a2")))
    assert r.returncode == 0, r.stderr


def test_h2_failed_test_blocks_promotion(box):
    deb = dict([box.deb("ou-a", "1", desc="failme")])
    box.admit(deb)
    blob = list(deb.values())[0]
    att = box.attest(blob)
    assert json.loads(att)["attestation"]["result"] == "fail"
    assert box.run(["record-test"], att).returncode == 0
    ev = [{"sha256": hashlib.sha256(blob).hexdigest(), "attestation_sha256": hashlib.sha256(canon(json.loads(att)["attestation"])).hexdigest()}]
    assert promote(box, "dev", "staging", deb, box.manifest("dev", "staging", deb, ev, approvers=("a1",))).returncode != 0


def test_h2_attest_refuses_unadmitted_package(box):
    assert box.run(["run", "deb-install-smoke", "a" * 64], prog=ATTEST).returncode != 0
