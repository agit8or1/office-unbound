"""Security review 7 regression tests for the release signer and the test runner: H-1 (duplicate stanzas), M-3 (stanza metadata), H-2 (one key per
channel), H-3 (the runner runs the test itself), L-5 (attestation freshness). Same sandbox as test_release_signer.py (own keys and state)."""
import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile

import pytest

from tests.test_release_signer import (ATTEST, Box, canon, dists, full_flow, promote, release, stanza, tar_of)  # noqa: F401

pytestmark = pytest.mark.skipif(not (shutil.which("gpg") and shutil.which("dpkg-deb")), reason="needs gpg and dpkg-deb")
H = lambda b: hashlib.sha256(b).hexdigest()  # noqa: E731


@pytest.fixture(scope="module")
def mbox(tmp_path_factory):
    return Box(tmp_path_factory.mktemp("sig7"))


@pytest.fixture(scope="module")
def stable(mbox):
    """ou-a 1 legitimately in dev, staging and stable; a never-admitted trojan"""
    box = mbox
    deb, ev = full_flow(box)
    assert promote(box, "dev", "staging", deb, box.manifest("dev", "staging", deb, ev, approvers=("a1",))).returncode == 0
    assert promote(box, "staging", "stable", deb, box.manifest("staging", "stable", deb, ev)).returncode == 0
    (an, ab), = deb.items()
    tn, tb = box.deb("ou-a", "2", content="TROJAN")
    return box, deb, an, ab, tn, tb


def sign(box, suite, pk, src=""):
    f = {"main/binary-amd64/Packages": pk.encode(), "main/binary-amd64/Packages.gz": gzip.compress(pk.encode()),
         "main/source/Sources": src.encode(), "main/source/Sources.gz": gzip.compress(src.encode())}
    return box.run(["sign", suite], tar_of({**f, "Release": release(f, suite).encode()}))


# ---------------------------------------------------------------------------------------------- H-1 / M-3
def test_legit_index_signs(stable):
    box, deb, an, ab, tn, tb = stable
    r = sign(box, "stable", stanza("stable", an, ab))
    assert r.returncode == 0, r.stderr


def test_h1_duplicate_basename_in_two_components_refused(stable):
    box, deb, an, ab, tn, tb = stable
    # PoC of review 7: trojan stanza first (other component), the admitted one last -> the old signer only kept the last
    pk = stanza("stable", an, tb, comp="x", Version="2") + stanza("stable", an, ab, comp="c")
    assert sign(box, "stable", pk).returncode != 0
    r = sign(box, "stable", stanza("stable", an, ab, comp="x") + stanza("stable", an, ab, comp="c"))
    assert r.returncode != 0 and b"more than once" in r.stderr
    r = sign(box, "stable", stanza("stable", an, ab) * 2)
    assert r.returncode != 0 and b"more than once" in r.stderr


def test_h1_duplicate_package_version_arch_refused(stable):
    box, deb, an, ab, tn, tb = stable
    pk = stanza("stable", an, ab, comp="c") + stanza("stable", "ou-a_1_amd64.deb".replace("ou-a", "ou-a"), ab, comp="d").replace("ou-a_1_amd64.deb", "ou-a_1_amd64.deb")
    assert sign(box, "stable", pk).returncode != 0


def test_h1_every_stanza_is_checked_not_only_the_last(stable):
    box, deb, an, ab, tn, tb = stable
    other = "ou-b_1_amd64.deb"
    pk = stanza("stable", other, tb, Package="ou-b", Version="1") + stanza("stable", an, ab)       # trojan FIRST, admitted last
    r = sign(box, "stable", pk)
    assert r.returncode != 0 and b"never admitted" in r.stderr


def test_h1_strict_parser_refuses_duplicate_fields_comments_and_crlf(stable):
    box, deb, an, ab, tn, tb = stable
    good = stanza("stable", an, ab)
    for bad in (good.rstrip("\n") + "\nSHA256: " + H(tb) + "\n\n",           # duplicate SHA256 field in one stanza
                "# note\n" + good, good.replace("\n", "\r\n"), " continuation first\n" + good,
                good.replace("Package:", "Package :", 1)):
        r = sign(box, "stable", bad)
        assert r.returncode != 0, bad[:40]


def test_m3_metadata_substitution_refused(stable):
    box, deb, an, ab, tn, tb = stable
    # the PoCs of the review: another package name/version with Conflicts, wrong Size/MD5sum, added Depends
    for over in ({"Package": "ou-b", "Version": "99", "Conflicts": "nftables"}, {"Version": "99"}, {"Conflicts": "nftables"}, {"Depends": "evil"},
                 {"Size": "1"}, {"MD5sum": "0" * 32}, {"Architecture": "all"}, {"Pre-Depends": "ou-a"}):
        r = sign(box, "stable", stanza("stable", an, ab, **over))
        assert r.returncode != 0, over


def test_m3_real_apt_ftparchive_output_is_accepted(stable, tmp_path):
    """compatibility: the Packages that apt-ftparchive really writes for the admitted pool signs without change"""
    if not shutil.which("apt-ftparchive"):
        pytest.skip("apt-ftparchive missing")
    box, deb, an, ab, tn, tb = stable
    pool = tmp_path / "pool" / "stable" / "c"
    pool.mkdir(parents=True)
    (pool / an).write_bytes(ab)
    out = subprocess.run(["apt-ftparchive", "packages", "pool/stable"], cwd=tmp_path, capture_output=True, check=True).stdout.decode()
    r = sign(box, "stable", out)
    assert r.returncode == 0, r.stderr


def test_sources_checks(stable):
    box, deb, an, ab, tn, tb = stable
    src = f"Package: s\nDirectory: pool/stable/c\nChecksums-Sha256:\n {H(tb)} {len(tb)} {an}\n {H(ab)} {len(ab)} {an}\n\n"
    assert sign(box, "stable", "", src).returncode != 0                 # same name twice, one never admitted
    src = f"Package: s\nDirectory: pool/stable/c\nChecksums-Sha256:\n {H(tb)} {len(tb)} {an}\n\n"
    assert sign(box, "stable", "", src).returncode != 0


# ---------------------------------------------------------------------------------------------- H-2
def verify_with(box, suite, keysuite, signed_tar):
    """gpgv the InRelease against the public key of `keysuite` only"""
    d = box.tmp / ("v-%s-%s" % (suite, keysuite))
    d.mkdir(exist_ok=True)
    tarfile.open(fileobj=io.BytesIO(signed_tar)).extractall(d)
    pub = subprocess.run(["gpg", "--export", box.fprs[keysuite]], env=box.env, capture_output=True, check=True).stdout
    (d / "k.gpg").write_bytes(pub)
    return subprocess.run(["gpgv", "--keyring", str(d / "k.gpg"), str(d / "Release.gpg"), str(d / "Release")], capture_output=True).returncode


def test_h2_each_channel_has_its_own_key(stable):
    box, deb, an, ab, tn, tb = stable
    assert len(set(box.fprs.values())) == 3
    r = sign(box, "dev", stanza("dev", an, ab))
    assert r.returncode == 0, r.stderr
    assert verify_with(box, "dev", "dev", r.stdout) == 0
    # the stable key (what first-contact guests pin) does NOT validate a dev Release: serving it under dists/stable fails apt's signature check
    assert verify_with(box, "dev", "stable", r.stdout) != 0
    assert verify_with(box, "dev", "staging", r.stdout) != 0
    r = sign(box, "stable", stanza("stable", an, ab))
    assert verify_with(box, "stable", "stable", r.stdout) == 0 and verify_with(box, "stable", "dev", r.stdout) != 0


def test_h2_missing_channel_key_refuses_to_sign(stable):
    box, deb, an, ab, tn, tb = stable
    p = os.path.join(box.state, "FINGERPRINT-dev")
    saved = open(p).read()
    os.unlink(p)
    try:
        r = sign(box, "dev", stanza("dev", an, ab))
        assert r.returncode != 0 and b"no signing key for channel dev" in r.stderr
    finally:
        open(p, "w").write(saved)


def test_h2_signed_release_carries_signer_set_suite_and_codename(stable):
    box, deb, an, ab, tn, tb = stable
    r = sign(box, "staging", stanza("staging", an, ab))
    assert r.returncode == 0, r.stderr
    rel = tarfile.open(fileobj=io.BytesIO(r.stdout)).extractfile("Release").read().decode()
    assert "Suite: staging\nCodename: staging\n" in rel


# ---------------------------------------------------------------------------------------------- H-3
def test_h3_runner_takes_no_result_from_the_caller(stable):
    box, deb, an, ab, tn, tb = stable
    h = H(ab)
    for args in (["attest", h, "install-smoke", "pass", "0" * 64], ["run", "deb-install-smoke", h, "pass"], ["run", "deb-install-smoke", h, "install-smoke", "pass", "0" * 64]):
        assert box.run(args, prog=ATTEST).returncode != 0
    assert box.run(["run", "no-such-kind", h], prog=ATTEST).returncode != 0


def test_h3_runner_runs_the_test_and_reports_what_it_saw(stable):
    box, *_ = stable
    good = dict([box.deb("ou-good", "1")])
    bad = dict([box.deb("ou-bad", "1", desc="failme")])
    box.admit(good)
    box.admit(bad)
    a = json.loads(box.attest(list(good.values())[0]))["attestation"]
    b = json.loads(box.attest(list(bad.values())[0]))["attestation"]
    assert a["result"] == "pass" and b["result"] == "fail"
    assert a["v"] == 2 and a["kind"] == "deb-install-smoke" and a["name"] == "install-smoke" and a["sha256"] == H(list(good.values())[0])
    log = open(os.path.join(box.runner, "logs", a["run_id"] + ".log"), "rb").read()
    assert a["log_sha256"] == H(log) and b"smoke of ou-good" in log             # the log hash is of what the RUNNER captured


def test_h3_blob_tamper_and_unadmitted_refused(stable):
    box, deb, an, ab, tn, tb = stable
    h = H(tb)
    assert box.run(["run", "deb-install-smoke", h], prog=ATTEST).returncode != 0          # never admitted
    one = dict([box.deb("ou-tamper", "1")])
    box.admit(one)
    sha = H(list(one.values())[0])
    open(os.path.join(box.state, "blobs", sha), "wb").write(b"x")
    r = box.run(["run", "deb-install-smoke", sha], prog=ATTEST)
    assert r.returncode != 0 and b"does not match its hash" in r.stderr


def test_h3_infrastructure_error_makes_no_attestation(stable):
    box, *_ = stable
    one = dict([box.deb("ou-infra", "1")])
    box.admit(one)
    prog = os.path.join(box.lib, "smoke-deb")
    saved = open(prog).read()
    open(prog, "w").write("#!/bin/bash\nexit 7\n")
    try:
        r = box.run(["run", "deb-install-smoke", H(list(one.values())[0])], prog=ATTEST)
        assert r.returncode != 0 and not r.stdout
    finally:
        open(prog, "w").write(saved)


def test_h3_image_kind_only_below_image_dir(stable, tmp_path):
    box, *_ = stable
    img = tmp_path / "x.img"
    img.write_bytes(b"i")
    r = box.run(["run", "image-first-boot", str(img)], prog=ATTEST)
    assert r.returncode != 0 and (b"must be below" in r.stderr or b"not installed" in r.stderr)
    assert box.run(["run", "image-first-boot", "relative.img"], prog=ATTEST).returncode != 0


def test_h3_record_refuses_v1_wrong_kind_and_old_attestation(stable):
    box, *_ = stable
    one = dict([box.deb("ou-fresh", "1")])
    box.admit(one)
    blob = list(one.values())[0]
    first = box.attest(blob)
    assert box.run(["record-test"], first).returncode == 0
    doc = json.loads(first)
    # an older (or equal) attestation can not overwrite the record (L-5)
    r = box.run(["record-test"], first)
    assert r.returncode != 0 and b"newer" in r.stderr
    # an attestation whose kind is not deb-install-smoke (e.g. the image kind) is not accepted by the package signer
    att = dict(doc["attestation"], kind="image-first-boot")
    r = box.run(["record-test"], json.dumps({"attestation": att, "sig": doc["sig"]}).encode())
    assert r.returncode != 0
    att = dict(doc["attestation"], v=1)
    assert box.run(["record-test"], json.dumps({"attestation": att, "sig": doc["sig"]}).encode()).returncode != 0
