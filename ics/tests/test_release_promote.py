"""Security review 5 H2: release.promote is an ICS typed action; the executor hands the pipeline an ICS-signed manifest."""
import json
import os
import stat
import sys

import pytest
from sqlalchemy import text

from ics import agentclient, worker

H = "/api/v1"
SHA_A, SHA_E = "a" * 64, "e" * 64


@pytest.fixture()
def team(mk_user, login):
    return {n: login(mk_user(n, r)) for n, r in [("op", "operator"), ("adm", "admin"), ("ap1", "approver"), ("ap2", "approver")]}


@pytest.fixture()
def pipeline(rt, tmp_path):
    """a stand-in for repo.sh promote-manifest: stores the manifest it was handed"""
    out = tmp_path / "got.json"
    s = tmp_path / "fake-promote.py"
    s.write_text(f"import sys, shutil\nshutil.copy(sys.argv[1], {str(out)!r})\n")
    object.__setattr__(rt.settings, "release_promote_cmd", f"{sys.executable} {s}")
    return out


def params(to="staging"):
    return {"component": "libhx", "from_channel": "dev" if to == "staging" else "staging", "to_channel": to,
            "packages": [{"file": "ou-libhx_1_amd64.deb", "sha256": SHA_A, "name": "ou-libhx", "version": "1"}],
            "evidence": [{"sha256": SHA_A, "attestation_sha256": SHA_E}]}


def plan(team, who, p, expect=201):
    c, h = team[who]
    r = c.post(f"{H}/plans", json={"action": "release.promote", "params": p}, headers=h)
    assert r.status_code == expect, r.text
    return r.json()


def test_stable_needs_two_real_approvers_and_manifest_is_signed(rt, team, pipeline):
    b = plan(team, "adm", params("stable"))
    assert b["risk"] == "high" and b["approvals_required"] == 2
    assert team["adm"][0].post(f"{H}/plans/{b['plan_id']}/approve", headers=team["adm"][1]).status_code in (401, 403)   # requester
    d1 = team["ap1"][0].post(f"{H}/plans/{b['plan_id']}/approve", headers=team["ap1"][1]).json()
    assert d1["status"] == "pending_approval" and not d1["job_id"]
    d2 = team["ap2"][0].post(f"{H}/plans/{b['plan_id']}/approve", headers=team["ap2"][1]).json()
    worker.run_once(rt)
    job = team["adm"][0].get(f"{H}/jobs/{d2['job_id']}").json()
    assert job["status"] == "succeeded", job
    doc = json.loads(pipeline.read_text())
    man = doc["manifest"]
    pub = agentclient.load_signing_key(rt.settings.signing_key_file).public_key()
    assert agentclient.verify(pub, b"ou-release-promotion-v1\n", man, doc["sig"])
    assert sorted(a["username"] for a in man["approvers"]) == ["ap1", "ap2"] and "adm" not in str(man["approvers"])
    assert man["packages"][0]["sha256"] == SHA_A and man["evidence"][0]["attestation_sha256"] == SHA_E
    assert (man["from"], man["to"]) == ("staging", "stable")


def test_staging_one_approver_and_refusals(rt, team, pipeline):
    b = plan(team, "adm", params("staging"))
    assert b["risk"] == "normal"
    plan(team, "adm", {**params(), "to_channel": "stable"}, expect=422)                    # dev>stable skip
    bad = params()
    bad["evidence"] = []
    plan(team, "adm", bad, expect=422)                                                    # a .deb without evidence
    plan(team, "op", params(), expect=403)                                                # admin only
    d = team["ap1"][0].post(f"{H}/plans/{b['plan_id']}/approve", headers=team["ap1"][1]).json()
    worker.run_once(rt)
    assert team["adm"][0].get(f"{H}/jobs/{d['job_id']}").json()["status"] == "succeeded"


def test_pipeline_refusal_fails_the_job(rt, team, tmp_path):
    s = tmp_path / "no.py"
    s.write_text("import sys\nprint('refused by signer')\nsys.exit(3)\n")
    object.__setattr__(rt.settings, "release_promote_cmd", f"{sys.executable} {s}")
    b = plan(team, "adm", params("staging"))
    d = team["ap1"][0].post(f"{H}/plans/{b['plan_id']}/approve", headers=team["ap1"][1]).json()
    worker.run_once(rt)
    j = team["adm"][0].get(f"{H}/jobs/{d['job_id']}").json()
    assert j["status"] == "failed" and "refused" in json.dumps(j)


def oci_params(**kw):
    p = {"component": "oci-synapse", "from_channel": "dev", "to_channel": "staging",
         "packages": [{"file": "oci:ou~synapse:1.165.0", "sha256": SHA_A}], "evidence": [{"sha256": SHA_A, "attestation_sha256": SHA_E}]}
    p.update(kw)
    return p


def test_oci_promotion_is_one_image_with_scan_evidence_and_uses_the_oci_command(rt, team, tmp_path):
    plan(team, "adm", oci_params(evidence=[]), expect=422)                                                         # no scan evidence
    plan(team, "adm", oci_params(component="synapse"), expect=422)                                                 # not an oci-* component
    plan(team, "adm", oci_params(evidence=[{"sha256": SHA_E, "attestation_sha256": SHA_E}]), expect=422)           # evidence for another digest
    out = tmp_path / "oci.json"
    s = tmp_path / "fake-oci-promote.py"
    s.write_text(f"import sys, shutil\nshutil.copy(sys.argv[1], {str(out)!r})\n")
    object.__setattr__(rt.settings, "release_promote_oci_cmd", f"{sys.executable} {s}")
    object.__setattr__(rt.settings, "release_promote_cmd", None)                                                   # the deb command is not used for images
    b = plan(team, "adm", oci_params())
    d = team["ap1"][0].post(f"{H}/plans/{b['plan_id']}/approve", headers=team["ap1"][1]).json()
    worker.run_once(rt)
    assert team["adm"][0].get(f"{H}/jobs/{d['job_id']}").json()["status"] == "succeeded"
    man = json.loads(out.read_text())["manifest"]
    assert man["packages"] == [{"file": "oci:ou~synapse:1.165.0", "sha256": SHA_A, "name": None, "version": None}] and man["evidence"][0]["attestation_sha256"] == SHA_E
