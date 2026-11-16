"""Read-only console views: GET /releases, GET /deployments/{slug}/bootstrap, /system controller block."""
import json
import os
import uuid
from dataclasses import replace

from sqlalchemy import text

from ics import audit, console_api
from ics.guest import callback

H = "/api/v1"
SHA_A, SHA_B, SHA_C = "a" * 64, "b" * 64, "c" * 64


def _packages(*items):
    return "\n\n".join(f"Package: {n}\nVersion: {v}\nArchitecture: amd64\nFilename: pool/{s}/{c}/{n}_{v}_amd64.deb\nSHA256: {h}" for s, c, n, v, h in items) + "\n"


def _repo(tmp_path, dev, staging=()):
    for suite, items in (("dev", dev), ("staging", staging)):
        d = tmp_path / "repo" / "dists" / suite / "main" / "binary-amd64"
        d.mkdir(parents=True)
        (d / "Packages").write_text(_packages(*items))
    rec = tmp_path / "records"
    rec.mkdir()
    return str(tmp_path / "repo"), str(rec), rec


def test_parse_packages_ignores_foreign_paths():
    raw = "Package: x\nVersion: 1\nFilename: ../../etc/x.deb\nSHA256: " + SHA_A + "\n\n" + _packages(("dev", "ou-x", "ou-x", "1.0", SHA_B))
    assert [p["name"] for p in console_api.parse_packages(raw)] == ["ou-x"]


def test_releases_not_configured_and_configured(tmp_path, rt, client, mk_user, login):
    vw = login(mk_user("vw", "viewer"))[0]
    j = vw.get(f"{H}/releases").json()
    assert j["configured"] is False and j["channels"] == []
    repo, recs, recdir = _repo(tmp_path, dev=[("dev", "ou-x", "ou-x", "1.0", SHA_A), ("dev", "ou-x", "ou-y", "2.0", SHA_B)])
    (recdir / (SHA_A + ".json")).write_text(json.dumps({"results": {"install-smoke": {"result": "pass", "attestation_sha256": SHA_C, "at": "2026-11-01T00:00:00Z"}}}))
    rt.settings = replace(rt.settings, release_repo_dir=repo, release_records_dir=recs) if hasattr(rt.settings, "__dataclass_fields__") else rt.settings.model_copy(update={"release_repo_dir": repo, "release_records_dir": recs})
    j = vw.get(f"{H}/releases").json()
    assert j["configured"] and [c["name"] for c in j["channels"]] == ["dev", "staging", "stable"]
    assert j["channels"][2]["available"] is False
    c = j["candidates"][0]
    assert (c["from_channel"], c["to_channel"], c["approvals_required"]) == ("dev", "staging", 1)
    assert c["ready"] is False and any("ou-y" in b for b in c["blocked"])      # ou-y has no test record
    (recdir / (SHA_B + ".json")).write_text(json.dumps({"results": {"install-smoke": {"result": "pass", "attestation_sha256": SHA_A}}}))
    c = vw.get(f"{H}/releases").json()["candidates"][0]
    assert c["ready"] and len(c["params"]["packages"]) == 2 and len(c["params"]["evidence"]) == 2
    assert c["params"]["packages"][0]["sha256"] == SHA_A


def test_bootstrap_states(rt, client, mk_user, login):
    vw = login(mk_user("vw2", "viewer"))[0]
    did = str(uuid.uuid4())
    with rt.session() as db:
        db.execute(text("INSERT INTO deployments (id, slug, customer_id, profile, profile_version, status, desired_spec) VALUES (:i, :slug, 'c', 'p', '1', 'active', '{}')"), {"i": did, "slug": "dep-" + did[:8]})
        for bid, vm, vmid, state, exp in (("1" * 16, "mail", 101, "pending", "1 hour"), ("2" * 16, "web", 102, "enrolled", "1 hour"), ("3" * 16, "db", 103, "pending", "-1 hour")):
            db.execute(text("INSERT INTO guest_bootstrap (bid, deployment_id, vm, vmid, mode, state, expires_at) VALUES (:b, :d, :v, :n, 'callback', :s, now() + CAST(:e AS interval))"),
                       {"b": bid, "d": did, "v": vm, "n": vmid, "s": state, "e": exp})
        audit.append(db, "guest.bootstrap_replay_alarm", actor_name="guest", resource="guest_bootstrap", resource_id="2" * 16, details={})
        db.commit()
    r = vw.get(f"{H}/deployments/dep-{did[:8]}/bootstrap")
    assert r.status_code == 200, r.text
    by = {v["vm"]: v for v in r.json()["vms"]}
    assert by["mail"]["state"] == "pending" and by["web"]["state"] == "enrolled" and by["db"]["state"] == "expired"
    assert by["web"]["replay_alarm"]["count"] == 1 and by["mail"]["replay_alarm"] is None
    assert by["mail"]["rate_limited"] is False
    for _ in range(callback.PER_BID_LIMIT):
        callback.LIMITER.allow("bid:" + "1" * 16, callback.PER_BID_LIMIT, callback.PER_BID_WINDOW)
    assert {v["vm"]: v for v in vw.get(f"{H}/deployments/dep-{did[:8]}/bootstrap").json()["vms"]}["mail"]["rate_limited"] is True
    callback.LIMITER.reset()
    assert vw.get(f"{H}/deployments/none/bootstrap").status_code == 404



def test_system_controller_block(mk_user, login):
    adm = login(mk_user("adm2", "admin"))[0]
    c = adm.get(f"{H}/system").json()["controller"]
    assert c["role"] == "primary" and c["epoch"] >= 1 and c["fenced"] is False and c["replication"] is None


def test_approval_policy(mk_user, login):
    assert login(mk_user("vw3", "viewer"))[0].get(f"{H}/approvals/policy").json() == {"normal": 1, "high": 2}
