"""Connection wizard sign-in (provisioning/adminsession): Proxmox user name + password (+ TOTP / recovery key), ticket-only storage, read-only
discovery, and plans that use the session instead of a password. Proxmox is the stateful simulator."""
import json

import pytest
from sqlalchemy import text

from ics import worker
from ics.provisioning import adminsession
from .infra_fixtures import H
from .test_inventory import World
from .test_provisioning import POLICY, owner, owner2  # noqa: F401  (fixtures)


@pytest.fixture()
def w(rt, mk_user, login):
    return World(rt, mk_user, login)


@pytest.fixture(autouse=True)
def _rl():
    from ics import ratelimit
    ratelimit.reset()
    yield


def sign_in(w, srv, user="root", realm="pam", password=None, expect=201, **kw):
    body = {"base_url": srv.url, "trust": "fingerprint", "fingerprint_sha256": srv.fingerprint, "username": user, "realm": realm,
            "password": srv.sim.ROOT_PW if password is None else password, **kw}
    r = w.ad.post(f"{H}/pve-sessions", json=body, headers=w.adh)
    assert r.status_code == expect, r.text
    return r.json()


def tfa_user(srv, uid="mfa@pve", totp="246810", recovery=("rec-aaaa-1111",), webauthn=False):
    srv.sim.add_user(uid, password="Mfa-Pass-1", comment="tfa", roles=[("/", "Administrator")])
    srv.sim.users[uid].update({"totp": totp, "recovery": list(recovery), "webauthn": webauthn})
    return uid


def dump(owner_engine) -> str:
    with owner_engine.connect() as c:
        out = []
        for q in ("SELECT params::text, coalesce(secret_enc::text,'') FROM plans", "SELECT coalesce(result::text,''), coalesce(error::text,'') FROM jobs",
                  "SELECT details_canon FROM audit_events", "SELECT row_to_json(s)::text FROM pve_admin_sessions s"):
            out += [[str(x) for x in r] for r in c.execute(text(q)).all()]
    return json.dumps(out)


def run_as_admin(w, action, params):
    r = w.ad.post(f"{H}/plans", json={"action": action, "params": params}, headers=w.adh)
    assert r.status_code == 201, r.text
    p = r.json()
    jid = p.get("job_id")
    if p["status"] != "approved":
        for c, h in ((w.a1, w.a1h), (w.a2, w.a2h))[: 2 if p["risk"] == "high" else 1]:
            rr = c.post(f"{H}/plans/{p['plan_id']}/approve", headers=h)
            assert rr.status_code == 200, rr.text
            jid = rr.json()["job_id"]
    while worker.run_once(w.rt):
        pass
    return p, w.ad.get(f"{H}/jobs/{jid}", headers=w.adh).json()


def test_password_login_keeps_only_the_ticket_and_never_the_password(w, owner, rt, owner_engine):
    s = sign_in(w, owner)
    assert s["state"] == "ready" and s["username"] == "root@pam" and s["trust"] == "fingerprint"
    assert "PVE:" not in json.dumps(s) and "csrf" not in json.dumps(s).lower()      # the view describes the credential but never carries it
    with rt.session() as db:
        r = adminsession.row(db, s["id"])
        c = db.execute(text("SELECT * FROM credentials WHERE id = :i"), {"i": str(r.credential_id)}).first()
        assert c.provider == "pve-admin" and c.purpose == "temporary_provisioning" and (c.expires_at - c.created_at).total_seconds() <= 30 * 60 + 1
    from ics.credentials import service as cred
    sec = json.loads(cred.get_secret(rt, r.credential_id))
    assert set(sec) == {"admin_ticket", "admin_csrf", "admin_ticket_user"} and sec["admin_ticket"].startswith("PVE:root@pam:")
    assert owner.sim.ROOT_PW not in dump(owner_engine)


def test_wrong_password_and_validation_errors_echo_nothing(w, owner, owner_engine):
    r = sign_in(w, owner, password="Wrong-Secret-xyz", expect=401)
    assert "rejected the login" in r["detail"]
    r = w.ad.post(f"{H}/pve-sessions", json={"base_url": owner.url, "trust": "fingerprint", "fingerprint_sha256": owner.fingerprint,
                                             "username": "root", "password": "Leaky-Secret-1", "bogus": 1}, headers=w.adh)
    assert r.status_code == 422 and "Leaky-Secret-1" not in r.text
    d = dump(owner_engine)
    assert "Wrong-Secret-xyz" not in d and "Leaky-Secret-1" not in d


def test_only_admins_can_sign_in(w, owner):
    r = w.o.post(f"{H}/pve-sessions", json={"base_url": owner.url, "trust": "fingerprint", "fingerprint_sha256": owner.fingerprint,
                                            "username": "root", "password": "x"}, headers=w.oh)
    assert r.status_code == 403


def test_totp_second_factor(w, owner, owner_engine):
    uid = tfa_user(owner)
    s = sign_in(w, owner, user="mfa", realm="pve", password="Mfa-Pass-1")
    assert s["state"] == "need_tfa" and s["tfa_methods"] == ["totp", "recovery"] and not s["webauthn_only"]
    assert w.ad.get(f"{H}/pve-sessions/{s['id']}/inventory", headers=w.adh).status_code == 409      # nothing works before the second factor
    r = w.ad.post(f"{H}/pve-sessions/{s['id']}/tfa", json={"method": "totp", "code": "000000"}, headers=w.adh)
    assert r.status_code == 401
    r = w.ad.post(f"{H}/pve-sessions/{s['id']}/tfa", json={"method": "totp", "code": "246 810"}, headers=w.adh)
    assert r.status_code == 200 and r.json()["state"] == "ready", r.text
    inv = w.ad.get(f"{H}/pve-sessions/{s['id']}/inventory", headers=w.adh).json()
    assert inv["account"]["ok"] is True and inv["cluster"]["nodes_total"] == 6
    assert "246810" not in dump(owner_engine) and "Mfa-Pass-1" not in dump(owner_engine)
    assert uid in owner.sim.users


def test_recovery_key_is_single_use_and_too_many_wrong_codes_end_the_session(w, owner, rt):
    tfa_user(owner, recovery=("rec-aaaa-1111", "rec-bbbb-2222"))
    s = sign_in(w, owner, user="mfa", realm="pve", password="Mfa-Pass-1")
    assert w.ad.post(f"{H}/pve-sessions/{s['id']}/tfa", json={"method": "recovery", "code": "rec-aaaa-1111"}, headers=w.adh).status_code == 200
    s2 = sign_in(w, owner, user="mfa", realm="pve", password="Mfa-Pass-1")
    assert w.ad.post(f"{H}/pve-sessions/{s2['id']}/tfa", json={"method": "recovery", "code": "rec-aaaa-1111"}, headers=w.adh).status_code == 401
    for _ in range(adminsession.MAX_TFA_ATTEMPTS - 2):
        assert w.ad.post(f"{H}/pve-sessions/{s2['id']}/tfa", json={"method": "totp", "code": "999999"}, headers=w.adh).status_code == 401
    r = w.ad.post(f"{H}/pve-sessions/{s2['id']}/tfa", json={"method": "totp", "code": "999999"}, headers=w.adh)
    assert r.status_code == 401 and "too many" in r.json()["detail"]
    with rt.session() as db:
        r = adminsession.row(db, s2["id"])
        assert r.state == "failed"
        assert db.execute(text("SELECT status FROM credentials WHERE id = :i"), {"i": str(r.credential_id)}).scalar() == "revoked"
    # the right code no longer helps: the session is gone
    assert w.ad.post(f"{H}/pve-sessions/{s2['id']}/tfa", json={"method": "totp", "code": "246810"}, headers=w.adh).status_code == 409


def test_webauthn_only_account_is_explained_not_attempted(w, owner):
    owner.sim.add_user("key@pve", password="Key-Pass-1", comment="", roles=[("/", "Administrator")])
    owner.sim.users["key@pve"].update({"webauthn": True})
    s = sign_in(w, owner, user="key", realm="pve", password="Key-Pass-1")
    assert s["state"] == "need_tfa" and s["tfa_methods"] == ["webauthn"] and s["webauthn_only"] is True
    r = w.ad.post(f"{H}/pve-sessions/{s['id']}/tfa", json={"method": "totp", "code": "123456"}, headers=w.adh)
    assert r.status_code == 422 and "WebAuthn" in r.json()["detail"]


def test_discovery_reports_tree_and_missing_setup_privileges(w, owner):
    s = sign_in(w, owner)
    inv = w.ad.get(f"{H}/pve-sessions/{s['id']}/inventory", headers=w.adh).json()
    assert {n["name"] for n in inv["nodes"]} >= {"pve06", "pve01"} and inv["cluster"]["version"]
    g = {x["vmid"]: x for x in inv["guests"]}
    assert g[126]["node"] == "pve06" and g[9612]["template"] is True
    assert "PVE06-Storage" in {x["storage"] for x in inv["storages"]} and "officeunbound-pve06" in inv["pools"]
    assert any(n["name"] == "vmbr0" for n in inv["networks"])
    owner.sim.add_user("aud@pve", password="Aud-Pass-1", comment="", roles=[("/", "PVEAuditor")])
    s2 = sign_in(w, owner, user="aud", realm="pve", password="Aud-Pass-1")
    inv2 = w.ad.get(f"{H}/pve-sessions/{s2['id']}/inventory", headers=w.adh).json()
    miss = {(m["path"], m["privilege"]) for m in inv2["account"]["missing"]}
    assert inv2["account"]["ok"] is False and ("/access", "User.Modify") in miss and ("/", "Permissions.Modify") in miss
    assert "pveum acl modify / -user aud@pve" in inv2["account"]["remediation"]


def test_sessions_are_private_to_their_creator(w, owner, rt, mk_user, login):
    s = sign_in(w, owner)
    other, oh = login(mk_user("adm2", "admin"))
    assert other.get(f"{H}/pve-sessions/{s['id']}", headers=oh).status_code == 404
    assert other.get(f"{H}/pve-sessions/{s['id']}/inventory", headers=oh).status_code == 404
    r = other.post(f"{H}/plans", json={"action": "provider.provision.plan_preview", "params": {
        "name": "owner", "base_url": owner.url, "fingerprint_sha256": owner.fingerprint, "admin_session": s["id"], "policy": POLICY}}, headers=oh)
    assert r.status_code == 404


def test_clients_cannot_inject_a_ticket(w, owner):
    r = w.ad.post(f"{H}/plans", json={"action": "provider.provision.plan_preview", "params": {
        "name": "owner", "base_url": owner.url, "fingerprint_sha256": owner.fingerprint, "admin_ticket": "PVE:root@pam:1::x", "admin_csrf": "abcdefgh",
        "admin_ticket_user": "root@pam", "policy": POLICY}}, headers=w.adh)
    assert r.status_code == 422 and "set by the server" in r.text


def test_a_session_is_never_used_for_another_address_or_anchor(w, owner, owner2):  # noqa: F811
    s = sign_in(w, owner)
    for over in ({"base_url": owner2.url, "fingerprint_sha256": owner2.fingerprint}, {"fingerprint_sha256": "ab" * 32}):
        params = {"name": "owner", "base_url": owner.url, "fingerprint_sha256": owner.fingerprint, "admin_session": s["id"], "policy": POLICY, **over}
        r = w.ad.post(f"{H}/plans", json={"action": "provider.provision.plan_preview", "params": params}, headers=w.adh)
        assert r.status_code == 422 and "different address or certificate" in r.text
    assert not owner2.sim.seen or all(p != "/access/ticket" or m != "POST" for m, p in owner2.sim.seen)


def test_full_setup_through_a_totp_session_registers_the_restricted_integration(w, owner, rt, owner_engine):
    tfa_user(owner)
    s = sign_in(w, owner, user="mfa", realm="pve", password="Mfa-Pass-1")
    assert w.ad.post(f"{H}/pve-sessions/{s['id']}/tfa", json={"method": "totp", "code": "246810"}, headers=w.adh).status_code == 200
    base = {"name": "owner", "base_url": owner.url, "fingerprint_sha256": owner.fingerprint, "admin_session": s["id"]}
    p, j = run_as_admin(w, "provider.provision.plan_preview", {**base, "policy": POLICY})
    assert j["status"] == "succeeded", j
    pv = j["result"]
    p2, j2 = run_as_admin(w, "provider.provision.apply", {**base, "preview_id": pv["preview_id"], "plan_hash": pv["plan_hash"]})
    assert p2["risk"] == "high" and j2["status"] == "succeeded", j2
    assert "ics-svc@pve!ics-prov" in owner.sim.tokens                    # the restricted service identity, not the admin, is what the ICS keeps
    with rt.session() as db:
        assert adminsession.row(db, s["id"]).state == "used"               # applied -> the sign-in is destroyed
        tmp = db.execute(text("SELECT status, length(secret_enc) AS n FROM credentials WHERE purpose = 'temporary_provisioning'")).all()
        assert tmp and all(r.status == "revoked" and r.n == 0 for r in tmp)
    assert w.ad.get(f"{H}/pve-sessions/{s['id']}/inventory", headers=w.adh).status_code == 409
    d = dump(owner_engine)
    assert "Mfa-Pass-1" not in d and "246810" not in d and "PVE:mfa@pve:" not in d


def test_expired_sessions_are_swept(w, owner, rt):
    s = sign_in(w, owner)
    with rt.session() as db:
        db.execute(text("UPDATE pve_admin_sessions SET expires_at = now() - interval '1 second' WHERE id = :i"), {"i": s["id"]})
        db.commit()
    from ics.actions import reap_expired
    reap_expired(rt)
    with rt.session() as db:
        r = adminsession.row(db, s["id"])
        assert r.state == "expired"
        assert db.execute(text("SELECT length(secret_enc) FROM credentials WHERE id = :i"), {"i": str(r.credential_id)}).scalar() == 0


def test_sign_out_destroys_the_ticket(w, owner, rt):
    s = sign_in(w, owner)
    assert w.ad.delete(f"{H}/pve-sessions/{s['id']}", headers=w.adh).json()["credential"] == "destroyed"
    with rt.session() as db:
        r = adminsession.row(db, s["id"])
        assert r.state == "cancelled"


def test_tls_lookup_offers_the_fingerprint_for_a_private_certificate(w, owner):
    r = w.ad.post(f"{H}/pve-sessions/tls", json={"base_url": owner.url}, headers=w.adh).json()
    assert r["presented_fingerprint_sha256"] == owner.fingerprint and r["public_ca"] is False and "System > Certificates" in r["verify_hint"]


def test_sign_in_attempts_are_rate_limited(w, owner):
    for _ in range(10):
        sign_in(w, owner, password="nope-nope", expect=401)
    r = w.ad.post(f"{H}/pve-sessions", json={"base_url": owner.url, "trust": "fingerprint", "fingerprint_sha256": owner.fingerprint,
                                             "username": "root", "password": owner.sim.ROOT_PW}, headers=w.adh)
    assert r.status_code == 429


def test_new_connection_plans_take_address_and_anchor_from_the_sign_in(w, owner):  # noqa: F811
    s = sign_in(w, owner)
    p, j = run_as_admin(w, "provider.provision.plan_preview", {"name": "owner", "admin_session": s["id"], "policy": POLICY})
    assert j["status"] == "succeeded", j
    with w.rt.session() as db:
        params = db.execute(text("SELECT params FROM plans WHERE id = :i"), {"i": p["plan_id"]}).scalar()
    assert params["base_url"] == owner.url and params["fingerprint_sha256"] == owner.fingerprint
