"""Organization Admin (tenant admin API): service credential + Keycloak token authz, cross-customer denial, role-claim forgery, approval policy,
audit identity, DNS guidance, branding. Runs the real worker against the in-memory LDAP/Keycloak/agent fakes from test_identity."""
import base64
import json
import time
import uuid

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from sqlalchemy import text

from ics import identity, worker
from ics.tenant_admin import dnscheck, jwtv, service

from .test_identity import add_stack, stack_params, world  # noqa: F401  (fixture)

H = "/api/v1"
T = "/api/v1/tenant"


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class Realm:
    """A Keycloak realm stand-in: RSA key + JWKS + token minting."""

    def __init__(self, name):
        self.name = name
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        n = self.key.public_key().public_numbers()
        self.kid = "k-" + name
        self.jwks = {"keys": [{"kty": "RSA", "kid": self.kid, "use": "sig", "alg": "RS256",
                               "n": b64(n.n.to_bytes(256, "big")), "e": b64(n.e.to_bytes(3, "big"))}]}
        self.issuer = f"https://auth.example.test/realms/{name}"
        self.enabled: dict[str, bool] = {}
        self.admins: set[str] = set()      # usernames that hold the org-admin realm role (what target_privileged asks Keycloak)

    def token(self, sub, username, roles=("org-admin",), azp="ou-portal", iss=None, exp=300, iat=None, alg="RS256", key=None, extra=None, typ="Bearer"):
        now = int(time.time()) if iat is None else iat
        claims = {"typ": typ, "sub": sub, "preferred_username": username, "name": username.title(), "iss": iss or self.issuer, "azp": azp, "iat": now, "exp": now + exp,
                  "realm_access": {"roles": list(roles)}, **(extra or {})}
        head = {"alg": alg, "kid": self.kid, "typ": "JWT"}
        body = f"{b64(json.dumps(head).encode())}.{b64(json.dumps(claims).encode())}"
        if alg == "none":
            return body + "."
        sig = (key or self.key).sign(body.encode(), padding.PKCS1v15(), hashes.SHA256())
        return f"{body}.{b64(sig)}"


class Tenant:
    def __init__(self, c, h, realm, name, stack):
        self.c, self.h, self.realm, self.name, self.stack = c, h, realm, name, stack
        self.key = None
        self.subs = {}

    def hdr(self, who="adm1", **kw):
        sub = self.subs.setdefault(who, str(uuid.uuid4()))
        self.realm.enabled[sub] = True
        return {"X-OU-Tenant-Key": self.key, "X-OU-User-Token": self.realm.token(sub, who, **kw)}


@pytest.fixture()
def tn(client, mk_user, login, rt, world, monkeypatch):  # noqa: F811
    service._JWKS.clear()
    service._fails.clear()
    op, oh = login(mk_user("root", "admin"))
    realms = {"acme": Realm("acme"), "globex": Realm("globex")}
    monkeypatch.setitem(service.HOOKS, "fetch_jwks", lambda cfg: realms[cfg["kc_realm"]].jwks)
    monkeypatch.setitem(service.HOOKS, "live", lambda rt_, stack, sub, role: realms[stack.cfg["kc_realm"]].enabled.get(sub, False))
    monkeypatch.setitem(service.HOOKS, "target_privileged", lambda rt_, stack, uid, role: uid in realms[stack.cfg["kc_realm"]].admins)
    monkeypatch.setattr(identity.Keycloak, "reset_mfa", lambda self, kid: 1, raising=False)
    out = {}
    for name in ("acme", "globex"):
        cid = str(uuid.uuid4())
        with rt.session() as d:
            d.execute(text("INSERT INTO customers (id, name, msp_owned, provisioning_mode) VALUES (:i, :n, true, 'auto')"), {"i": cid, "n": name.title() + " Ltd"})
            d.commit()
        add_stack(rt, name=name, kc_realm=name, mail_domain=f"{name}.test", ldap_people_dn=f"ou=people,dc={name},dc=test",
                  ldap_groups_dn=f"ou=groups,dc={name},dc=test", ldap_bind_dn=f"cn=svc-ics,ou=system,dc={name},dc=test",
                  ldap_url=f"ldaps://ldap.{name}.test", files_node_id=str(uuid.uuid4()), gromox_node_id=str(uuid.uuid4()))
        r = op.post(f"{H}/customers/{cid}/tenant-admin", headers=oh, json={"stack": name, "app_groups": {"mail": "mail-users", "files": "files-users"}})
        assert r.status_code == 201, r.text
        t = Tenant(client, oh, realms[name], name, name)
        t.key, t.cid = r.json()["service_key"], cid
        out[name] = t
    out["op"], out["oh"] = op, oh
    out["client"] = client
    return out


def run_jobs(rt):
    while worker.run_once(rt):
        pass


def new_user(tn, t, uid="alice", who="adm1", apps=None):
    return tn["client"].post(f"{T}/users", headers=t.hdr(who), json={"uid": uid, "display_name": f"{uid.title()} Example", "apps": apps or {"mail": True, "files": True}})


# ---- authentication / authorisation -----------------------------------------------------------------------------------------------------
def test_bind_is_admin_only_and_key_shown_once(tn, client, mk_user, login):
    ap, h = login(mk_user("oper", "operator"))
    assert ap.post(f"{H}/customers/{tn['acme'].cid}/tenant-admin", headers=h, json={"stack": "acme"}).status_code == 403
    r = tn["op"].post(f"{H}/customers/{tn['acme'].cid}/tenant-admin", headers=tn["oh"], json={"stack": "acme"})
    assert r.status_code == 409  # already bound
    with tn["op"].app.state.rt.session() as d:
        row = d.execute(text("SELECT key_sha256 FROM tenant_admin_bindings WHERE customer_id = :c"), {"c": tn["acme"].cid}).first()
    assert tn["acme"].key.split(".", 1)[1] not in row.key_sha256 and len(row.key_sha256) == 64   # only a hash is stored


def test_missing_or_bad_credentials(tn):
    c, a = tn["client"], tn["acme"]
    assert c.get(f"{T}/users").status_code == 401
    assert c.get(f"{T}/users", headers={"X-OU-Tenant-Key": "tsk_aaaaaaaaaaaa." + "A" * 43, "X-OU-User-Token": "x"}).status_code == 401
    assert c.get(f"{T}/users", headers={"X-OU-Tenant-Key": a.key}).status_code == 401                       # no user token
    assert c.get(f"{T}/users", headers={"X-OU-Tenant-Key": a.key, "X-OU-User-Token": "a.b.c"}).status_code == 401
    assert c.get(f"{T}/users", headers=a.hdr()).status_code == 200
    # an ICS operator session cookie is not a tenant credential
    assert tn["op"].get(f"{T}/users", headers=tn["oh"]).status_code == 401


def test_cross_customer_denial(tn):
    c, a, g = tn["client"], tn["acme"], tn["globex"]
    # globex's admin presents a perfectly valid token for ITS realm together with ACME's service key -> refused (issuer is taken from acme's binding)
    forged = {"X-OU-Tenant-Key": a.key, "X-OU-User-Token": g.realm.token("s-g", "gadmin")}
    assert c.get(f"{T}/users", headers=forged).status_code == 401
    # and the other way round
    assert c.get(f"{T}/users", headers={"X-OU-Tenant-Key": g.key, "X-OU-User-Token": a.realm.token("s-a", "aadmin")}).status_code == 401
    # data separation: a user and request created in globex are invisible/unknown in acme
    assert new_user(tn, g, "gina").status_code == 202
    pid = c.get(f"{T}/requests", headers=g.hdr()).json()[0]["id"]
    run_jobs(tn["op"].app.state.rt)
    assert c.get(f"{T}/requests/{pid}", headers=a.hdr()).status_code == 404
    assert c.get(f"{T}/users/gina", headers=a.hdr()).status_code == 404
    assert c.get(f"{T}/users", headers=a.hdr()).json() == []
    for p in ("disable", "enable", "delete"):
        assert c.post(f"{T}/users/gina/{p}", headers=a.hdr(), json={"reason": "x"}).status_code in (404, 409, 422)
    assert c.post(f"{T}/requests/{pid}/approve", headers=a.hdr()).status_code == 404
    assert c.post(f"{T}/requests/{pid}/enrollment", headers=a.hdr()).status_code == 404
    assert c.get(f"{T}/users/gina", headers=g.hdr()).status_code == 200


def test_role_claim_forgery_and_token_checks(tn):
    c, a = tn["client"], tn["acme"]
    sub = str(uuid.uuid4())
    base = {"X-OU-Tenant-Key": a.key}
    # no org-admin role -> 403 (and it is audited)
    assert c.get(f"{T}/users", headers={**base, "X-OU-User-Token": a.realm.token(sub, "pleb", roles=("user",))}).status_code == 403
    # role forged by editing the payload of a valid token (signature no longer matches)
    good = a.realm.token(sub, "pleb", roles=("user",))
    h_, p_, s_ = good.split(".")
    claims = json.loads(base64.urlsafe_b64decode(p_ + "=="))
    claims["realm_access"]["roles"].append("org-admin")
    forged = f"{h_}.{b64(json.dumps(claims).encode())}.{s_}"
    assert c.get(f"{T}/users", headers={**base, "X-OU-User-Token": forged}).status_code == 401
    # a token signed with an attacker's own key but the right kid / issuer / role
    evil = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert c.get(f"{T}/users", headers={**base, "X-OU-User-Token": a.realm.token(sub, "evil", key=evil)}).status_code == 401
    # alg=none, HS256 confusion, wrong azp, wrong issuer, expired, absurd lifetime, other realm's issuer string
    assert c.get(f"{T}/users", headers={**base, "X-OU-User-Token": a.realm.token(sub, "x", alg="none")}).status_code == 401
    assert c.get(f"{T}/users", headers={**base, "X-OU-User-Token": a.realm.token(sub, "x", alg="HS256")}).status_code == 401
    assert c.get(f"{T}/users", headers={**base, "X-OU-User-Token": a.realm.token(sub, "x", azp="account")}).status_code == 401
    assert c.get(f"{T}/users", headers={**base, "X-OU-User-Token": a.realm.token(sub, "x", iss="https://auth.example.test/realms/globex")}).status_code == 401
    assert c.get(f"{T}/users", headers={**base, "X-OU-User-Token": a.realm.token(sub, "x", iat=int(time.time()) - 4000)}).status_code == 401
    assert c.get(f"{T}/users", headers={**base, "X-OU-User-Token": a.realm.token(sub, "x", exp=86400)}).status_code == 401
    with tn["op"].app.state.rt.session() as d:
        n = d.execute(text("SELECT count(*) FROM audit_events WHERE action = 'tenant.auth_failed'")).scalar()
    assert n >= 9
    # review 6 L2: a flat top-level `roles` claim does NOT grant the role, and an ID token is not an access token
    flat = a.realm.token(sub, "flat", roles=(), extra={"roles": ["org-admin"]})
    assert c.get(f"{T}/users", headers={**base, "X-OU-User-Token": flat}).status_code == 403
    assert c.get(f"{T}/users", headers={**base, "X-OU-User-Token": a.realm.token(sub, "idt", typ="ID")}).status_code == 401


def test_disabled_admin_cannot_change_anything_but_valid_token_can_read(tn):
    a = tn["acme"]
    h = a.hdr("adm1")
    a.realm.enabled[a.subs["adm1"]] = False          # disabled / role removed in Keycloak after the token was issued
    assert tn["client"].get(f"{T}/users", headers=h).status_code == 200      # reads are limited by the 5-minute token life
    r = tn["client"].post(f"{T}/users", headers=h, json={"uid": "bob", "display_name": "Bob", "apps": {"mail": True}})
    assert r.status_code == 403


# ---- user lifecycle through the policy --------------------------------------------------------------------------------------------------
def test_create_user_auto_approved_executes_audited_and_link_is_one_time(tn, rt, world):  # noqa: F811
    c, a = tn["client"], tn["acme"]
    r = new_user(tn, a, "alice")
    assert r.status_code == 202 and r.json()["approval_mode"] == "auto" and r.json()["state"] == "working"
    pid = r.json()["id"]
    run_jobs(rt)
    st = c.get(f"{T}/requests/{pid}", headers=a.hdr()).json()
    assert st["state"] == "done", st
    assert "alice" in world.ldap and world.ldap["alice"]["groups"] == {"mail-users", "files-users"}
    u = c.get(f"{T}/users/alice", headers=a.hdr()).json()
    assert u["mail"] == "alice@acme.test" and u["apps"] == {"mail": True, "files": True} and u["state"] == "active"
    e = c.post(f"{T}/requests/{pid}/enrollment", headers=a.hdr())
    assert e.status_code == 200 and e.json()["token"] and e.json()["uid"] == "alice"
    assert c.post(f"{T}/requests/{pid}/enrollment", headers=a.hdr()).status_code == 409           # once only
    with rt.session() as d:   # audit carries the END USER's identity, and no token
        ev = d.execute(text("SELECT action, actor_name, details FROM audit_events WHERE action LIKE 'tenant.%' AND resource_id = :p ORDER BY seq"), {"p": pid}).all()
        blob = json.dumps([dict(x._mapping) for x in d.execute(text("SELECT details FROM audit_events")).all()], default=str)
    acts = [x.action for x in ev]
    assert "tenant.request" in acts and "tenant.auto_approved" in acts and "tenant.enrollment_link_shown" in acts
    assert ev[0].actor_name == "tenant:adm1" and ev[0].details["tenant_user"] == "adm1" and ev[0].details["tenant_user_sub"] == a.subs["adm1"]
    assert e.json()["token"] not in blob
    assert "service_key" not in blob and a.key.split(".", 1)[1] not in blob


def test_groups_and_privilege_limits(tn, rt, world):  # noqa: F811
    c, a = tn["client"], tn["acme"]
    new_user(tn, a, "alice", apps={"mail": True})
    run_jobs(rt)
    assert c.post(f"{T}/users/alice/groups", headers=a.hdr(), json={"add": ["files-admin"]}).status_code == 422     # privileged: never tenant-assignable
    assert c.post(f"{T}/users/alice/groups", headers=a.hdr(), json={"add": ["not-a-group"]}).status_code == 422
    r = c.post(f"{T}/users/alice/groups", headers=a.hdr(), json={"add": ["files-users"]})
    assert r.status_code == 202
    run_jobs(rt)
    assert world.ldap["alice"]["groups"] == {"mail-users", "files-users"}
    g = {x["name"]: x for x in c.get(f"{T}/groups", headers=a.hdr()).json()}
    assert set(g) == {"mail-users", "files-users"} and g["files-users"]["members"] == 1
    assert c.post(f"{T}/users", headers=a.hdr(), json={"uid": "bob", "display_name": "Bob", "groups": ["files-admin"]}).status_code == 422


def test_disable_enable_reset_and_self_protection(tn, rt, world):  # noqa: F811
    c, a = tn["client"], tn["acme"]
    new_user(tn, a, "alice")
    run_jobs(rt)
    h = a.hdr()
    assert c.post(f"{T}/users/adm1/disable", headers=h, json={}).status_code == 409                       # not yourself
    assert c.post(f"{T}/users/adm1/delete", headers=h, json={}).status_code == 409
    world.kc["alice"] = {"id": "kc-alice", "username": "alice", "enabled": True, "sessions": 0, "offline": 0}
    assert c.post(f"{T}/users/alice/reset", headers=h, json={"what": "mfa"}).status_code == 202
    assert c.post(f"{T}/users/alice/reset", headers=h, json={"what": "password"}).status_code == 202
    assert c.post(f"{T}/users/alice/reset", headers=h, json={"what": "root"}).status_code == 422
    run_jobs(rt)
    reqs = c.get(f"{T}/requests", headers=h).json()
    assert [x["state"] for x in reqs if x["kind"].startswith("user.reset")] == ["done", "done"]
    d = c.post(f"{T}/users/alice/disable", headers=h, json={"reason": "left the company"})
    assert d.status_code == 202
    run_jobs(rt)
    assert world.ldap["alice"]["locked"] is True
    assert c.get(f"{T}/users/alice", headers=h).json()["state"] == "disabled"
    assert c.post(f"{T}/users/alice/enable", headers=h, json={}).status_code == 202
    run_jobs(rt)
    assert world.ldap["alice"]["locked"] is False


def test_delete_needs_a_second_org_admin(tn, rt, world):  # noqa: F811
    c, a = tn["client"], tn["acme"]
    new_user(tn, a, "alice")
    run_jobs(rt)
    c.post(f"{T}/users/alice/disable", headers=a.hdr(), json={})
    run_jobs(rt)
    r = c.post(f"{T}/users/alice/delete", headers=a.hdr(), json={"reason": "offboarding"})
    assert r.status_code == 202 and r.json()["state"] == "waiting_admin" and r.json()["risk"] == "high"
    pid = r.json()["id"]
    run_jobs(rt)
    assert "alice" in world.ldap                                                                              # nothing ran
    assert c.post(f"{T}/requests/{pid}/approve", headers=a.hdr("adm1")).status_code == 403                    # the requester cannot approve
    assert c.get(f"{T}/requests/{pid}", headers=a.hdr("adm1")).json()["can_decide"] is False
    assert c.get(f"{T}/requests/{pid}", headers=a.hdr("adm2")).json()["can_decide"] is True
    assert c.post(f"{T}/requests/{pid}/approve", headers=tn["globex"].hdr("adm2")).status_code == 404         # other customer's admin cannot
    ok = c.post(f"{T}/requests/{pid}/approve", headers=a.hdr("adm2"))
    assert ok.status_code == 200
    assert c.post(f"{T}/requests/{pid}/approve", headers=a.hdr("adm3")).status_code == 409                    # decided once
    run_jobs(rt)
    assert "alice" not in world.ldap
    assert c.get(f"{T}/requests/{pid}", headers=a.hdr()).json()["decided_by"] == "adm2"
    with rt.session() as d:
        approver = d.execute(text("SELECT details FROM audit_events WHERE action = 'tenant.approved'")).first()
    assert approver.details["tenant_user"] == "adm2"


def test_delete_can_require_the_service_provider(tn, rt, world, mk_user, login):  # noqa: F811
    rt_ = tn["op"].app.state.rt
    with rt_.session() as d:
        d.execute(text("UPDATE tenant_admin_bindings SET policy = jsonb_set(policy, '{destructive_approval}', '\"msp\"') WHERE customer_id = :c"), {"c": tn["acme"].cid})
        d.commit()
    c, a = tn["client"], tn["acme"]
    new_user(tn, a, "alice")
    run_jobs(rt)
    c.post(f"{T}/users/alice/disable", headers=a.hdr(), json={})
    run_jobs(rt)
    r = c.post(f"{T}/users/alice/delete", headers=a.hdr(), json={"reason": "offboarding"}).json()
    assert r["state"] == "waiting_msp"
    assert c.post(f"{T}/requests/{r['id']}/approve", headers=a.hdr("adm2")).status_code == 409               # org admins cannot approve an MSP-gated request
    # the MSP approves it in the ICS console (a normal approver who is not the tenant principal): ONE approval is the tenant tier
    ap, h = login(mk_user("msp-approver", "approver"))
    ok = ap.post(f"{H}/plans/{r['id']}/approve", headers=h)
    assert ok.status_code == 200 and ok.json()["status"] == "approved" and ok.json()["approvals_required"] == 1
    run_jobs(rt)
    assert "alice" not in world.ldap


def test_policy_can_require_second_admin_for_everything(tn, rt, world):  # noqa: F811
    with rt.session() as d:
        d.execute(text("UPDATE tenant_admin_bindings SET policy = jsonb_set(policy, '{self_service_auto}', 'false') WHERE customer_id = :c"), {"c": tn["acme"].cid})
        d.commit()
    c, a = tn["client"], tn["acme"]
    r = new_user(tn, a, "alice").json()
    assert r["approval_mode"] == "second_admin" and r["state"] == "waiting_admin"
    run_jobs(rt)
    assert "alice" not in world.ldap
    assert c.post(f"{T}/requests/{r['id']}/approve", headers=a.hdr("adm2")).status_code == 200
    run_jobs(rt)
    assert "alice" in world.ldap


def test_tenant_plans_are_scoped_in_the_operator_console_and_principals_cannot_log_in(tn, rt, mk_user, login):
    new_user(tn, tn["acme"], "alice")
    with rt.session() as d:
        pr = d.execute(text("SELECT username, enrolled, password_hash FROM users WHERE username LIKE 'tenant-%'")).all()
        cust = d.execute(text("SELECT customer_id FROM plans WHERE action = 'idm.user.create'")).scalar()
    assert len(pr) == 4 and all(not p.enrolled and p.password_hash is None for p in pr)
    assert str(cust) == tn["acme"].cid
    r = tn["client"].post(f"{H}/auth/login", json={"username": pr[0].username, "password": "x" * 14, "totp_code": "123456"})
    assert r.status_code == 401


# ---- apps, branding, domains --------------------------------------------------------------------------------------------------------------
def test_branding_and_apps(tn):
    c, a, g = tn["client"], tn["acme"], tn["globex"]
    assert c.put(f"{T}/branding", headers=a.hdr(), json={"accent": "#ffee00"}).status_code == 422          # too light for white text
    assert c.put(f"{T}/branding", headers=a.hdr(), json={"accent": "red"}).status_code == 422
    assert c.put(f"{T}/branding", headers=a.hdr(), json={"display_name": "<b>x"}).status_code == 422
    assert c.put(f"{T}/branding", headers=a.hdr(), json={"display_name": "Acme Brothers", "accent": "#1a5fb4"}).status_code == 200
    bad = c.put(f"{T}/branding/logo", headers=a.hdr(), content=b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>')
    assert bad.status_code == 422
    assert c.put(f"{T}/branding/logo", headers=a.hdr(), content=b"GIF89a....").status_code == 422
    svg = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><circle cx="5" cy="5" r="4" fill="#1a5fb4"/></svg>'
    assert c.put(f"{T}/branding/logo", headers=a.hdr(), content=svg).status_code == 200
    pub = c.get(f"{T}/branding", headers={"X-OU-Tenant-Key": a.key}).json()          # service credential only: any signed-in user's page needs it
    assert pub["display_name"] == "Acme Brothers" and pub["accent"] == "#1a5fb4" and pub["has_logo"] and pub["apps"] == {"mail": True, "files": True}
    lg = c.get(f"{T}/branding/logo", headers={"X-OU-Tenant-Key": a.key})
    assert lg.content == svg and lg.headers["content-type"] == "image/svg+xml" and "sandbox" in lg.headers["content-security-policy"]
    assert c.get(f"{T}/branding", headers={"X-OU-Tenant-Key": g.key}).json()["display_name"] == "Globex Ltd"      # not acme's
    assert c.put(f"{T}/apps", headers=a.hdr(), json={"apps": {"files": False}}).status_code == 200
    assert c.put(f"{T}/apps", headers=a.hdr(), json={"apps": {"telephony": True}}).status_code == 422
    assert c.get(f"{T}/branding", headers={"X-OU-Tenant-Key": a.key}).json()["apps"] == {"mail": True, "files": False}
    assert c.get(f"{T}/branding", headers={"X-OU-Tenant-Key": g.key}).json()["apps"] == {"mail": True, "files": True}


def test_domains_and_dns_guidance(tn, monkeypatch):
    zone = {("acme.test", "MX"): ["mail.example.test"], ("acme.test", "TXT"): ["v=spf1 include:other -all", "v=spf1 mx -all"],
            ("_dmarc.acme.test", "TXT"): ["v=DMARC1; p=none"], ("autodiscover.acme.test", "CNAME"): ["elsewhere.test"]}

    def fake(name, rtype):
        if name == "default._domainkey.acme.test":
            raise dnscheck.DnsError("down")
        return zone.get((name, rtype), [])
    monkeypatch.setitem(service.HOOKS, "dns", fake)
    r = tn["client"].get(f"{T}/domains?check=true", headers=tn["acme"].hdr()).json()
    st = {x["key"]: x["status"] for x in r["dns"]["acme.test"]}
    assert r["domains"][0]["name"] == "acme.test"
    assert st == {"mx": "ok", "spf": "differs", "dkim": "unknown", "dmarc": "ok", "autodiscover": "differs", "srv_autodiscover": "missing",
                  "srv_imaps": "missing", "srv_submission": "missing", "srv_caldavs": "missing", "srv_carddavs": "missing"}


def test_the_client_setup_srv_records_are_checked_and_optional():
    zone = {("_imaps._tcp.acme.test", "SRV"): ["mail.example.test:993"], ("_submission._tcp.acme.test", "SRV"): ["mail.example.test:25"],
            ("_caldavs._tcp.acme.test", "SRV"): ["other.test:443"]}
    rows = {r["key"]: r for r in dnscheck.check_domain("acme.test", "mail.example.test", "default", resolver=lambda n, t: zone.get((n, t), []))}
    assert rows["srv_imaps"]["status"] == "ok" and rows["srv_imaps"]["optional"] and rows["srv_imaps"]["expected"] == "0 1 993 mail.example.test"
    assert rows["srv_submission"]["status"] == "differs"          # wrong port
    assert rows["srv_caldavs"]["status"] == "differs"             # wrong host
    assert rows["srv_carddavs"]["status"] == "missing" and rows["srv_carddavs"]["name"] == "_carddavs._tcp.acme.test"
    assert not rows["mx"]["optional"]


def test_without_dkim_signing_the_dkim_row_is_not_available_and_not_queried():
    asked = []

    def fake(name, rtype):
        asked.append(name)
        return []
    rows = {r["key"]: r for r in dnscheck.check_domain("acme.test", "mail.example.test", "default", resolver=fake, dkim_available=False)}
    assert rows["dkim"]["status"] == "not_available" and rows["dkim"]["optional"] and rows["dkim"]["expected"] == "-" and rows["dkim"]["found"] == []
    assert not any("_domainkey" in n for n in asked)
    assert {k: r["status"] for k, r in rows.items() if k != "dkim"} == {k: "missing" for k in rows if k != "dkim"}
    with_dkim = {r["key"]: r for r in dnscheck.check_domain("acme.test", "mail.example.test", "default", resolver=fake)}
    assert with_dkim["dkim"]["status"] == "missing" and "default._domainkey.acme.test" in asked     # the default still checks it


def test_the_srv_wire_format_parses_target_and_port():
    import struct
    q = b"\x12\x34\x81\x80" + struct.pack(">HHHH", 1, 1, 0, 0) + b"\x06_imaps\x04_tcp\x04acme\x04test\x00" + struct.pack(">HH", 33, 1)
    target = b"\x04mail\x04acme\x04test\x00"
    rd = struct.pack(">HHH", 0, 1, 993) + target
    msg = q + b"\xc0\x0c" + struct.pack(">HHIH", 33, 1, 300, len(rd)) + rd
    assert dnscheck._parse(msg, 33)[1] == ["mail.acme.test:993"]


def test_jwt_and_dns_wire_helpers():
    r = Realm("x")
    t = r.token("s", "u")
    assert jwtv.verify(t, r.jwks, issuer=r.issuer, client_id="ou-portal")["sub"] == "s"
    assert jwtv.realm_roles({"realm_access": {"roles": ["a"]}, "roles": ["b"]}) == {"a"}   # review 6 L2: the flat claim is ignored
    # DNS response parsing (TXT with compression pointer)
    import struct
    q = b"\x03abc\x04test\x00\x00\x10\x00\x01"
    ans = b"\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x3c" + struct.pack(">H", 9) + b"\x08v=spf1 x"
    msg = struct.pack(">HHHHHH", 1, 0x8180, 1, 1, 0, 0) + q + ans
    assert dnscheck._parse(msg, 16)[1] == ["v=spf1 x"]
    with pytest.raises(dnscheck.DnsError):
        dnscheck.query("bad name!", "TXT")


# ---- review 6 H2: the single-admin takeover chain is refused ----------------------------------------------------------------------------
def _seed_admin(tn, rt, world, uid="boss", t="acme"):  # noqa: F811
    a = tn[t]
    assert new_user(tn, a, uid).status_code == 202
    run_jobs(rt)
    world.kc[uid] = {"id": "kc-" + uid, "username": uid, "enabled": True, "sessions": 0, "offline": 0}
    a.realm.admins.add(uid)
    return a


def _enrollments(rt, uid):
    with rt.session() as d:
        return d.execute(text("SELECT e.* FROM idm_enrollments e JOIN idm_users u ON u.id = e.user_id WHERE u.uid = :u ORDER BY e.created_at"), {"u": uid}).all()


def test_h2_admin_takeover_chain_is_refused(tn, rt, world):  # noqa: F811
    c = tn["client"]
    a = _seed_admin(tn, rt, world)
    before = len(_enrollments(rt, "boss"))
    h1 = a.hdr("adm1")
    # step 1 of the chain: reset the other admin's password -> high risk, waits for a decision, nothing is issued
    r = c.post(f"{T}/users/boss/reset", headers=h1, json={"what": "password"})
    assert r.status_code == 202 and r.json()["risk"] == "high" and r.json()["approval_mode"] != "auto" and r.json()["state"] == "waiting_admin"
    pw = r.json()["id"]
    # step 2: reset MFA of the other admin -> same
    r2 = c.post(f"{T}/users/boss/reset", headers=h1, json={"what": "mfa"})
    assert r2.status_code == 202 and r2.json()["risk"] == "high" and r2.json()["state"] == "waiting_admin"
    mf = r2.json()["id"]
    run_jobs(rt)
    assert len(_enrollments(rt, "boss")) == before                      # no link was minted
    assert c.post(f"{T}/requests/{pw}/enrollment", headers=h1).status_code in (403, 409)
    # never self-approvable, not even under another sub of the same person's session
    assert c.post(f"{T}/requests/{pw}/approve", headers=h1).status_code == 403
    assert c.post(f"{T}/requests/{mf}/approve", headers=h1).status_code == 403
    # re-enable / disable of an administrator is equally a two-person decision
    d = c.post(f"{T}/users/boss/disable", headers=h1, json={"reason": "x"})
    assert d.status_code == 202 and d.json()["risk"] == "high" and d.json()["state"] == "waiting_admin"
    run_jobs(rt)
    assert world.ldap["boss"].get("locked") in (None, False)
    # a genuine second admin approves: it executes, but the requester STILL cannot obtain the link
    assert c.post(f"{T}/requests/{pw}/approve", headers=a.hdr("adm2")).status_code == 200
    run_jobs(rt)
    assert c.get(f"{T}/requests/{pw}", headers=h1).json()["state"] == "done"
    assert len(_enrollments(rt, "boss")) == before + 1
    e = c.post(f"{T}/requests/{pw}/enrollment", headers=h1)
    assert e.status_code == 403 and "token" not in e.text
    with rt.session() as dbs:
        assert dbs.execute(text("SELECT count(*) FROM audit_events WHERE action = 'tenant.enrollment_link_refused'")).scalar() >= 1
    # the account owner gets it through the operator (out of band), once
    op, oh = tn["op"], tn["oh"]
    got = op.post(f"{H}/identity/enrollments/{pw}/deliver", headers=oh)
    assert got.status_code == 200 and got.json()["uid"] == "boss" and got.json()["token"]
    assert op.post(f"{H}/identity/enrollments/{pw}/deliver", headers=oh).status_code == 404


def test_h2_privileged_group_member_is_protected_without_the_role_flag(tn, rt, world):  # noqa: F811
    c = tn["client"]
    a = _seed_admin(tn, rt, world, "carol")
    a.realm.admins.discard("carol")                                    # Keycloak says: no admin role ...
    with rt.session() as d:                                           # ... but the directory says: privileged group member
        d.execute(text("UPDATE idm_users SET groups = CAST(:g AS jsonb) WHERE uid = 'carol'"), {"g": '["files-admin"]'})
        d.commit()
    r = c.post(f"{T}/users/carol/reset", headers=a.hdr("adm1"), json={"what": "mfa"})
    assert r.status_code == 202 and r.json()["risk"] == "high" and r.json()["state"] == "waiting_admin"


def test_h2_target_check_fails_closed_and_ordinary_users_stay_self_service(tn, rt, world, monkeypatch):  # noqa: F811
    c, a = tn["client"], tn["acme"]
    new_user(tn, a, "alice")
    run_jobs(rt)
    world.kc["alice"] = {"id": "kc-alice", "username": "alice", "enabled": True, "sessions": 0, "offline": 0}
    r = c.post(f"{T}/users/alice/reset", headers=a.hdr(), json={"what": "mfa"})
    assert r.status_code == 202 and r.json()["approval_mode"] == "auto" and r.json()["risk"] == "normal"
    # the real hook: any Keycloak error means "privileged"
    class Boom:
        def __init__(self, *a, **k):
            raise identity.IdentityError("down")
    monkeypatch.setattr(identity, "Keycloak", Boom)
    assert service.target_privileged_check(rt, None, "alice", "org-admin") is True


# ---- review 6 M4: unauthenticated failures are throttled and not audited one by one ----------------------------------------------------------
def test_m4_bad_service_credentials_are_throttled_and_cost_no_audit_rows(tn, rt):
    c = tn["client"]
    with rt.session() as d:
        before = d.execute(text("SELECT count(*) FROM audit_events")).scalar()
    codes = [c.get(f"{T}/users", headers={"X-OU-Tenant-Key": "tsk_aaaaaaaaaaaa." + "A" * 43, "X-OU-User-Token": "x"}).status_code for _ in range(service.FAIL_LIMIT + 15)]
    assert codes[:service.FAIL_LIMIT] == [401] * service.FAIL_LIMIT and set(codes[service.FAIL_LIMIT:]) == {429}
    assert c.get(f"{T}/users").status_code == 429                      # a missing key from the same address is throttled too, without a DB write
    with rt.session() as d:
        assert d.execute(text("SELECT count(*) FROM audit_events")).scalar() == before
        assert d.execute(text("SELECT count(*) FROM audit_events WHERE action = 'tenant.auth_failed'")).scalar() == 0
    # the window passes -> the legitimate caller from that address works again
    service._fails.clear()
    assert c.get(f"{T}/users", headers=tn["acme"].hdr()).status_code == 200


def test_m4_summary_row_is_written_at_most_once_per_window(tn, rt, monkeypatch):
    c = tn["client"]
    monkeypatch.setattr(service, "SUMMARY_EVERY", 0.0)
    for _ in range(3):
        c.get(f"{T}/users", headers={"X-OU-Tenant-Key": "tsk_bbbbbbbbbbbb." + "B" * 43, "X-OU-User-Token": "x"})
    with rt.session() as d:
        n = d.execute(text("SELECT count(*) FROM audit_events WHERE action = 'tenant.auth_failed_summary'")).scalar()
    assert n == 3     # with a zero window every failure may flush; with the production window only the first after 300 s does
    monkeypatch.setattr(service, "SUMMARY_EVERY", 300.0)
    service._agg["last_flush"] = time.monotonic()
    for _ in range(5):
        c.get(f"{T}/users", headers={"X-OU-Tenant-Key": "tsk_bbbbbbbbbbbb." + "B" * 43, "X-OU-User-Token": "x"})
    with rt.session() as d:
        assert d.execute(text("SELECT count(*) FROM audit_events WHERE action = 'tenant.auth_failed_summary'")).scalar() == 3


# ---- review 6 L1: SVG allowlist ---------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("svg", [
    b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:x="http://www.w3.org/2000/svg"><x:script>alert(1)</x:script></svg>',
    b'<svg xmlns="http://www.w3.org/2000/svg"><a href="javascript:alert(1)"><circle r="1"/></a></svg>',
    b'<svg xmlns="http://www.w3.org/2000/svg"><a><set attributeName="href" to="java&#x73;cript:alert(1)"/><text>x</text></a></svg>',
    b'<svg xmlns="http://www.w3.org/2000/svg"><use href="https://evil.example/x.svg#a"/></svg>',
    b'<svg xmlns="http://www.w3.org/2000/svg"><circle r="1" style="fill:url(https://evil.example/x)"/></svg>',
    b'<!DOCTYPE svg [<!ENTITY a "b">]><svg xmlns="http://www.w3.org/2000/svg"><text>&a;</text></svg>',
    b'<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><div xmlns="http://www.w3.org/1999/xhtml"/></foreignObject></svg>',
])
def test_l1_svg_allowlist_refuses_scripting_variants(svg):
    with pytest.raises(service.TenantError):
        service.sniff_logo(svg)


def test_l1_plain_svg_is_accepted():
    assert service.sniff_logo(b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><defs><linearGradient id="g"><stop offset="0" stop-color="#fff"/></linearGradient></defs><circle cx="5" cy="5" r="4" fill="url(#g)"/></svg>') == "image/svg+xml"


# ---- review 6 L4 ---------------------------------------------------------------------------------------------------------------------------
def test_l4_logo_upload_is_capped_while_streaming_and_unknown_kid_refetch_is_rate_limited(tn, monkeypatch):
    c, a = tn["client"], tn["acme"]
    r = c.put(f"{T}/branding/logo", headers=a.hdr(), content=b"\x89PNG\r\n\x1a\n" + b"0" * 300_000)
    assert r.status_code == 413
    calls = []
    real = service.HOOKS["fetch_jwks"]
    monkeypatch.setitem(service.HOOKS, "fetch_jwks", lambda cfg: (calls.append(1), real(cfg))[1])
    service._JWKS.clear()
    assert c.get(f"{T}/users", headers=a.hdr()).status_code == 200            # first fetch
    n = len(calls)
    other = Realm("acme")
    other.kid = "k-rotated"                                                   # a kid the JWKS does not know
    for _ in range(5):
        assert c.get(f"{T}/users", headers={"X-OU-Tenant-Key": a.key, "X-OU-User-Token": other.token("s", "x")}).status_code == 401
    assert len(calls) == n                                                    # no refetch storm
