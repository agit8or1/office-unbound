"""Mailbox administration (agent BE): aliases, shared mailboxes + grants, mail and storage quotas. Runs the real worker, approvals, vault and audit against
in-memory fakes of the node agent (a model of the helper's rules in agent/ou_agent/mbxhelper.py) and of the OpenCloud Graph client."""
import json
import uuid

import pytest
from pydantic import ValidationError
from sqlalchemy import text

from ics import identity, mailadmin, worker
from ics.identity import IdentityError
from ics.tenant_admin import service

from .test_identity import KC_SECRET, LDAP_PW, stack_params, world  # noqa: F401  (fixture)
from .test_tenant_admin import H, T, Realm, Tenant, run_jobs

OC_PW = "oc-quota-secret-12345"


class Node:
    """What the gromox node holds: users, aliases, shared mailboxes, quota props, grants. Mirrors the helper's validation and refusals."""

    def __init__(self):
        self.users = {"alice": {}, "bob": {}, "carol": {}}
        self.aliases: dict[str, str] = {}
        self.shared: dict[str, dict] = {}
        self.quota: dict[str, dict] = {}
        self.calls: list = []
        self.fail_next = None

    def call(self, rt, node_id, action, params, known):
        self.calls.append((action, params))
        if self.fail_next:
            msg, self.fail_next = self.fail_next, None
            raise IdentityError(msg)
        from ou_agent import mbxspec
        params = mbxspec.CHECKS[action](params)   # the REAL closed-shape validation of the agent
        dom = "acme.test"
        if action == "gromox.set_aliases":
            u = params["user"]
            for a in params["aliases"]:
                if a.split("@")[1] not in (dom, "acme-alt.test"):
                    raise IdentityError("gromox.set_aliases: refused by the node: alias domain is not one of this mailbox system's domains")
                if self.aliases.get(a, f"{u}@{dom}") != f"{u}@{dom}" or a.split("@")[0] in self.users and a.endswith("@" + dom):
                    raise IdentityError("gromox.set_aliases: refused by the node: an alias belongs to another mailbox")
            self.aliases = {a: m for a, m in self.aliases.items() if m != f"{u}@{dom}"}
            self.aliases.update({a: f"{u}@{dom}" for a in params["aliases"]})
            return {"mail": f"{u}@{dom}", "aliases": sorted(a for a, m in self.aliases.items() if m == f"{u}@{dom}")}
        if action == "gromox.shared_create":
            n = params["name"]
            if n in self.shared or n in self.users:
                raise IdentityError("gromox.shared_create: refused by the node: a mailbox with this name already exists")
            self.shared[n] = {"full_access": set(), "send_as": set(), "send_on_behalf": set(), "suspended": False}
            return {"mail": f"{n}@{dom}", "address_status": 4}
        if action == "gromox.shared_delete":
            self.shared[params["name"]].update(suspended=True, full_access=set(), send_as=set(), send_on_behalf=set())
            return {"mail": f"{params['name']}@{dom}", "suspended": True, "data_retained": True}
        if action == "gromox.shared_access":
            s = self.shared[params["name"]]
            (s[params["kind"]].add if params["grant"] else s[params["kind"]].discard)(f"{params['user']}@{dom}")
            return {"members": {k: sorted(s[k]) for k in mbxspec.KINDS}}
        if action == "gromox.set_quota":
            self.quota[params["user"]] = {k: params[k] for k in ("send_kb", "receive_kb", "storage_kb")}
            return {"mail": f"{params['user']}@{dom}", **self.quota[params["user"]], "used_bytes": 1234}
        if action == "gromox.mail_usage":
            return {"usage": {u: {**self.quota.get(u, {"send_kb": None, "receive_kb": None, "storage_kb": None}), "used_bytes": 1000} for u in params["users"]}}
        raise AssertionError(action)


class FakeOC:
    drives: dict = {}
    patched: list = []

    def __init__(self, rt, stack):
        assert stack.oc_pw == OC_PW and stack.cfg["oc_quota_user"] == "svc-quota"

    def close(self): pass
    def personal_drives(self): return {k: dict(v) for k, v in FakeOC.drives.items()}

    def set_total(self, drive_id, total):
        FakeOC.patched.append((drive_id, total))
        for v in FakeOC.drives.values():
            if v["drive_id"] == drive_id:
                v["total"] = total


@pytest.fixture()
def mt(client, mk_user, login, rt, world, monkeypatch):  # noqa: F811
    service._JWKS.clear()
    op, oh = login(mk_user("root", "admin"))
    realm = Realm("acme")
    monkeypatch.setitem(service.HOOKS, "fetch_jwks", lambda cfg: realm.jwks)
    monkeypatch.setitem(service.HOOKS, "live", lambda rt_, stack, sub, role: realm.enabled.get(sub, False))
    node = Node()
    monkeypatch.setattr(identity, "agent_call", node.call)
    FakeOC.drives, FakeOC.patched = {}, []
    monkeypatch.setattr(mailadmin, "_oc", lambda rt_, stack: FakeOC(rt_, stack))
    p = stack_params(name="acme", kc_realm="acme", mail_domain="acme.test", alias_domains=["acme-alt.test"], probe_client_id="ou-probe",
                     oc_quota_user="svc-quota", oc_quota_password=OC_PW, ldap_people_dn="ou=people,dc=acme,dc=test", ldap_groups_dn="ou=groups,dc=acme,dc=test",
                     ldap_bind_dn="cn=svc-ics,ou=system,dc=acme,dc=test")
    m = identity.StackRegister.model_validate(p)
    cfg = m.model_dump(mode="json", exclude={"ldap_bind_password", "kc_client_secret", "mas_client_secret", "oc_quota_password"})
    sid = str(uuid.uuid4())
    enc = rt.vault.encrypt(json.dumps({"ldap_bind_password": LDAP_PW, "kc_client_secret": KC_SECRET, "oc_quota_password": OC_PW}).encode(), identity.stack_aad(sid, cfg))
    cid = str(uuid.uuid4())
    with rt.session() as d:
        d.execute(text("INSERT INTO customers (id, name, msp_owned, provisioning_mode) VALUES (:i, 'Acme Ltd', true, 'auto')"), {"i": cid})
        d.execute(text("INSERT INTO idm_stacks (id, name, config, secret_enc) VALUES (:i, 'acme', CAST(:c AS jsonb), :s)"), {"i": sid, "n": "acme", "c": json.dumps(cfg), "s": enc})
        d.commit()
    r = op.post(f"{H}/customers/{cid}/tenant-admin", headers=oh, json={"stack": "acme", "app_groups": {"mail": "mail-users", "files": "files-users"}})
    assert r.status_code == 201, r.text
    t = Tenant(client, oh, realm, "acme", "acme")
    t.key, t.cid = r.json()["service_key"], cid
    t.node, t.client, t.rt = node, client, rt
    for uid in ("alice", "bob", "carol"):
        assert client.post(f"{T}/users", headers=t.hdr("adm1"), json={"uid": uid, "display_name": f"{uid.title()} Example", "apps": {"mail": True, "files": True}}).status_code == 202
    run_jobs(rt)
    return t


def do(mt, method, path, who="adm1", **kw):
    r = getattr(mt.client, method)(f"{T}{path}", headers=mt.hdr(who), **kw)
    if r.status_code == 202:
        run_jobs(mt.rt)
    return r


def last_state(mt, r):
    return mt.client.get(f"{T}/requests/{r.json()['id']}", headers=mt.hdr()).json()


# ---- validation ---------------------------------------------------------------------------------------------------------------------
def test_models_are_closed_and_strict():
    S = "acme"
    for bad in ({"add": [], "remove": []}, {"add": ["x"]}, {"add": ["a@b.test"], "remove": ["a@b.test"]}, {"add": ["a b@x.test"]}, {"add": ["a@x.test"] * 1 + ["Bob;rm@x.test"]},
                {"add": ["a@x.test"], "extra": 1}):
        with pytest.raises(ValidationError):
            mailadmin.SetAliases.model_validate({"stack": S, "uid": "alice", **bad})
    assert mailadmin.SetAliases.model_validate({"stack": S, "uid": "alice", "add": ["Sales@X.test", "sales@x.test"]}).add == ["sales@x.test"]
    for bad in ({"name": "A b"}, {"name": "x"}, {"name": "ok", "display_name": "<b>"}, {"name": "ok", "display_name": " lead"}):
        with pytest.raises(ValidationError):
            mailadmin.SharedCreate.model_validate({"stack": S, "display_name": "Support", **bad})
    for bad in ({"kind": "admin"}, {"kind": "full_access", "uid": "Bob"}, {"kind": "full_access", "extra": 1}):
        with pytest.raises(ValidationError):
            mailadmin.SharedAccess.model_validate({"stack": S, "name": "support", "uid": "bob", **{"kind": "full_access", **bad}})
    for bad in ({"limit_mb": 0}, {"limit_mb": -1}, {"limit_mb": 10_000_001}, {"limit_mb": None, "send_mb": 5}, {"limit_mb": 5, "send_mb": "x"}):
        with pytest.raises(ValidationError):
            mailadmin.SetMailQuota.model_validate({"stack": S, "uid": "alice", **bad})
    assert mailadmin.SetMailQuota.model_validate({"stack": S, "uid": "alice", "limit_mb": 10, "send_mb": 8}).effective() == {"send_kb": 8192, "receive_kb": 10240, "storage_kb": 10240}
    assert mailadmin.SetMailQuota.model_validate({"stack": S, "uid": "alice", "limit_mb": None}).effective() == {"send_kb": None, "receive_kb": None, "storage_kb": None}
    with pytest.raises(ValidationError):
        mailadmin.SetStorageQuota.model_validate({"stack": S, "uid": "alice", "quota_mb": 0})
    with pytest.raises(ValidationError):
        identity.StackRegister.model_validate(stack_params(oc_quota_user="svc-quota"))                 # user without password
    with pytest.raises(ValidationError):
        identity.StackRegister.model_validate(stack_params(alias_domains=["Bad Domain"]))
    assert "oc-quota" not in repr(identity.StackRegister.model_validate(stack_params(probe_client_id="p", oc_quota_user="svc-quota", oc_quota_password=OC_PW)))


def test_agent_spec_rejects_hostile_parameters():
    from ou_agent import mbxspec
    from ou_agent.proto import Reject
    bad = [("gromox.set_aliases", {"user": "alice", "aliases": ["a@x.test'; DROP TABLE users;--"]}), ("gromox.set_aliases", {"user": "alice", "aliases": ["a@x.test", "a@x.test"]}),
           ("gromox.set_aliases", {"user": "Alice", "aliases": []}), ("gromox.set_aliases", {"user": "alice", "aliases": [], "x": 1}),
           ("gromox.set_aliases", {"user": "../x", "aliases": []}), ("gromox.shared_create", {"name": "ok", "display_name": "a\nb"}),
           ("gromox.shared_access", {"name": "s", "user": "s", "kind": "full_access", "grant": True}), ("gromox.shared_access", {"name": "s", "user": "u", "kind": "root", "grant": True}),
           ("gromox.shared_access", {"name": "s", "user": "u", "kind": "send_as", "grant": "yes"}), ("gromox.set_quota", {"user": "u", "send_kb": 0, "receive_kb": None, "storage_kb": None}),
           ("gromox.set_quota", {"user": "u", "send_kb": 2**31, "receive_kb": None, "storage_kb": None}), ("gromox.set_quota", {"user": "u", "send_kb": True, "receive_kb": None, "storage_kb": None}),
           ("gromox.set_quota", {"user": "u", "send_kb": 1}), ("gromox.mail_usage", {"users": []}), ("gromox.mail_usage", {"users": ["u1"] * 1 + ["Bad"]})]
    for action, params in bad:
        with pytest.raises(Reject):
            mbxspec.CHECKS[action](params)
    ok = mbxspec.CHECKS["gromox.set_aliases"]({"user": "alice", "aliases": ["z@x.test", "a@x.test"]})
    assert ok["aliases"] == ["a@x.test", "z@x.test"]


# ---- aliases ------------------------------------------------------------------------------------------------------------------------
def test_aliases_add_remove_uniqueness_and_domains(mt):
    r = do(mt, "post", "/users/alice/aliases", json={"add": ["Sales@acme.test", "info@acme-alt.test"], "remove": []})
    assert r.status_code == 202 and last_state(mt, r)["state"] == "done"
    assert mt.node.aliases == {"sales@acme.test": "alice@acme.test", "info@acme-alt.test": "alice@acme.test"}
    v = mt.client.get(f"{T}/aliases", headers=mt.hdr()).json()
    assert v["domains"] == ["acme-alt.test", "acme.test"]
    assert [u["aliases"] for u in v["users"] if u["uid"] == "alice"] == [["info@acme-alt.test", "sales@acme.test"]]
    # foreign domain, duplicate with another person, an existing mailbox address, another person's alias: all refused at plan time
    assert do(mt, "post", "/users/alice/aliases", json={"add": ["x@evil.test"]}).status_code == 422
    assert do(mt, "post", "/users/bob/aliases", json={"add": ["sales@acme.test"]}).status_code == 409
    assert do(mt, "post", "/users/bob/aliases", json={"add": ["alice@acme.test"]}).status_code == 409
    assert do(mt, "post", "/users/alice/aliases", json={"remove": ["nope@acme.test"]}).status_code == 422
    assert do(mt, "post", "/users/ghost/aliases", json={"add": ["g@acme.test"]}).status_code == 404
    r = do(mt, "post", "/users/alice/aliases", json={"remove": ["sales@acme.test"]})
    assert last_state(mt, r)["state"] == "done" and list(mt.node.aliases) == ["info@acme-alt.test"]
    assert do(mt, "post", "/users/bob/aliases", json={"add": ["sales@acme.test"]}).status_code == 202   # free again
    with mt.rt.session() as d:
        assert d.execute(text("SELECT count(*) FROM audit_events WHERE action = 'identity.aliases_changed'")).scalar() >= 3


def test_alias_node_refusal_leaves_the_record_unchanged(mt):
    mt.node.fail_next = "gromox.set_aliases: refused by the node: an alias belongs to another mailbox"
    r = do(mt, "post", "/users/alice/aliases", json={"add": ["race@acme.test"]})
    st = last_state(mt, r)
    assert st["state"] == "failed" and "node" in (st["error"] or "")
    with mt.rt.session() as d:
        assert d.execute(text("SELECT count(*) FROM idm_aliases")).scalar() == 0


def test_alias_is_scoped_to_the_customer(mt):
    """an alias that collides with an address of ANOTHER stack of the same customer is refused; another customer is irrelevant."""
    with mt.rt.session() as d:
        cust = d.execute(text("SELECT customer_id FROM idm_stacks WHERE name = 'acme'")).scalar()
        d.execute(text("INSERT INTO idm_stacks (id, name, config, secret_enc, customer_id) VALUES (gen_random_uuid(), 'acme2', CAST(:c AS jsonb), 'x', :k)"),
                  {"c": json.dumps({"mail_domain": "acme.test"}), "k": str(cust)})
        sid = d.execute(text("SELECT id FROM idm_stacks WHERE name = 'acme2'")).scalar()
        d.execute(text("INSERT INTO idm_aliases (stack_id, uid, alias) VALUES (:s, 'zed', 'taken@acme.test')"), {"s": str(sid)})
        d.commit()
    assert do(mt, "post", "/users/alice/aliases", json={"add": ["taken@acme.test"]}).status_code == 409


# ---- shared mailboxes ---------------------------------------------------------------------------------------------------------------
def test_shared_mailbox_lifecycle_and_grants(mt):
    r = do(mt, "post", "/shared", json={"name": "support", "display_name": "Support team"})
    assert r.status_code == 202 and last_state(mt, r)["state"] == "done"
    assert do(mt, "post", "/shared", json={"name": "support", "display_name": "again"}).status_code == 409
    assert do(mt, "post", "/shared", json={"name": "alice", "display_name": "clash"}).status_code == 409
    for kind in ("full_access", "send_as"):
        r = do(mt, "post", "/shared/support/grant", json={"uid": "bob", "kind": kind})
        assert last_state(mt, r)["state"] == "done"
    assert mt.node.shared["support"]["full_access"] == {"bob@acme.test"} and mt.node.shared["support"]["send_as"] == {"bob@acme.test"}
    v = mt.client.get(f"{T}/shared", headers=mt.hdr()).json()
    mb = v["mailboxes"][0]
    assert mb["mail"] == "support@acme.test" and mb["grants"]["full_access"] == ["bob"] and mb["grants"]["send_as"] == ["bob"] and mb["grants"]["send_on_behalf"] == []
    assert do(mt, "post", "/shared/support/grant", json={"uid": "ghost", "kind": "send_as"}).status_code == 404
    assert do(mt, "post", "/shared/support/revoke", json={"uid": "carol", "kind": "full_access"}).status_code == 422
    assert do(mt, "post", "/shared/support/grant", json={"uid": "bob", "kind": "root"}).status_code == 422
    r = do(mt, "post", "/shared/support/revoke", json={"uid": "bob", "kind": "send_as"})
    assert last_state(mt, r)["state"] == "done" and mt.node.shared["support"]["send_as"] == set() and mt.node.shared["support"]["full_access"]
    # delete is high risk: second org-admin required; data is retained and the address can never be reused
    r = do(mt, "post", "/shared/support/delete", json={"reason": "no longer needed"})
    assert r.status_code == 202 and r.json()["state"] == "waiting_admin"
    assert mt.client.post(f"{T}/requests/{r.json()['id']}/approve", headers=mt.hdr("adm1")).status_code == 403
    assert mt.client.post(f"{T}/requests/{r.json()['id']}/approve", headers=mt.hdr("adm2")).status_code == 200
    run_jobs(mt.rt)
    assert last_state(mt, r)["state"] == "done" and mt.node.shared["support"]["suspended"] and not mt.node.shared["support"]["full_access"]
    assert mt.client.get(f"{T}/shared", headers=mt.hdr()).json()["mailboxes"] == []
    assert do(mt, "post", "/shared", json={"name": "support", "display_name": "reuse"}).status_code == 409
    assert do(mt, "post", "/shared/support/grant", json={"uid": "bob", "kind": "send_as"}).status_code == 404


def test_requires_org_admin_and_cross_tenant_isolation(mt):
    for path in ("/aliases", "/shared", "/quotas"):
        assert mt.client.get(f"{T}{path}", headers={"X-OU-Tenant-Key": mt.key}).status_code == 401
        assert mt.client.get(f"{T}{path}", headers=mt.hdr(roles=("user",))).status_code == 403
    assert mt.client.post(f"{T}/shared", headers=mt.hdr(roles=()), json={"name": "x1", "display_name": "x"}).status_code == 403
    assert mt.client.post(f"{T}/users/alice/quota/mail", headers=mt.hdr(roles=()), json={"limit_mb": 5}).status_code == 403


# ---- quotas -------------------------------------------------------------------------------------------------------------------------
def test_mail_quota_set_and_clear(mt):
    r = do(mt, "post", "/users/bob/quota/mail", json={"limit_mb": 50})
    assert last_state(mt, r)["state"] == "done"
    assert mt.node.quota["bob"] == {"send_kb": 51200, "receive_kb": 51200, "storage_kb": 51200}
    q = mt.client.get(f"{T}/quotas", headers=mt.hdr()).json()
    bob = [u for u in q["users"] if u["uid"] == "bob"][0]
    assert bob["mail"]["limit_kb"] == 51200 and bob["mail"]["used_bytes"] == 1000 and q["available"]["mail"] is True
    assert do(mt, "post", "/users/bob/quota/mail", json={"limit_mb": 0}).status_code == 422
    r = do(mt, "post", "/users/bob/quota/mail", json={"limit_mb": None})
    assert mt.node.quota["bob"] == {"send_kb": None, "receive_kb": None, "storage_kb": None}


def test_storage_quota_goes_through_the_files_service(mt):
    with mt.rt.session() as d:
        eid = d.execute(text("SELECT entry_uuid FROM idm_users WHERE uid = 'carol'")).scalar()
    FakeOC.drives = {eid: {"drive_id": "storage$space!carol", "total": 0, "used": 4096}}
    r = do(mt, "post", "/users/carol/quota/files", json={"quota_mb": 2})
    assert last_state(mt, r)["state"] == "done" and FakeOC.patched == [("storage$space!carol", 2 * 1024 * 1024)]
    q = mt.client.get(f"{T}/quotas", headers=mt.hdr()).json()
    c = [u for u in q["users"] if u["uid"] == "carol"][0]
    assert c["files"] == {"used_bytes": 4096, "limit_bytes": 2 * 1024 * 1024} and q["available"]["files"] is True and q["files_quota_supported"] is True
    r = do(mt, "post", "/users/carol/quota/files", json={"quota_mb": None})   # unlimited = 0
    assert FakeOC.patched[-1][1] == 0 and last_state(mt, r)["state"] == "done"
    # a person without a personal drive yet: plain failure, nothing recorded
    r = do(mt, "post", "/users/alice/quota/files", json={"quota_mb": 5})
    st = last_state(mt, r)
    assert st["state"] == "failed" and "personal drive" in st["error"]


def test_storage_quota_unavailable_without_identity(client, mk_user, login, rt, world):  # noqa: F811
    from .test_identity import add_stack
    add_stack(rt)
    with rt.session() as d:
        row = identity._stack_row(d, "acme")
        with pytest.raises(ValueError):
            mailadmin.precheck(d, rt, "idm.user.set_storage_quota", mailadmin.SetStorageQuota(stack="acme", uid="alice", quota_mb=5))
        assert row is not None


def test_opencloud_client_calls_only_the_three_graph_endpoints(rt, monkeypatch):
    seen = []

    class R:
        def __init__(s, code, js): s.status_code, s._j = code, js
        def json(s): return s._j

    class H_:
        def __init__(s, *a, **k): pass
        def close(s): pass
        def post(s, url, data=None, **k):
            seen.append(("POST", url, sorted(data)))
            return R(200, {"access_token": "T"})
        def request(s, method, url, headers=None, params=None, json=None, **k):
            seen.append((method, url, params, json, headers["Authorization"]))
            if method == "GET":
                return R(200, {"value": [{"id": "d1", "owner": {"user": {"id": "u1"}}, "quota": {"total": 10, "used": 3}}, {"id": "d2"}]})
            return R(200, {})

    monkeypatch.setattr(mailadmin.httpx, "Client", H_)
    monkeypatch.setattr(mailadmin, "_guard", lambda rt_, h: None)
    from .test_identity import PEM
    st = identity.Stack(type("R_", (), {"id": "i", "name": "acme", "config": stack_params(probe_client_id="ou-probe", oc_quota_user="svc-quota")})(),
                        {"ldap_bind_password": "x", "kc_client_secret": "y", "oc_quota_password": OC_PW})
    assert PEM
    oc = mailadmin.OpenCloudQuota(rt, st)
    assert oc.personal_drives() == {"u1": {"drive_id": "d1", "total": 10, "used": 3}}
    oc.set_total("storage$a!b", 5)
    assert seen[0][0] == "POST" and seen[0][2] == ["client_id", "grant_type", "password", "scope", "username"]
    assert seen[1][1].endswith("/graph/v1.0/drives") and seen[1][2] == {"$filter": "driveType eq 'personal'"} and seen[1][4] == "Bearer T"
    assert seen[2][0] == "PATCH" and seen[2][1].endswith("/graph/v1.0/drives/storage%24a%21b") and seen[2][3] == {"quota": {"total": 5}}
    with pytest.raises(IdentityError):
        oc.set_total("../../users", 1)


def test_non_tenant_plan_path_and_audit_has_no_secrets(mt):
    r = do(mt, "post", "/users/alice/quota/mail", json={"limit_mb": 7})
    with mt.rt.session() as d:
        blob = json.dumps([dict(x._mapping) for x in d.execute(text("SELECT details FROM audit_events")).all()], default=str)
    assert OC_PW not in blob and LDAP_PW not in blob and KC_SECRET not in blob and r.status_code == 202
    assert worker.run_once is not None
