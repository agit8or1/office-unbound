"""Server side of Office Unbound Desktop (ADR-0022, owner decisions 2026-11-25): the realm's public `ou-desktop` client (realm template,
reconciled in place by cfg.keycloak_realm) and the discovery document /.well-known/office-unbound/client.json on the autodiscover name
(configure.client_document -> cfg.gromox `client_document` -> a static file served by the groupware's nginx)."""
import inspect
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
from ou_agent import cfghelper as h  # noqa: E402
from ou_agent import cfgspec as c  # noqa: E402
from ou_agent.proto import Reject  # noqa: E402

from ics.deploy import configure  # noqa: E402

PW = "Abcdefghijklmnop_qrstuv-0123456789"
KEY = configure._rsa_key()


def _desktop(realm: dict) -> dict:
    return next(x for x in realm["clients"] if x["clientId"] == configure.DESKTOP_CLIENT)


# ---------------------------------------------------------------- (a) the ou-desktop client

def test_the_realm_has_a_public_pkce_loopback_client_for_the_desktop_app():
    r = json.loads(configure.realm_json("e2e.example", PW))
    d = _desktop(r)
    assert d["publicClient"] is True and "secret" not in d and d.get("clientAuthenticatorType") in (None, "client-secret")
    assert d["standardFlowEnabled"] is True
    assert not d["implicitFlowEnabled"] and not d["directAccessGrantsEnabled"] and not d["serviceAccountsEnabled"] and not d["bearerOnly"]
    assert d["attributes"]["pkce.code.challenge.method"] == "S256"
    assert d["attributes"]["oauth2.device.authorization.grant.enabled"] == "false" and d["attributes"]["oidc.ciba.grant.enabled"] == "false"
    # RFC 8252 loopback only: Keycloak ignores the port of 127.0.0.1; no https/web redirect, no web origin, no logout redirect
    assert d["redirectUris"] == ["http://127.0.0.1", "http://127.0.0.1/*"] and d["webOrigins"] == []
    assert d["attributes"]["post.logout.redirect.uris"] == ""
    assert "offline_access" in d["optionalClientScopes"] and {"profile", "email"} <= set(d["defaultClientScopes"])
    # OpenCloud maps users by the uuid claim and roles by the flat roles claim: the same mappers as the OpenCloud desktop client
    oc = next(x for x in r["clients"] if x["clientId"] == "OpenCloudDesktop")
    assert [m["name"] for m in d["protocolMappers"]] == [m["name"] for m in oc["protocolMappers"]]
    assert [x["clientId"] for x in r["clients"]].count(configure.DESKTOP_CLIENT) == 1


def test_adding_the_desktop_client_leaves_every_other_template_client_as_it_was():
    r = json.loads(configure.realm_json("e2e.example", PW))
    oc = next(x for x in r["clients"] if x["clientId"] == "OpenCloudDesktop")
    assert oc["redirectUris"] == ["http://127.0.0.1", "http://localhost"]   # what today's app (fallback) uses keeps working
    extra = [{"clientId": "ou-portal", "publicClient": False}]
    r2 = json.loads(configure.realm_json("e2e.example", PW, clients=extra))
    assert [x for x in r2["clients"] if x["clientId"] != "ou-portal"] == r["clients"]


class _FakeKc:
    """Keycloak admin REST as cfg.keycloak_realm uses it: clients by clientId, nothing else changes."""

    def __init__(self, clients):
        self.clients = {x["clientId"]: {**x, "id": f"uuid-{x['clientId']}"} for x in clients}
        self.calls = []

    def __call__(self, method, path, token=None, body=None, form=None, ok=(200, 201, 204)):
        self.calls.append((method, path))
        if path.endswith("/token"):
            return {"access_token": "t"}
        if method == "GET" and path == "/admin/realms/ou":
            return {"realm": "ou"}
        if method == "GET" and "/clients?clientId=" in path:
            cid = path.split("=", 1)[1]
            return [self.clients[cid]] if cid in self.clients else []
        if method == "POST" and path.endswith("/clients"):
            assert body["clientId"] not in self.clients
            self.clients[body["clientId"]] = {**body, "id": f"uuid-{body['clientId']}"}
            return None
        if method == "PUT" and "/clients/" in path:
            cid = next(k for k, v in self.clients.items() if path.endswith("/" + v["id"]))
            self.clients[cid] = body
            return None
        if method == "GET":
            return []
        raise AssertionError(f"unexpected {method} {path}")


def test_the_in_place_realm_reconcile_creates_the_client_once_and_never_touches_other_clients(monkeypatch):
    want = json.loads(configure.realm_json("e2e.example", PW))
    template_ids = {x["clientId"] for x in want["clients"]}
    others = [{"clientId": "admin-cli", "publicClient": True}, {"clientId": "customer-made", "redirectUris": ["https://x.example/*"]}]
    existing = [x for x in want["clients"] if x["clientId"] != configure.DESKTOP_CLIENT] + others
    kc = _FakeKc(existing)
    before = json.loads(json.dumps({k: v for k, v in kc.clients.items() if k not in template_ids}))
    monkeypatch.setattr(h, "_kc", kc)
    monkeypatch.setattr(h, "_kc_ready", lambda: None)
    p = {"realm_json": json.dumps({"realm": "ou", "clients": want["clients"]}), "admin_password": PW}
    done = h.keycloak_realm(c.CHECKS["cfg.keycloak_realm"](p, {}), None)
    assert done["clients_created"] == [configure.DESKTOP_CLIENT]
    assert kc.clients[configure.DESKTOP_CLIENT]["redirectUris"] == ["http://127.0.0.1", "http://127.0.0.1/*"]
    again = h.keycloak_realm(c.CHECKS["cfg.keycloak_realm"](p, {}), None)        # idempotent: a second run creates nothing
    assert again["clients_created"] == [] and configure.DESKTOP_CLIENT in again["clients_updated"]
    assert [x for x in kc.clients.values() if x["clientId"] == configure.DESKTOP_CLIENT].__len__() == 1
    assert {k: v for k, v in kc.clients.items() if k not in template_ids} == before   # admin-cli, customer clients: untouched
    touched = {p for m, p in kc.calls if m in ("POST", "PUT", "DELETE")}
    assert not any("uuid-admin-cli" in p or "uuid-customer-made" in p for p in touched) and not any(m == "DELETE" for m, _ in kc.calls)


# ---------------------------------------------------------------- (b) the discovery document

def _plan(components=("portal", "office", "groupware", "chat"), hosts=None, tenant=None):
    vms = [{"name": "id", "components": ["identity", "edge"]}, {"name": "files", "components": ["files", *[x for x in components if x in ("portal", "office")]]},
           {"name": "gw", "components": [x for x in components if x == "groupware"]},
           {"name": "chat", "components": [x for x in components if x in ("chat", "meetings")]}]
    if tenant:
        for v in vms:
            v["tenant"] = tenant
    p = {"input": {"domain": "e2e.example"}, "vms": vms, "firewall": [], "dns": []}
    if hosts is not None:
        p["names"] = {(tenant or ""): {"domain": f"{tenant}.e2e.example" if tenant else "e2e.example", "hosts": hosts}}
    return p


def test_the_client_document_lists_the_plans_services_and_names_the_desktop_client():
    d = configure.client_document(_plan(), None)
    assert d == {"version": 1, "name": "e2e.example", "issuer": "https://auth.e2e.example/realms/ou", "client_id": "ou-desktop",
                 "auth": "https://auth.e2e.example/", "files": "https://cloud.e2e.example/", "portal": "https://portal.e2e.example/",
                 "office": "https://office.e2e.example/", "mail": "https://mail.e2e.example/web/", "matrix": "https://matrix.e2e.example/",
                 "chat_web": "https://chat.e2e.example/"}
    assert "meet" not in d                                                     # meetings only when deployed
    assert configure.client_document(_plan(("chat", "meetings")), None)["meet"] == "https://meet.e2e.example/"
    small = configure.client_document(_plan(()), None)
    assert set(small) == {"version", "name", "issuer", "client_id", "auth", "files"}


def test_the_client_document_follows_name_settings_and_tenants():
    d = configure.client_document(_plan(hosts={"cloud": "files.corp.example", "auth": "login.corp.example"}), None)
    assert d["files"] == "https://files.corp.example/" and d["issuer"] == "https://login.corp.example/realms/ou"
    t = configure.client_document(_plan(tenant="acme", hosts={}), "acme")
    assert t["name"] == "acme.e2e.example" and t["files"] == "https://cloud.acme.e2e.example/" and t["mail"] == "https://mail.acme.e2e.example/web/"
    assert configure.client_document(_plan(tenant="acme", hosts={}), None) == configure.client_document(_plan(()), None), \
        "the provider scope sees none of the tenant's services"


def test_the_client_document_is_built_from_the_plan_alone_never_from_request_data():
    assert list(inspect.signature(configure.client_document).parameters) == ["plan", "tenant"]   # no request, header or user argument
    plan = _plan()
    a, b = configure.client_document(plan, None), configure.client_document(json.loads(json.dumps(plan)), None)
    assert a == b                                                               # deterministic: the same plan, the same document
    # the nginx location serves one fixed file: no request variable ($host, $uri, $args, ...) is used
    block = h.GW_NGINX[h.GW_NGINX.index("location = /.well-known/office-unbound/client.json"):]
    block = block[:block.index("}}") + 2]
    assert "$" not in block and "try_files /well-known/office-unbound/client.json =404;" in block and "proxy_pass" not in block
    assert "default_type application/json;" in block


def _ctx(monkeypatch, features):
    monkeypatch.setattr(configure, "secret", lambda rt, dep, name, make=None: f"{name}-" + "x" * 20)
    monkeypatch.setattr(configure, "_tls", lambda ctx, vm, *a: {"runbook": "cfg.tls", "params": {}})
    monkeypatch.setattr(configure, "realm_key", lambda rt, dep, t=None: KEY)
    monkeypatch.setattr(configure, "agent_features", lambda ctx_, vm_, rb: features if (vm_, rb) == ("gw", "cfg.gromox") else [])
    agent = type("A", (), {"address": lambda self, vm: "10.0.0.11"})()
    return type("Ctx", (), {"deployment_id": "d1", "rt": None, "slug": "e2e", "plan": _plan(), "env": type("E", (), {"agent": agent})()})()


def test_cfg_gromox_carries_the_document_only_to_agents_that_serve_it(monkeypatch):
    g = next(r["params"] for r in configure.groupware_runbooks(_ctx(monkeypatch, []), "gw") if r["runbook"] == "cfg.gromox")
    assert "client_document" not in g                                          # an older agent's closed schema would refuse it
    g = next(r["params"] for r in configure.groupware_runbooks(_ctx(monkeypatch, ["brand_fonts", "client_document"]), "gw")
             if r["runbook"] == "cfg.gromox")
    assert g["client_document"] == configure.client_document(_plan(), None)
    assert c.check_gromox(g, {"enabled": True}) == g                            # what the ICS sends is what the agent accepts
    assert "client_document" in c.FEATURES["cfg.gromox"] and configure.CLIENT_DOC_FEATURE == "client_document"


@pytest.mark.parametrize("change", [
    {"extra": "x"}, {"version": 2}, {"version": True}, {"version": "1"}, {"files": "http://cloud.e2e.example/"},
    {"files": "https://cloud.e2e.example:8443/"}, {"files": "https://cloud.e2e.example/x"}, {"files": "https://cloud.e2e.example/?a=1"},
    {"mail": "https://mail.e2e.example/"}, {"issuer": "https://auth.e2e.example/realms/master/../ou"}, {"issuer": "http://auth.e2e.example/realms/ou"},
    {"client_id": "Bad Id"}, {"client_id": ""}, {"name": "not a name"}, {"meet": "javascript:alert(1)"}, {"files": None},
])
def test_the_agent_refuses_a_document_outside_its_closed_schema(change):
    doc = {**configure.client_document(_plan(), None), **change}
    if change.get("files", "") is None:
        del doc["files"]
    with pytest.raises(Reject):
        c.check_client_document(doc, "e2e.example")


def test_the_agent_writes_the_document_as_a_world_readable_static_file_and_removes_it(tmp_path, monkeypatch):
    monkeypatch.setattr(h, "BRAND_ROOT", str(tmp_path))
    monkeypatch.setattr(h.os, "chown", lambda *a, **k: None)   # root:root on the VM; the test runs unprivileged
    monkeypatch.setattr(h, "CLIENT_DOC", str(tmp_path / "well-known" / "office-unbound" / "client.json"))
    doc = c.check_client_document(configure.client_document(_plan(), None), "e2e.example")
    h._client_document(doc)
    f = tmp_path / "well-known" / "office-unbound" / "client.json"
    assert json.loads(f.read_text()) == doc and oct(f.stat().st_mode & 0o777) == "0o644"
    h._client_document(None)
    assert not f.exists()


def test_running_deployments_get_the_desktop_client_and_document_with_their_next_change():
    """0.13.9 shipped the realm client and the discovery document without a config_revision bump, so a running deployment's in-place change
    never re-ran the identity and groupware configuration (the preview on officeunbound8 had no step for either). Revision 2 makes it."""
    from ics.deploy.catalog import load_catalog
    cat = load_catalog()
    assert cat.components["identity"].config_revision >= 2
    assert cat.components["groupware"].config_revision >= 2
