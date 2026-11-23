"""Team chat deployed by the ICS (Synapse + MAS + Element Web behind the chat VM's TLS proxy, sign-in through the deployment's Keycloak):
the configuration the engine writes, generated from a real plan, without a node."""
import json
import re

import pytest
import yaml
from cryptography.hazmat.primitives import serialization

from ics.deploy import configure
from ics.deploy.plan import generate_plan
from tests.test_deploy_plan import cap, inp, pinned

DOMAIN = "chat.example"
LAYOUT = [{"name": "id", "components": ["identity", "edge", "portal"]},
          {"name": "files", "components": ["files", "office", "chat"]},
          {"name": "mail", "components": ["groupware"]}]


@pytest.fixture()
def ctx(monkeypatch):
    store = {}

    def fake_secret(rt, dep, name, make=None):
        if name not in store:
            store[name] = (make or (lambda: "s3cret-" + name.replace(":", "-")))()
        return store[name]
    monkeypatch.setattr(configure, "secret", fake_secret)
    p = generate_plan(inp(profile="custom", users=20, domain=DOMAIN, custom_layout=LAYOUT), cap(3), pinned())
    assert p["errors"] == [], p["errors"]
    addr = {v["name"]: f"10.0.0.{i + 10}" for i, v in enumerate(p["vms"])}
    agent = type("A", (), {"address": staticmethod(lambda vm: addr[vm])})()
    c = type("C", (), {"plan": p, "rt": None, "deployment_id": "dep-1", "slug": "dep", "env": type("E", (), {"agent": agent})()})()
    c.store = store
    return c


def _vm(p, comp):
    return next(v["name"] for v in p["vms"] if comp in (v.get("components") or []))


def _files(rbs, volume):
    rb = next(r for r in rbs if r["runbook"] == "cfg.volume_files" and r["params"]["volume"] == volume)
    return {f["path"]: f for f in rb["params"]["files"]}


def test_chat_is_configured_like_the_lab_proved_it(ctx):
    vm = _vm(ctx.plan, "chat")
    rbs = configure.chat_runbooks(ctx, vm)
    kinds = [r["runbook"] for r in rbs]
    assert kinds.count("cfg.pg_db") == 2 and {r["params"]["database"] for r in rbs if r["runbook"] == "cfg.pg_db"} == {"synapse", "mas"}
    hs = yaml.safe_load(_files(rbs, "config")["homeserver.yaml"]["content"])
    assert hs["server_name"] == f"matrix.{DOMAIN}" and hs["report_stats"] is False
    assert hs["enable_registration"] is False and hs["password_config"]["enabled"] is False
    assert hs["listeners"] == [{"port": 8008, "bind_addresses": ["127.0.0.1"], "type": "http", "x_forwarded": True, "resources": [{"names": ["client"]}]}]
    assert hs["federation_domain_whitelist"] == [] and hs["trusted_key_servers"] == []
    assert hs["matrix_authentication_service"]["endpoint"] == "http://127.0.0.1:8080/"
    sk = _files(rbs, "config")["signing.key"]
    assert sk["mode"] == 0o600 and re.fullmatch(r"ed25519 a_[0-9a-f]{4} [A-Za-z0-9+/]{43}\n", sk["content"])
    mas = yaml.safe_load(_files(rbs, "masconfig")["config.yaml"]["content"])
    assert mas["passwords"]["enabled"] is False and mas["account"]["password_registration_enabled"] is False
    assert mas["matrix"]["secret"] == hs["matrix_authentication_service"]["secret"]
    assert mas["http"]["issuer"] == f"https://mas.{DOMAIN}/" and mas["http"]["listeners"][0]["binds"] == [{"address": "127.0.0.1:8080"}]
    serialization.load_pem_private_key(mas["secrets"]["keys"][0]["key"].encode(), password=None)
    assert re.fullmatch(r"[0-9a-f]{64}", mas["secrets"]["encryption"])
    prov = mas["upstream_oauth2"]["providers"][0]
    assert re.fullmatch(r"[0-7][0-9A-HJKMNP-TV-Z]{25}", prov["id"])
    assert prov["issuer"] == f"https://auth.{DOMAIN}/realms/{configure.REALM}" and prov["client_id"] == configure.MATRIX_CLIENT
    assert prov["on_backchannel_logout"] == "logout_all" and prov["pkce_method"] == "always"
    assert prov["claims_imports"]["skip_confirmation"] is True and prov["claims_imports"]["localpart"]["action"] == "require"
    assert "telemetry" not in mas and "sentry" not in _files(rbs, "masconfig")["config.yaml"]["content"]
    assert "BEGIN CERTIFICATE" in _files(rbs, "masconfig")["trust.crt"]["content"]
    front = _files(rbs, "front")["nginx.conf"]["content"]
    assert f"server_name matrix.{DOMAIN};" in front and f"server_name mas.{DOMAIN};" in front and "location /api/admin/ { return 403; }" in front
    el = json.loads(_files(rbs, "front")["config.json"]["content"])
    assert el["default_server_config"]["m.homeserver"]["base_url"] == f"https://matrix.{DOMAIN}" and el["disable_guests"] is True
    assert el["sso_redirect_options"] == {"immediate": True}          # no "Sign in" click: straight through MAS to the portal's Keycloak session
    sites = {r["params"]["server_names"][0]: r["params"]["upstream"] for r in rbs if r["runbook"] == "cfg.nginx_site"}
    assert sites == {f"{h}.{DOMAIN}": "http://127.0.0.1:8070" for h in ("chat", "matrix", "mas")}
    assert not re.search(r"@[A-Z_]+@", front + json.dumps(hs) + json.dumps(mas))       # every template placeholder filled


def test_keycloak_gets_the_chat_client_with_back_channel_logout(ctx):
    rbs = configure.identity_runbooks(ctx, _vm(ctx.plan, "identity"))
    realm = json.loads(next(f["content"] for r in rbs if r["runbook"] == "cfg.volume_files" for f in r["params"]["files"] if f["path"].startswith("import/realm")))
    cl = next(c for c in realm["clients"] if c["clientId"] == configure.MATRIX_CLIENT)
    pid = configure.mas_provider_id(None, "dep-1")
    assert cl["redirectUris"] == [f"https://mas.{DOMAIN}/upstream/callback/{pid}"] and cl["publicClient"] is False
    assert cl["attributes"]["backchannel.logout.url"] == f"https://mas.{DOMAIN}/upstream/backchannel-logout/{pid}"
    assert cl["directAccessGrantsEnabled"] is False and cl["attributes"]["pkce.code.challenge.method"] == "S256"


def test_gateway_serves_and_certifies_the_chat_names(ctx):
    edge = _vm(ctx.plan, "edge")
    names = configure.edge_served_names(ctx.plan, edge, None)
    assert {f"{h}.{DOMAIN}" for h in ("chat", "matrix", "mas")} <= set(names)
    up = {r["params"]["server_names"][0]: r["params"] for r in configure.edge_runbooks(ctx, edge) if r["runbook"] == "cfg.nginx_site"}
    files_ip = ctx.env.agent.address(_vm(ctx.plan, "chat"))
    assert up[f"matrix.{DOMAIN}"]["upstream"] == f"https://{files_ip}:443" and up[f"matrix.{DOMAIN}"]["upstream_name"] == f"matrix.{DOMAIN}"


def test_no_chat_no_chat_client():
    p = generate_plan(inp(profile="custom", users=20, domain=DOMAIN, custom_layout=[LAYOUT[0], {"name": "files", "components": ["files", "office"]}]),
                      cap(3), pinned())
    assert configure.vm_of(p, "chat", None) is None
    assert not {f"matrix.{DOMAIN}"} & set(configure.edge_served_names(p, _vm(p, "edge"), None))


def test_audit_never_sees_chat_secrets(ctx):
    for r in configure.chat_runbooks(ctx, _vm(ctx.plan, "chat")):
        red = json.dumps(configure.redact(r["runbook"], r["params"]))
        for v in ctx.store.values():
            assert v not in red


def test_only_the_portal_and_chat_may_frame_chat_and_sign_in(ctx):
    front = _files(configure.chat_runbooks(ctx, _vm(ctx.plan, "chat")), "front")["nginx.conf"]["content"]
    fa = f"frame-ancestors 'self' https://chat.{DOMAIN} https://portal.{DOMAIN}"
    assert front.count(fa) == 2 and "X-Frame-Options SAMEORIGIN" not in front
    rbs = configure.identity_runbooks(ctx, _vm(ctx.plan, "identity"))
    realm = json.loads(next(f["content"] for r in rbs if r["runbook"] == "cfg.volume_files" for f in r["params"]["files"] if f["path"].startswith("import/realm")))
    csp = realm["browserSecurityHeaders"]["contentSecurityPolicy"]
    assert f"frame-ancestors 'self' https://chat.{DOMAIN} https://mas.{DOMAIN} https://portal.{DOMAIN};" in csp and "*" not in csp


def test_without_chat_keycloak_keeps_its_default_framing():
    assert "browserSecurityHeaders" not in json.loads(configure.realm_json(DOMAIN, "pw"))


def test_self_service_profile_only_with_a_writer_capable_agent(ctx, monkeypatch):
    vm = _vm(ctx.plan, "identity")

    def realm_of(rbs):
        return json.loads(next(f["content"] for r in rbs if r["runbook"] == "cfg.volume_files" for f in r["params"]["files"] if f["path"].startswith("import/realm")))
    old = configure.identity_runbooks(ctx, vm)                               # agent without the feature: unchanged, read-only directory
    ldap = realm_of(old)["components"]["org.keycloak.storage.UserStorageProvider"][0]["config"]
    assert ldap["editMode"] == ["READ_ONLY"] and "svc-bind" in ldap["bindDn"][0]
    assert "writer_password" not in next(r for r in old if r["runbook"] == "cfg.ldap_init")["params"]
    monkeypatch.setattr(configure, "agent_features", lambda c, v, rb: ["writer"] if rb == "cfg.ldap_init" else [])
    rbs = configure.identity_runbooks(ctx, vm)
    init = next(r for r in rbs if r["runbook"] == "cfg.ldap_init")["params"]
    realm = realm_of(rbs)
    prov = realm["components"]["org.keycloak.storage.UserStorageProvider"][0]
    assert prov["config"]["editMode"] == ["WRITABLE"] and prov["config"]["bindDn"][0].startswith("cn=svc-idp,")
    assert prov["config"]["bindCredential"] == [init["writer_password"]] and prov["config"]["usePasswordModifyExtendedOp"] == ["true"]
    maps = {m["name"]: m["config"] for m in prov["subComponents"]["org.keycloak.storage.ldap.mappers.LDAPStorageMapper"]}
    assert maps["email"]["read.only"] == ["true"] and maps["username"]["read.only"] == ["true"] and maps["first name"]["read.only"] == ["false"]
    assert {maps[k]["ldap.attribute"][0] for k in ("displayName", "phone", "mobile")} == {"displayName", "telephoneNumber", "mobile"}
    prof = json.loads(realm["components"]["org.keycloak.userprofile.UserProfileProvider"][0]["config"]["kc.user.profile.config"][0])
    edit = {a["name"]: a["permissions"]["edit"] for a in prof["attributes"]}
    assert edit["email"] == ["admin"] and edit["username"] == ["admin"] and edit["phone"] == ["admin", "user"] and "unmanagedAttributePolicy" not in prof
    assert set(configure.SELF_PROFILE.values()) <= set(__import__("ou_agent.cfghelper", fromlist=["x"]).LDAP_SELF_ATTRS)
    assert configure.redact("cfg.ldap_init", init)["writer_password"] == "[redacted]"
