"""Name settings (plan.py NameSettings), the user portal and single sign-on in the deployed stack, single- and multi-tenant (configure.py).
Owner 2026-11-20: "we need a central portal login ... this can be single tenant or multi tenant but we need to make settings for fqdn"."""
import json
import os
import sys

import pytest
from cryptography import x509

from ics.deploy import configure
from ics.deploy.plan import NameSettings, TenantNames, generate_plan

from .test_deploy_plan import cap, inp, pinned

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
from ou_agent import cfgspec as c  # noqa: E402
from ou_agent.proto import Reject  # noqa: E402


def _dns(p):
    return {(r["name"], r["type"]): r["value"] for r in p["dns"]}


def _ok(p):
    assert p["executable"], p["errors"]
    return p


# ---- plan --------------------------------------------------------------------------------------------------------

def test_defaults_are_the_catalog_names_and_the_portal_is_in_every_stack():
    p = _ok(generate_plan(inp(), cap(), pinned()))
    d = _dns(p)
    assert d[("portal.acme.example", "A")] == d[("auth.acme.example", "A")] == "vm:acme-prod-id"   # through the edge
    assert p["names"][""]["hosts"]["portal"] == "portal.acme.example" and p["names"][""]["domain"] == "acme.example"
    assert any(v["name"] == "acme-prod-id" and "portal" in v["components"] for v in p["vms"])
    assert {c["name"] for c in p["checks"]} >= {"acme-prod-id-portal-portal-ready"}


def test_host_settings_rename_records_targets_and_container_settings():
    p = _ok(generate_plan(inp(names=NameSettings(hosts={"cloud": "files", "mail": "mx.acme-mail.com", "portal": "start"})), cap(), pinned()))
    d = _dns(p)
    assert ("files.acme.example", "A") in d and ("cloud.acme.example", "A") not in d and ("start.acme.example", "A") in d
    assert d[("acme.example", "MX")] == "10 mx.acme-mail.com" and d[("autodiscover.acme.example", "CNAME")] == "mx.acme-mail.com"
    kc = next(r for s in p["steps"] if s["kind"] == "agent_runbook" for r in s["params"].get("runbooks", [])
              if r["runbook"] == "podman.deploy_unit" and r["params"]["component"] == "identity")
    assert kc["params"]["env"]["KC_HOSTNAME"] == "https://auth.acme.example"
    off = next(r for s in p["steps"] if s["kind"] == "agent_runbook" for r in s["params"].get("runbooks", [])
               if r["runbook"] == "podman.deploy_unit" and r["params"]["component"] == "office")
    assert off["params"]["env"]["OU_WOPI_HOST"] == "https://files.acme.example:443"


@pytest.mark.parametrize("names, code", [
    (NameSettings(hosts={"webmail": "mail2"}), "names_unknown_host"),
    (NameSettings(tenants={"t01": TenantNames(domain="a.example")}), "names_unknown_tenant"),          # small is single-tenant
    (NameSettings(hosts={"cloud": "portal"}), "names_duplicate"),                                     # files and portal on one name
])
def test_bad_name_settings_are_refused(names, code):
    p = generate_plan(inp(names=names), cap(), pinned())
    assert not p["executable"] and code in {e["code"] for e in p["errors"]}


def test_a_host_setting_must_be_a_label_or_a_full_name():
    with pytest.raises(ValueError):
        NameSettings(hosts={"cloud": "bad name"})


def _multi(**names):
    return _ok(generate_plan(inp(profile="msp-multi", tenants=2, users=20, names=NameSettings(**names) if names else None),
                             cap(nodes=3, cores=128, mem=1_000_000, sto=20000), pinned()))


def test_each_tenant_gets_its_own_domain_and_portal():
    p = _multi(tenants={"t01": TenantNames(domain="customer-a.com", hosts={"cloud": "drive"})})
    d = _dns(p)
    assert ("portal.customer-a.com", "A") in d and ("drive.customer-a.com", "A") in d and ("mail.customer-a.com", "A") in d
    assert ("portal.t02.acme.example", "A") in d and ("cloud.t02.acme.example", "A") in d          # default: <tenant>.<deployment domain>
    assert d[("customer-a.com", "MX")] == "10 mail.customer-a.com"
    assert p["names"]["t01"]["domain"] == "customer-a.com" and p["names"]["t02"]["domain"] == "t02.acme.example"
    portals = [v["name"] for v in p["vms"] if "portal" in v["components"]]
    assert len(portals) == 2 and all(v.split("-")[2] in ("t01", "t02") for v in portals)


# ---- configuration -----------------------------------------------------------------------------------------------

class _Agent:
    def __init__(self, plan):
        self.ip = {v["name"]: f"10.0.0.{i + 10}" for i, v in enumerate(plan["vms"])}

    def address(self, vm):
        return self.ip[vm]


KEY = configure._rsa_key()


def _ctx(plan, monkeypatch):
    store = {}

    def secret(rt, dep, name, make=None):
        if name not in store:
            store[name] = make() if make else f"{name}-" + "x" * 24
        return store[name]
    monkeypatch.setattr(configure, "secret", secret)
    monkeypatch.setattr(configure, "realm_key", lambda rt, dep, t=None: secret(rt, dep, configure.sname(t, "realm-signing-key"), lambda: KEY))
    ctx = type("Ctx", (), {"deployment_id": "d1", "rt": None, "slug": "prod", "plan": plan, "env": type("E", (), {"agent": _Agent(plan)})()})()
    return ctx, store


def _runbooks(ctx, vm):
    out = []
    for comp in next(v["components"] for v in ctx.plan["vms"] if v["name"] == vm):
        if comp in configure.BUILDERS:
            out += configure.BUILDERS[comp](ctx, vm)
    return out


def test_single_tenant_edge_sends_unknown_names_to_the_portal_and_everything_passes_the_agent_schemas(monkeypatch):
    p = _ok(generate_plan(inp(names=NameSettings(hosts={"portal": "start"})), cap(), pinned()))
    ctx, store = _ctx(p, monkeypatch)
    rb = _runbooks(ctx, "acme-prod-id")
    default = [r for r in rb if r["runbook"] == "cfg.nginx_default"]
    assert default == [{"runbook": "cfg.nginx_default", "params": {"redirect": "https://start.acme.example/", "tls_name": "deployment"}}]
    sites = {r["params"]["server_names"][0]: r["params"]["upstream"] for r in rb if r["runbook"] == "cfg.nginx_site"}
    assert sites["start.acme.example"] == "http://127.0.0.1:8090" and sites["auth.acme.example"] == "http://127.0.0.1:8080"
    portal = next(r for r in rb if r["runbook"] == "cfg.portal")["params"]
    assert portal["base_url"] == "https://start.acme.example" and portal["issuer"] == "https://auth.acme.example/realms/ou"
    assert portal["mail_web_url"] == "https://mail.acme.example/web/" and portal["files_url"] == "https://cloud.acme.example"
    assert portal["client_secret"] == store["portal-client-secret"]
    for r in rb:   # what the ICS sends is what the agent accepts
        if r["runbook"] in c.CHECKS:
            c.CHECKS[r["runbook"]](r["params"], {"enabled": True})
    realm = json.loads(next(f["content"] for r in rb if r["runbook"] == "cfg.volume_files" for f in r["params"]["files"] if f["path"].startswith("import/realm")))
    cl = {x["clientId"]: x for x in realm["clients"]}
    assert cl["ou-portal"]["secret"] == store["portal-client-secret"] and cl["ou-portal"]["redirectUris"] == ["https://start.acme.example/auth/callback"]
    assert cl["ou-webmail"]["secret"] == store["webmail-client-secret"] and cl["ou-webmail"]["redirectUris"] == ["https://mail.acme.example/web"]
    assert cl["ou-webmail"]["attributes"]["pkce.code.challenge.method"] == ""            # grommunio-web sends no PKCE
    keys = realm["components"]["org.keycloak.keys.KeyProvider"]
    assert next(k for k in keys if k["providerId"] == "rsa")["config"]["privateKey"] == [KEY]
    ldap_user = next(r for r in rb if r["runbook"] == "cfg.ldap_user")["params"]
    assert "org-admin" in ldap_user["groups"]                                              # the administrator opens the portal's admin area
    red = json.dumps([configure.redact(r["runbook"], r["params"]) for r in rb])
    assert store["portal-client-secret"] not in red and KEY not in red


def test_every_app_site_refuses_the_apps_own_administration_and_the_portal_keeps_its_name(monkeypatch):
    """Owner 2026-11-21: no app keeps its own admin settings; administration is done through the Office Unbound console and portal."""
    for p in (_ok(generate_plan(inp(), cap(), pinned())), _multi(tenants={"t01": TenantNames(domain="customer-a.com")})):
        ctx, _ = _ctx(p, monkeypatch)
        rb = [r for vm in (v["name"] for v in p["vms"]) for r in _runbooks(ctx, vm)]
        sites = [r["params"] for r in rb if r["runbook"] == "cfg.nginx_site"]
        assert sites
        for s in sites:
            label = s["name"].split("-")[0]
            want = {"auth": "keycloak", "cloud": "opencloud", "office": "collabora", "mail": "groupware", "autodiscover": "groupware"}.get(label)
            assert s.get("lockdown") == want, s["name"]
            assert c.check_nginx_site(s, {"enabled": True}).get("lockdown") == want
        assert {s["lockdown"] for s in sites if "lockdown" in s} >= {"keycloak", "opencloud", "collabora"}


def test_the_webmail_trusts_exactly_the_realm_key_the_ics_made(monkeypatch):
    p = _ok(generate_plan(inp(), cap(), pinned()))
    ctx, store = _ctx(p, monkeypatch)
    g = next(r for r in _runbooks(ctx, "acme-prod-groupware") if r["runbook"] == "cfg.gromox")["params"]
    assert g["sso"]["bearer_pubkey"] == configure.realm_public_key(KEY) and g["sso"]["client_secret"] == store["webmail-client-secret"]
    assert c.check_gromox(g, {"enabled": True})["sso"]["redirect_url"] == "https://mail.acme.example/web"


def test_multi_tenant_scopes_have_their_own_secrets_ca_and_edge_certificates(monkeypatch):
    p = _multi(tenants={"t01": TenantNames(domain="customer-a.com")})
    ctx, store = _ctx(p, monkeypatch)
    edge = next(v["name"] for v in p["vms"] if "edge" in v["components"])
    rb = _runbooks(ctx, edge)
    tls = {r["params"]["name"]: r["params"] for r in rb if r["runbook"] == "cfg.tls"}
    assert set(tls) == {"deployment", "deployment-t01", "deployment-t02"}
    for name, dom in (("deployment-t01", "customer-a.com"), ("deployment-t02", "t02.acme.example")):
        ca = x509.load_pem_x509_certificate(tls[name]["ca_pem"].encode())
        assert [n.value for n in ca.extensions.get_extension_for_class(x509.NameConstraints).value.permitted_subtrees] == [dom]
        leaf = x509.load_pem_x509_certificate(tls[name]["cert_pem"].encode())
        sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        assert sans and all(s == dom or s.endswith("." + dom) for s in sans)
    assert tls["deployment-t01"]["ca_pem"] != tls["deployment-t02"]["ca_pem"]
    sites = {r["params"]["name"]: r["params"] for r in rb if r["runbook"] == "cfg.nginx_site"}
    assert sites["portal-t01"]["server_names"] == ["portal.customer-a.com"] and sites["portal-t01"]["tls_name"] == "deployment-t01"
    assert sites["auth-t02"]["server_names"] == ["auth.t02.acme.example"] and sites["auth-t02"]["upstream"].startswith("https://")
    assert next(r for r in rb if r["runbook"] == "cfg.nginx_default")["params"]["redirect"] is None   # never another tenant's portal
    # tenant VMs: their own scope only
    ids = sorted(v["name"] for v in p["vms"] if "identity" in v["components"])
    pw = [next(r for r in _runbooks(ctx, vm) if r["runbook"] == "cfg.ldap_user")["params"]["password"] for vm in ids]
    assert pw[0] != pw[1] and "t01-admin-password" in store and "t02-admin-password" in store
    t01 = next(r for r in _runbooks(ctx, ids[0]) if r["runbook"] == "cfg.ldap_user")["params"]
    assert t01["mail"] == "ou-admin@customer-a.com"
    for r in rb:
        if r["runbook"] in c.CHECKS:
            c.CHECKS[r["runbook"]](r["params"], {"enabled": True})


def test_the_agent_refuses_a_portal_or_default_site_outside_https():
    good = {"base_url": "https://portal.a.example", "issuer": "https://auth.a.example/realms/ou", "client_id": "ou-portal",
            "client_secret": "x" * 32, "files_url": "", "mail_web_url": "", "mail_host": "", "mail_domain": "a.example", "org_name": "a.example"}
    assert c.check_portal(dict(good), {"enabled": True})["base_url"] == "https://portal.a.example"
    for bad in ({"base_url": "http://portal.a.example"}, {"issuer": "https://auth.a.example/x"}, {"client_secret": "short"}, {"extra": 1}):
        with pytest.raises(Reject):
            c.check_portal({**good, **bad}, {"enabled": True})
    with pytest.raises(Reject):
        c.check_nginx_default({"redirect": "http://evil.example/", "tls_name": "deployment"}, {"enabled": True})
    assert c.check_nginx_default({"redirect": None, "tls_name": "deployment"}, {"enabled": True})["redirect"] is None


def test_tenant_secret_names_fit_the_database(rt):
    """Regression (found 2026-11-20 before any multi-tenant run): tenant secret names must satisfy deployment_secrets.name's CHECK, and the
    real store keeps tenants apart."""
    import re
    from sqlalchemy import text
    for t in ("t01", "t50"):
        for n in ("admin-password", "webmail-client-secret", "realm-signing-key", "deployment-ca", "portal-client-secret"):
            assert re.fullmatch(r"[a-z][a-z0-9-]{1,40}", configure.sname(t, n))
    with rt.session() as db:
        did = str(db.execute(text("INSERT INTO deployments (slug, customer_id, profile, profile_version, status, desired_spec) "
                                  "VALUES ('mt1', 'c-000000000000', 'msp-multi', '1', 'active', '{}'::jsonb) RETURNING id")).scalar())
        db.commit()
    a = configure.secret(rt, did, configure.sname("t01", "admin-password"))
    b = configure.secret(rt, did, configure.sname("t02", "admin-password"))
    assert a != b and configure.secret(rt, did, configure.sname("t01", "admin-password")) == a


def test_role_names_say_what_each_vm_is_and_legacy_deployments_keep_theirs():
    """Owner 2026-11-20: "name the vm's something clear ... same with templates"."""
    from ics.deploy.executor import pick_template, template_base
    from ics.deploy.plan import vm_description
    legacy = _ok(generate_plan(inp(), cap(), pinned()))
    assert sorted(v["name"] for v in legacy["vms"]) == ["acme-prod-files", "acme-prod-groupware", "acme-prod-id"]   # unchanged without the field
    new = _ok(generate_plan(inp(vm_names="role"), cap(), pinned()))
    assert sorted(v["name"] for v in new["vms"]) == ["prod-files", "prod-gateway", "prod-mail"]
    gw = next(v for v in new["vms"] if v["name"] == "prod-gateway")
    assert vm_description("prod", gw["components"]) .startswith("Office Unbound · prod · gateway VM: sign-in and directory, web entry (gateway), user portal")
    multi = _ok(generate_plan(inp(profile="msp-multi", tenants=2, users=20, vm_names="role"), cap(nodes=3, cores=128, mem=1_000_000, sto=20000), pinned()))
    names = sorted(v["name"] for v in multi["vms"])
    assert "prod-t01-mail" in names and "prod-t02-identity" in names and len(set(names)) == len(names)
    tpls = [{"name": "ou-tpl-ubuntu-2404", "vmid": 148, "tags": ["ou-image", "ou-rel-ubuntu-2404-20261119", "ou-ver-8"]},
            {"name": "ou-tpl-ubuntu-2404-v10", "vmid": 147, "tags": ["ou-image", "ou-rel-ubuntu-2404-20261120", "ou-ver-10"]}]
    assert template_base("ou-tpl-ubuntu-2404-v10") == "ou-tpl-ubuntu-2404" and pick_template(tpls, "ou-tpl-ubuntu-2404")["vmid"] == 147
