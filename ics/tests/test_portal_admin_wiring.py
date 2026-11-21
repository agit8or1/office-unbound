"""The deployed portal's admin area (owner: "create tenant admin accounts from the console; those accounts can login and do admin functions"):
the ICS URL setting (Settings -> Network & domains: the console's public name), cfg.portal's optional `admin` parameters (closed schema, sent only
to an agent that reports the feature), and the tenant-admin API trusting a deployment's portal key and realm tokens derived from the applied plan."""
import base64
import json
import os
import sys
import time
import uuid

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import ValidationError
from sqlalchemy import text

from ics import netsettings as ns
from ics.deploy import appaccess, configure
from ics.tenant_admin import deployment as tdep
from ics.tenant_admin import jwtv

from .test_deploy_names import _ctx
from .test_gateway_certs import _plan

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
from ou_agent import cfghelper as h  # noqa: E402
from ou_agent import cfgspec as c  # noqa: E402
from ou_agent import runbooks as agent_runbooks  # noqa: E402
from ou_agent.proto import Reject  # noqa: E402

T = "/api/v1/tenant"
DKEY = "tdk_" + "0" * 31 + "1." + "A" * 43


# ---- setting -------------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("v, want", [("console.example.com", "console.example.com"), ("Console.Example.COM.", "console.example.com"), ("", None), (None, None)])
def test_the_console_name_is_a_dns_name(v, want):
    assert ns.NetworkSettings(console_name=v).console_name == want


@pytest.mark.parametrize("v", ["192.168.22.10", "https://console.example.com", "console.example.com:8443", "console", "a b.example.com"])
def test_the_console_name_is_never_an_address_url_or_port(v):
    with pytest.raises(ValidationError):
        ns.NetworkSettings(console_name=v)


def test_the_ics_url_for_vms_follows_the_setting(rt):
    with rt.session() as db:
        assert ns.ics_url_for_vms(db) is None
        ns.put(db, ns.NetworkSettings(public_ipv4="184.175.230.187", console_name="console.example.com"), "test")
        db.commit()
        assert ns.ics_url_for_vms(db) == "https://console.example.com"


# ---- agent schema and helper ---------------------------------------------------------------------------------------------------
def _portal_params(**admin):
    p = {"base_url": "https://app.acme.example", "issuer": "https://auth.acme.example/realms/ou", "client_id": "ou-portal",
         "client_secret": "s" * 32, "files_url": "", "mail_web_url": "", "mail_host": "", "mail_domain": "acme.example", "org_name": "acme.example"}
    if admin:
        p["admin"] = admin
    return p


def test_cfg_portal_admin_is_optional_and_closed():
    assert "admin" not in c.check_portal(_portal_params(), {"enabled": True})                       # what every older ICS sends
    assert "admin" not in c.check_portal({**_portal_params(), "admin": None}, {"enabled": True})
    ok = c.check_portal(_portal_params(ics_url="https://console.example.com", ics_key=DKEY), {"enabled": True})
    assert ok["admin"] == {"ics_url": "https://console.example.com", "ics_key": DKEY}
    for bad in ({"ics_url": "https://192.168.22.10", "ics_key": DKEY}, {"ics_url": "https://console.example.com:8443", "ics_key": DKEY},
                {"ics_url": "http://console.example.com", "ics_key": DKEY}, {"ics_url": "https://console.example.com", "ics_key": "tsk_abc.def"},
                {"ics_url": "https://console.example.com", "ics_key": DKEY + "\nX=1"},
                {"ics_url": "https://console.example.com", "ics_key": DKEY, "extra": 1}, {"ics_url": "https://console.example.com"}):
        with pytest.raises(Reject):
            c.check_portal({**_portal_params(), "admin": bad}, {"enabled": True})
    with pytest.raises(Reject):
        c.check_portal({**_portal_params(), "admin_url": "https://console.example.com"}, {"enabled": True})


def test_the_agent_reports_the_portal_admin_feature():
    caps = agent_runbooks.capabilities({"runbooks": {"cfg.portal": {"enabled": True}, "cfg.hosts": {"enabled": True}}})
    assert caps["cfg.portal"] == {"enabled": True, "features": ["admin"]} and caps["cfg.hosts"] == {"enabled": True}


@pytest.fixture()
def portal_fake(tmp_path, monkeypatch):
    calls = []

    class X:
        def run(self, argv, check=True, **kw):
            calls.append(argv)
            out = "install ok installed" if "dpkg-query" in argv[0] else ("active" if argv[-2:] == ["is-active", "ou-portal"] else "")
            return type("R", (), {"stdout": out, "stderr": "", "returncode": 0})()
    monkeypatch.setattr(h, "PORTAL_ETC", str(tmp_path))
    monkeypatch.setattr(h, "_gid", lambda n: os.getgid())
    monkeypatch.setattr(h.os, "chown", lambda *a, **k: None)
    monkeypatch.setattr(h, "BIN", {**h.BIN, "dpkg-query": "dpkg-query", "systemctl": "systemctl"})
    return tmp_path, X(), calls


def test_the_helper_writes_the_ics_link_and_keeps_the_key_out_of_the_environment_file(portal_fake):
    d, x, calls = portal_fake
    p = c.check_portal(_portal_params(ics_url="https://console.example.com", ics_key=DKEY), {"enabled": True})
    r = h.portal(p, x)
    assert r["admin_area"] is True and r["config_changed"] is True
    env = (d / "portal.env").read_text()
    assert "PORTAL_ICS_URL=https://console.example.com\n" in env and f"PORTAL_ICS_KEY_FILE={d}/ics-tenant-key\n" in env
    assert "PORTAL_ICS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt\n" in env and DKEY not in env and "s" * 32 not in env
    assert (d / "ics-tenant-key").read_text() == DKEY and oct((d / "ics-tenant-key").stat().st_mode & 0o777) == "0o640"
    assert h.portal(p, x)["config_changed"] is False                                                  # idempotent
    r = h.portal(c.check_portal(_portal_params(), {"enabled": True}), x)                              # switched off: no credential left
    assert r["admin_area"] is False and not (d / "ics-tenant-key").exists() and "PORTAL_ICS" not in (d / "portal.env").read_text()


# ---- configure -----------------------------------------------------------------------------------------------------------------
class _RT:
    """Only what portal_admin needs: a session (the setting is monkeypatched)."""
    class _S:
        def __enter__(self):
            return None

        def __exit__(self, *a):
            return False

    def session(self):
        return self._S()


def test_the_portal_gets_the_admin_area_only_with_the_setting_and_a_capable_agent(monkeypatch):
    p = _plan()
    ctx, store = _ctx(p, monkeypatch)
    ctx.deployment_id = str(uuid.UUID(int=7))
    store["portal-ics-key"] = "k" * 43   # what secrets.token_urlsafe(32) makes
    vm = configure.vm_of(p, "portal", None)
    cfg = lambda: next(r for r in configure.portal_runbooks(ctx, vm) if r["runbook"] == "cfg.portal")["params"]   # noqa: E731
    assert "admin" not in cfg()                                                                       # no runtime (unit tests, previews)
    ctx.rt = _RT()
    url, feats = {"v": None}, {"v": ["admin"]}
    monkeypatch.setattr(ns, "ics_url_for_vms", lambda db: url["v"])
    monkeypatch.setattr(configure, "portal_agent_features", lambda ctx_, vm_: feats["v"])
    assert "admin" not in cfg()                                                                       # no console name set
    url["v"] = "https://console.example.com"
    feats["v"] = []
    assert "admin" not in cfg()                                                                       # an older agent would refuse it
    feats["v"] = ["admin"]
    params = cfg()
    assert params["admin"] == {"ics_url": "https://console.example.com", "ics_key": f"tdk_{'0' * 31}7.{store['portal-ics-key']}"}
    assert c.check_portal(params, {"enabled": True})["admin"] == params["admin"]                     # what the ICS sends, the agent accepts
    assert store["portal-ics-key"] not in json.dumps(configure.redact("cfg.portal", params))


# ---- tenant-admin API for a deployment -----------------------------------------------------------------------------------------
def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _token(key, iss, sub="u-1", username="boss", roles=("org-admin",), azp="ou-portal", exp=300, alg="RS256"):
    now = int(time.time())
    claims = {"typ": "Bearer", "sub": sub, "preferred_username": username, "name": "Boss", "iss": iss, "azp": azp, "iat": now, "exp": now + exp,
              "realm_access": {"roles": list(roles)}}
    body = f"{b64(json.dumps({'alg': alg, 'kid': 'whatever', 'typ': 'JWT'}).encode())}.{b64(json.dumps(claims).encode())}"
    return f"{body}.{b64(key.sign(body.encode(), padding.PKCS1v15(), hashes.SHA256()))}"


@pytest.fixture()
def deployed(rt, monkeypatch):
    p = _plan()
    with rt.session() as db:
        db.execute(text("DELETE FROM deployments WHERE slug = 'padm'"))
        dep = db.execute(text("INSERT INTO deployments (slug, customer_id, profile, profile_version, status, desired_spec) "
                              "VALUES ('padm', 'c-000000000000', 'small', '1', 'active', '{}'::jsonb) RETURNING id")).scalar()
        db.commit()
    dep = str(dep)
    monkeypatch.setattr(appaccess, "_applied_plan", lambda db, d: p)
    people = [{"username": "boss", "email": "boss@acme.example", "name": "Boss", "role": "admin", "locked": False,
               "groups": ["opencloudAdmin", "mail-users", "org-admin"]},
              {"username": "ann", "email": "ann@acme.example", "name": "Ann", "role": "user", "locked": True, "groups": ["opencloudUser", "mail-users"]}]
    monkeypatch.setitem(tdep.HOOKS, "people", lambda rt_, db, slug: {"people": people})
    key = configure.portal_key(rt, dep)
    realm = serialization.load_pem_private_key(configure.realm_key(rt, dep).encode(), password=None)
    return {"dep": dep, "key": key, "realm": realm, "iss": f"https://{configure.fq(p, None, 'auth')}/realms/ou"}


def test_a_deployed_portal_reads_with_its_key_and_an_org_admin_token(client, deployed):
    tok = _token(deployed["realm"], deployed["iss"])
    hd = {"X-OU-Tenant-Key": deployed["key"], "X-OU-User-Token": tok}
    me = client.get(f"{T}/me", headers=hd)
    assert me.status_code == 200, me.text
    assert me.json()["domain"] == "acme.example" and me.json()["users"] == {"active": 1, "disabled": 1} and me.json()["user"]["username"] == "boss"
    us = {u["uid"]: u for u in client.get(f"{T}/users", headers=hd).json()}
    assert us["boss"]["is_you"] and us["boss"]["administrator"] and us["boss"]["apps"] == {"mail": True, "files": True}
    assert us["ann"]["state"] == "disabled" and us["ann"]["groups"] == ["mail-users", "opencloudUser"]
    assert client.get(f"{T}/users/ann", headers=hd).json()["mail"] == "ann@acme.example"
    assert client.get(f"{T}/users/nobody", headers=hd).status_code == 404
    assert set(client.get(f"{T}/apps", headers=hd).json()["apps"]) == {"mail", "files"}
    assert client.get(f"{T}/requests", headers=hd).json() == []
    assert client.get(f"{T}/aliases", headers=hd).status_code == 404
    assert client.get(f"{T}/branding", headers={"X-OU-Tenant-Key": deployed["key"]}).json()["display_name"] == "acme.example"
    r = client.post(f"{T}/users/ann/enable", headers=hd, json={})
    assert r.status_code == 409 and "service provider" in r.json()["detail"]                     # changes stay in the console for now


def test_a_deployed_portal_is_refused_without_the_right_proofs(client, deployed, rt):
    good = _token(deployed["realm"], deployed["iss"])
    k = deployed["key"]
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cases = [
        ({"X-OU-Tenant-Key": k[:-1] + ("B" if k[-1] != "B" else "C"), "X-OU-User-Token": good}, 401),      # wrong secret
        ({"X-OU-Tenant-Key": "tdk_" + uuid.uuid4().hex + "." + k.split(".", 1)[1], "X-OU-User-Token": good}, 401),   # another deployment id
        ({"X-OU-Tenant-Key": k, "X-OU-User-Token": _token(other, deployed["iss"])}, 401),                    # not the realm's key
        ({"X-OU-Tenant-Key": k, "X-OU-User-Token": _token(deployed["realm"], "https://auth.evil.example/realms/ou")}, 401),
        ({"X-OU-Tenant-Key": k, "X-OU-User-Token": _token(deployed["realm"], deployed["iss"], azp="ou-webmail")}, 401),
        ({"X-OU-Tenant-Key": k, "X-OU-User-Token": _token(deployed["realm"], deployed["iss"], roles=("mail-users",))}, 403),
        ({"X-OU-Tenant-Key": k}, 401),
    ]
    for hd, want in cases:
        assert client.get(f"{T}/me", headers=hd).status_code == want, hd
    with rt.session() as db:   # a destroyed deployment's portal is no longer trusted
        db.execute(text("UPDATE deployments SET status = 'destroyed' WHERE id = :i"), {"i": deployed["dep"]})
        db.commit()
    assert client.get(f"{T}/me", headers={"X-OU-Tenant-Key": k, "X-OU-User-Token": good}).status_code == 401


def test_a_pinned_key_accepts_only_rs256_and_ignores_the_kid():
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    tok = _token(k, "https://auth.x.example/realms/ou")
    assert jwtv.verify(tok, None, issuer="https://auth.x.example/realms/ou", client_id="ou-portal", pinned=k.public_key())["sub"] == "u-1"
    h_, p_, _s = tok.split(".")
    hs = b64(json.dumps({"alg": "HS256", "kid": "x"}).encode()) + "." + p_ + "." + b64(b"x" * 32)
    with pytest.raises(jwtv.TokenError):
        jwtv.verify(hs, None, issuer="https://auth.x.example/realms/ou", client_id="ou-portal", pinned=k.public_key())
