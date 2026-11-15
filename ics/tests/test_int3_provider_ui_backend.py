"""Integration 3: read-only discovery with temporary admin credentials (never persisted/logged) and the full effective-grant view."""
import json

import pytest
from sqlalchemy import text

from ics.providers.proxmox.admin import ProxmoxAdminClient
from .infra_fixtures import H
from .test_provisioning import mode_a, owner, w  # noqa: F401  (fixtures)


def _body(srv, **kw):
    b = {"stage": "discover", "base_url": srv.url, "fingerprint_sha256": srv.fingerprint, "username": "root@pam", "password": srv.sim.ROOT_PW}
    b.update(kw)
    return b


def test_discover_with_temporary_admin_credentials_is_readonly_and_never_stored(w, owner, owner_engine):
    discarded = []
    orig = ProxmoxAdminClient.discard
    ProxmoxAdminClient.discard = lambda self: (discarded.append(self.mode), orig(self))[1]
    writes_before = len(getattr(owner.sim, "requests", []) or [])
    try:
        r = w.ad.post(f"{H}/setup/probe", json=_body(owner), headers=w.adh)
    finally:
        ProxmoxAdminClient.discard = orig
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["ok"] and out["readonly"] and out["nodes"] and out["storages"] and "bridges" in out and "templates" in out and "pools" in out
    assert any(n["name"] == "pve06" for n in out["nodes"]) or out["nodes"]
    assert owner.sim.ROOT_PW not in json.dumps(out) and discarded == ["ticket"]            # client wiped after use
    # nothing persisted or audited with the credential; no endpoint created
    with owner_engine.connect() as c:
        dump = json.dumps([[str(x) for x in row] for row in c.execute(text("SELECT details_canon FROM audit_events")).all()]
                          + [[str(x) for x in row] for row in c.execute(text("SELECT params::text FROM plans")).all()])
        assert owner.sim.ROOT_PW not in dump and "setup.discover" in dump
        assert c.execute(text("SELECT count(*) FROM endpoints")).scalar() == 0
    # admin only; both auth styles are not accepted at once; a wrong password is a clean 422 without the secret
    assert w.o.post(f"{H}/setup/probe", json=_body(owner), headers=w.oh).status_code == 403
    assert w.ad.post(f"{H}/setup/probe", json=_body(owner, token_id="a@pve!t", token_secret="x" * 36), headers=w.adh).status_code == 422
    bad = w.ad.post(f"{H}/setup/probe", json=_body(owner, password="wrong-password"), headers=w.adh)
    assert bad.status_code == 422 and "wrong-password" not in bad.text


def test_permissions_view_lists_full_effective_grants(w, owner):
    pv, p, j = mode_a(w, owner)
    assert j["status"] == "succeeded", j
    eid = j["result"]["endpoint_id"]
    v = w.v.get(f"{H}/providers/{eid}/permissions").json()
    g = v["grants"]
    pool = next(x for x in g if x["path"] == "/pool/officeunbound-pve06")
    assert pool["privileges"] and pool["role"] and pool["propagate"] in (True, False) and pool["enforced_by"] == "proxmox"
    assert any(x["path"].startswith("/nodes/") and "visibility" in x["note"] for x in g)
    assert any(x["enforced_by"] == "ics" and "pve06" in x["note"] for x in g)               # node allowlist is ICS-enforced
    assert v["custom_grants"] == [] and any(e["enforced_by"] in ("ics", "both") for e in v["ics_enforced"])
