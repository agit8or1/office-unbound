"""Open your apps: what an administrator needs to reach a deployment's applications from their own computer.

Read side (`access_info`): links to the user-facing apps, the name -> address lines for a hosts file (until the owner's public DNS exists),
the deployment CA certificate (public: browsers and mail clients trust the deployment's certificates with it) and the administrator's
directory user name. Built only from what the ICS recorded: the applied plan's DNS records and the addresses of the enrolled VMs.

Secret side (`reveal_admin_password`): the directory password of `ou-admin` (Keycloak, files, Office, webmail, IMAP/SMTP). It is a read of a
secret the ICS already holds, not a change, so it is not a plan/job (a job result would persist the password). Instead: admin role, a FRESH
second factor (a one-time TOTP code, single use and throttled exactly like sign-in) and an audit event; the response is never cached.
Owner request 2026-11-20 ("yes build the apps panel"): the console had no way to sign in to a deployed stack."""
from __future__ import annotations

import json

from sqlalchemy import text

from . import configure

ADMIN_UID = "ou-admin"

# component of the DNS record -> (title, path, what it is). Office opens from Files; LDAP and the MX/TXT records are not apps.
APPS = {
    "files": ("Files", "/", "File sync and sharing; documents open in Office from here"),
    "groupware": ("Webmail", "/web/", "Mail, calendar and contacts in the browser"),
    "edge": ("Account", f"/realms/{configure.REALM}/account/", "Single sign-on account: password, sessions"),
}


def _applied_plan(db, d) -> dict | None:
    row = db.execute(text("SELECT plan FROM deployment_revisions WHERE deployment_id = :d AND revision = :r AND status = 'applied' "
                          "ORDER BY id DESC LIMIT 1"), {"d": str(d.id), "r": d.current_revision}).first()
    return row.plan if row is not None else None


def _addresses(db, d) -> dict[str, str]:
    """VM logical name -> address of its enrolled agent node."""
    out = {}
    for r in db.execute(text("SELECT r.logical_name, n.address FROM deployment_resources r JOIN nodes n "
                             "ON n.id::text = r.provider_ref->>'agent_node_id' WHERE r.deployment_id = :d AND r.kind = 'vm' "
                             "AND r.state <> 'removed'"), {"d": str(d.id)}).all():
        out[r.logical_name] = r.address
    return out


def _secret_if_present(rt, db, dep_id: str, name: str) -> str | None:
    row = db.execute(text("SELECT value_enc FROM deployment_secrets WHERE deployment_id = :d AND name = :n"), {"d": dep_id, "n": name}).first()
    return rt.vault.decrypt(row.value_enc, configure._ctx(dep_id, name)).decode() if row is not None else None


def build(plan: dict, addresses: dict[str, str]) -> dict:
    """Pure part: apps, hosts lines and client settings from the plan's DNS records and the VM addresses."""
    domain = plan["input"]["domain"]
    a = {x["name"]: addresses.get(x["value"][3:]) for x in plan.get("dns", []) if x["type"] == "A" and str(x["value"]).startswith("vm:")}
    for x in plan.get("dns", []):
        if x["type"] == "CNAME" and x["value"] in a:
            a[x["name"]] = a[x["value"]]
    hosts: dict[str, list[str]] = {}
    for name, addr in sorted(a.items()):
        if addr:
            hosts.setdefault(addr, []).append(name)
    apps = []
    for x in sorted(plan.get("dns", []), key=lambda r: r["name"]):
        if x["type"] == "A" and x.get("component") in APPS and a.get(x["name"]):
            title, path, what = APPS[x["component"]]
            apps.append({"id": x["component"], "title": title, "url": f"https://{x['name']}{path}", "description": what})
    mail = next((x["name"] for x in plan.get("dns", []) if x.get("component") == "groupware" and x["type"] == "A"), None)
    clients = None
    if mail and a.get(mail):
        clients = {"imap": {"host": mail, "port": 993, "security": "SSL/TLS"},
                   "smtp": {"host": mail, "port": 587, "security": "STARTTLS", "auth": "password"},
                   "activesync": f"https://{mail}/Microsoft-Server-ActiveSync", "caldav": f"https://{mail}/dav/",
                   "autodiscover": f"autodiscover.{domain}"}
    return {"domain": domain, "apps": apps, "clients": clients,
            "hosts": [{"address": k, "names": v} for k, v in sorted(hosts.items())],
            "admin": {"username": ADMIN_UID, "email": f"{ADMIN_UID}@{domain}"}}


def access_info(rt, db, d) -> dict:
    plan = _applied_plan(db, d)
    if plan is None or d.status in ("destroyed", "destroying"):
        return {"deployment": d.slug, "ready": False, "apps": [], "hosts": [], "clients": None, "ca_pem": None, "admin": None,
                "note": "The apps are listed once the deployment has been created."}
    ca = _secret_if_present(rt, db, str(d.id), "deployment-ca")
    out = build(plan, _addresses(db, d))
    pw_set = db.execute(text("SELECT 1 FROM deployment_secrets WHERE deployment_id = :d AND name = 'admin-password'"), {"d": str(d.id)}).first()
    return {"deployment": d.slug, "ready": True, **out, "ca_pem": json.loads(ca)["cert"] if ca else None,
            "admin": {**out["admin"], "password_available": pw_set is not None}}


def admin_password(rt, db, d) -> str | None:
    return _secret_if_present(rt, db, str(d.id), "admin-password")
