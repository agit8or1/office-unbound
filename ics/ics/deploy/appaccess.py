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
    "portal": ("Portal", "/", "Start here: one sign-in for mail, calendar, contacts, files and documents"),
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
    order = list(APPS)
    for x in sorted(plan.get("dns", []), key=lambda r: (order.index(r["component"]) if r.get("component") in order else 99, r["name"])):
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


# ---------------------------------------------------------------- dashboard: every deployment's apps, links and health
# which components an app depends on (its status = the worst state of their health checks)
APP_COMPONENTS = {"portal": ("portal", "identity", "edge"), "files": ("files", "office", "edge"), "groupware": ("groupware",),
                  "edge": ("identity", "edge")}
SERVICE_TITLES = {"identity": "Sign-in and directory", "edge": "Gateway (web entry)", "portal": "User portal", "files": "Files",
                  "office": "Documents (Office)", "groupware": "Mail, calendar, contacts"}
_RANK = {"critical": 3, "warning": 2, "unknown": 1, "ok": 0}


def _worst(states: list[str]) -> str:
    return max(states, key=lambda s: _RANK.get(s, 1)) if states else "unknown"


def apps_overview(db) -> list[dict]:
    """For the dashboard: per deployment that is not destroyed, the app links (as in the apps panel) with a status from the deployment's own
    health checks, and the status of every service. No secret, no address beyond what the apps panel shows."""
    out = []
    for d in db.execute(text("SELECT * FROM deployments WHERE status NOT IN ('destroyed', 'destroying') ORDER BY slug")).all():
        plan = _applied_plan(db, d)
        # a disabled check says nothing about the app (2026-11-20: a disabled, last-critical check showed every gateway app "Down")
        checks = db.execute(text("SELECT name, state, last_raw, last_run_at FROM checks WHERE deployment_id = :d AND enabled"), {"d": str(d.id)}).all()
        comp_of = {c["name"]: c.get("component") for c in (plan or {}).get("checks", [])}
        by_comp: dict[str, list] = {}
        for c in checks:
            by_comp.setdefault(comp_of.get(c.name) or "", []).append(c)
        services = []
        for comp, title in SERVICE_TITLES.items():
            cs = by_comp.get(comp)
            if cs:
                bad = [c for c in cs if c.state != "ok"]
                services.append({"id": comp, "title": title, "status": _worst([c.state for c in cs]), "checks": len(cs),
                                 "failing": [c.name for c in bad][:5]})
        apps = []
        if plan is not None:
            b = build(plan, _addresses(db, d))
            for a in b["apps"]:
                st = _worst([c.state for comp in APP_COMPONENTS.get(a["id"], (a["id"],)) for c in by_comp.get(comp, [])])
                apps.append({**a, "status": st})
        out.append({"deployment": d.slug, "status": d.status, "domain": (plan or {}).get("input", {}).get("domain"),
                    "portal": next((a["url"] for a in apps if a["id"] == "portal"), None), "apps": apps, "services": services,
                    "health": _worst([s["status"] for s in services]) if services else "unknown"})
    return out
