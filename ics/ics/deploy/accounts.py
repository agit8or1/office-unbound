"""Sign-in accounts an administrator sets on a deployment (owner 2026-11-20: "make the login admin/...", "change password to 8 char min").

Typed action directory.account.set {deployment, username, password}: creates or updates the directory person `username@<domain>` (portal,
sign-in, files, documents through the directory; groups opencloudUser, mail-users, org-admin) and gives it a mailbox. The password travels only
as the plan's encrypted secret and inside the signed agent request; the ICS keeps the account NAME (to recreate the mailbox list), never the
password."""
from __future__ import annotations

import json
import re

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from sqlalchemy import text

from .. import audit
from . import appaccess, configure

KEY = "deployment.accounts"
# administrator: portal admin area (org-admin) but an ordinary OpenCloud user - administration happens in the console, never inside
# OpenCloud (owner 2026-11-21). opencloudAdmin is kept only by the built-in ou-admin (configure.identity_runbooks) for recovery.
GROUPS = ["opencloudUser", configure.MAIL_GROUP, configure.ORG_ADMIN_GROUP]
USER_GROUPS = ["opencloudUser", configure.MAIL_GROUP]                                    # regular user
# never held by a People account: removed on every set, so an administrator made earlier (then in opencloudAdmin) loses OpenCloud Admin
# when saved again (OpenCloud's OIDC role mapper picks the highest mapped role, so opencloudAdmin would otherwise win over opencloudUser)
NEVER_GROUPS = ["opencloudAdmin"]
ROLE_GROUPS = {"admin": GROUPS, "user": USER_GROUPS}
SLUG = r"^[a-z0-9][a-z0-9-]{1,30}$"
UID = r"^[a-z][a-z0-9.-]{0,30}[a-z0-9]$"
USER_PASSWORD = re.compile(r"^[A-Za-z0-9_-]{8,128}$")


# the deployment's own administrator: its password is the stored `admin-password` secret (shown by the reveal) and it is the organisation
# administrator that always remains, so a lock, delete or demotion can never leave the organisation without one. Never changed from People.
PROTECTED = appaccess.ADMIN_UID
# same rule as the agent's PERSON_RE (cfgspec) for each part, so a name is refused when the plan is made, not after approval
NAME_PART = re.compile(r"^[A-Za-z][A-Za-z .'-]{0,62}$")


def _not_protected(v: str) -> str:
    if v == PROTECTED:
        raise ValueError(f"{PROTECTED} is the deployment's own administrator and is not changed here (its password is shown under Open your apps)")
    return v


class AccountLock(BaseModel):
    model_config = ConfigDict(extra="forbid")
    deployment: str = Field(pattern=SLUG)
    username: str = Field(pattern=UID)
    locked: bool

    @field_validator("username")
    @classmethod
    def _protected(cls, v: str) -> str:
        return _not_protected(v)


class AccountDelete(BaseModel):
    model_config = ConfigDict(extra="forbid")
    deployment: str = Field(pattern=SLUG)
    username: str = Field(pattern=UID)


class AccountSet(BaseModel):
    model_config = ConfigDict(extra="forbid")
    deployment: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,30}$")
    username: str = Field(pattern=r"^[a-z][a-z0-9.-]{0,30}[a-z0-9]$")
    password: SecretStr
    role: Literal["admin", "user"] = "admin"
    display_name: str | None = Field(default=None, max_length=61)

    @field_validator("username")
    @classmethod
    def _protected(cls, v: str) -> str:
        return _not_protected(v)

    @field_validator("display_name")
    @classmethod
    def _name(cls, v: str | None) -> str | None:
        if v is not None and not all(NAME_PART.fullmatch(x) for x in v.split(None, 1)):
            raise ValueError("letters, spaces, . ' and -; the first and last name each start with a letter")
        return v

    @field_validator("password")
    @classmethod
    def _pw(cls, v: SecretStr) -> SecretStr:
        if not USER_PASSWORD.fullmatch(v.get_secret_value()):
            raise ValueError("8-128 characters: letters, digits, - and _")
        return v


def accounts(db) -> dict:
    row = db.execute(text("SELECT value FROM system_settings WHERE key = :k"), {"k": KEY}).first()
    return dict(row.value) if row else {}


def accounts_for(rt, slug: str) -> list[str]:
    with rt.session() as db:
        return list(accounts(db).get(slug, []))


def _target(db, slug: str):
    """(deployment row, applied plan, directory node id, domain) of a deployment's own scope. Agent requests are pinned to that node."""
    from ..gateway import GatewayError, _edge_node
    d = db.execute(text("SELECT * FROM deployments WHERE slug = :s AND status NOT IN ('destroyed', 'destroying')"), {"s": slug}).first()
    if d is None:
        raise GatewayError(f"deployment {slug} not found")
    plan = appaccess._applied_plan(db, d)
    if plan is None:
        raise GatewayError("the deployment has no applied plan yet")
    idvm = configure.vm_of(plan, "identity", None)
    if idvm is None:
        raise GatewayError("this deployment has no directory in the deployment scope (multi-tenant: per tenant, not supported here yet)")
    node = _edge_node(db, d, idvm)
    if not node:
        raise GatewayError(f"the directory VM {idvm} has no enrolled agent")
    return d, plan, node, configure.scope(plan, None)["domain"]


def _remember(db, slug: str, username: str, present: bool) -> None:
    st = accounts(db)
    names = set(st.get(slug, []))
    names = names | {username} if present else names - {username}
    st[slug] = sorted(names)
    db.execute(text("INSERT INTO system_settings (key, value, updated_at, updated_by) VALUES (:k, CAST(:v AS jsonb), now(), 'accounts') "
                    "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now(), updated_by = EXCLUDED.updated_by"),
               {"k": KEY, "v": json.dumps(st)})


def _mailboxes(rt, db, d, plan):
    from ..gateway import _Ctx, _edge_node, _run
    gwvm = configure.vm_of(plan, "groupware", None)
    if not gwvm:
        return None
    ctx = _Ctx(rt, d, plan, appaccess._addresses(db, d))
    gro = next(r for r in configure.groupware_runbooks(ctx, gwvm) if r["runbook"] == "cfg.gromox")
    return _run(rt, _edge_node(db, d, gwvm), "cfg.gromox", gro["params"]).get("mailboxes")


def exec_set(rt, db, m: AccountSet, plan_row, known: list[str]) -> dict:
    """Create or update a person: password, role (administrator / user; the other role's groups are removed) and a mailbox."""
    from ..gateway import _run
    pw = m.password.get_secret_value()
    known.append(pw)
    d, plan, node, domain = _target(db, m.deployment)
    parts = (m.display_name or "").split(None, 1)
    given = parts[0] if parts else m.username.capitalize()
    surname = parts[1] if len(parts) > 1 else ("Administrator" if m.role == "admin" else "User")
    groups = ROLE_GROUPS[m.role]
    res = _run(rt, node, "cfg.ldap_user", {"domain": domain, "uid": m.username, "given_name": given, "surname": surname,
                                           "mail": f"{m.username}@{domain}", "password": pw, "groups": groups})
    other = [g for g in NEVER_GROUPS + ROLE_GROUPS["user" if m.role == "admin" else "admin"] if g not in groups]
    _run(rt, node, "cfg.ldap_groups", {"domain": domain, "uid": m.username, "add": [], "remove": other})
    _remember(db, m.deployment, m.username, True)
    db.commit()   # the mailbox list below reads it
    mailbox = _mailboxes(rt, db, d, plan)
    audit.append(db, "deployment.account_set", actor_name="worker", resource="deployment", resource_id=str(d.id),
                 details={"deployment": d.slug, "username": m.username, "role": m.role, "created": res.get("created"), "groups": groups,
                          "mailbox": mailbox is not None, "plan_id": str(plan_row.id)})
    return {"deployment": d.slug, "username": m.username, "email": f"{m.username}@{domain}", "role": m.role, "created": res.get("created"),
            "mailboxes": mailbox}


def exec_lock(rt, db, m: AccountLock, plan_row, known: list[str]) -> dict:
    from ..gateway import _run
    d, plan, node, domain = _target(db, m.deployment)
    res = _run(rt, node, "cfg.ldap_lock", {"domain": domain, "uid": m.username, "locked": m.locked})
    audit.append(db, "deployment.account_locked" if m.locked else "deployment.account_unlocked", actor_name="worker", resource="deployment",
                 resource_id=str(d.id), details={"deployment": d.slug, "username": m.username, "plan_id": str(plan_row.id)})
    return {"deployment": d.slug, "username": m.username, "locked": m.locked, "result": res}


def exec_delete(rt, db, m: AccountDelete, plan_row, known: list[str]) -> dict:
    from ..gateway import _run
    d, plan, node, domain = _target(db, m.deployment)
    res = _run(rt, node, "cfg.ldap_delete", {"domain": domain, "uid": m.username})
    _remember(db, m.deployment, m.username, False)
    audit.append(db, "deployment.account_deleted", actor_name="worker", resource="deployment", resource_id=str(d.id),
                 details={"deployment": d.slug, "username": m.username, "plan_id": str(plan_row.id),
                          "note": "the mailbox content is kept (gromox); it is no longer reachable without the directory entry"})
    return {"deployment": d.slug, "username": m.username, "deleted": res.get("deleted", True)}


def people(rt, db, slug: str) -> dict:
    """The deployment's directory, read live through the agent (cfg.ldap_list): people with their role and lock state. No password ever."""
    from ..gateway import _run
    d, plan, node, domain = _target(db, slug)
    res = _run(rt, node, "cfg.ldap_list", {"domain": domain})
    out = []
    for p in res.get("people", []):
        g = set(p.get("groups") or [])
        role = "admin" if configure.ORG_ADMIN_GROUP in g else ("user" if g else "none")
        out.append({"username": p.get("uid"), "email": p.get("mail"), "name": p.get("display_name") or " ".join(x for x in (p.get("given_name"), p.get("surname")) if x),
                    "role": role, "locked": bool(p.get("locked")), "groups": sorted(g), "system": p.get("uid") == "ou-admin"})
    return {"deployment": d.slug, "domain": domain, "people": sorted(out, key=lambda x: x["username"] or ""), "truncated": bool(res.get("truncated"))}
