"""Sign-in accounts an administrator sets on a deployment (owner 2026-11-20: "make the login admin/...", "change password to 8 char min").

Typed action directory.account.set {deployment, username, password}: creates or updates the directory person `username@<domain>` (portal,
sign-in, files, documents through the directory; groups opencloudAdmin, mail-users, org-admin) and gives it a mailbox. The password travels only
as the plan's encrypted secret and inside the signed agent request; the ICS keeps the account NAME (to recreate the mailbox list), never the
password."""
from __future__ import annotations

import json
import re

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from sqlalchemy import text

from .. import audit
from . import appaccess, configure

KEY = "deployment.accounts"
GROUPS = ["opencloudAdmin", configure.MAIL_GROUP, configure.ORG_ADMIN_GROUP]
USER_PASSWORD = re.compile(r"^[A-Za-z0-9_-]{8,128}$")


class AccountSet(BaseModel):
    model_config = ConfigDict(extra="forbid")
    deployment: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,30}$")
    username: str = Field(pattern=r"^[a-z][a-z0-9.-]{0,30}[a-z0-9]$")
    password: SecretStr

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


def exec_set(rt, db, m: AccountSet, plan_row, known: list[str]) -> dict:
    from ..gateway import GatewayError, _Ctx, _edge_node, _run
    pw = m.password.get_secret_value()
    known.append(pw)
    d = db.execute(text("SELECT * FROM deployments WHERE slug = :s AND status NOT IN ('destroyed', 'destroying')"), {"s": m.deployment}).first()
    if d is None:
        raise GatewayError(f"deployment {m.deployment} not found")
    plan = appaccess._applied_plan(db, d)
    if plan is None:
        raise GatewayError("the deployment has no applied plan yet")
    idvm = configure.vm_of(plan, "identity", None)
    if idvm is None:
        raise GatewayError("this deployment has no directory in the deployment scope (multi-tenant: per tenant, not supported here yet)")
    node = _edge_node(db, d, idvm)
    if not node:
        raise GatewayError(f"the directory VM {idvm} has no enrolled agent")
    domain = configure.scope(plan, None)["domain"]
    res = _run(rt, node, "cfg.ldap_user", {"domain": domain, "uid": m.username, "given_name": m.username.capitalize(), "surname": "Administrator",
                                           "mail": f"{m.username}@{domain}", "password": pw, "groups": GROUPS})
    st = accounts(db)
    names = sorted(set(st.get(m.deployment, [])) | {m.username})
    st[m.deployment] = names
    db.execute(text("INSERT INTO system_settings (key, value, updated_at, updated_by) VALUES (:k, CAST(:v AS jsonb), now(), 'accounts') "
                    "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now(), updated_by = EXCLUDED.updated_by"),
               {"k": KEY, "v": json.dumps(st)})
    db.commit()   # the mailbox list below reads it
    mailbox = None
    gwvm = configure.vm_of(plan, "groupware", None)
    if gwvm:
        gnode = _edge_node(db, d, gwvm)
        ctx = _Ctx(rt, d, plan, appaccess._addresses(db, d))
        gro = next(r for r in configure.groupware_runbooks(ctx, gwvm) if r["runbook"] == "cfg.gromox")
        mailbox = _run(rt, gnode, "cfg.gromox", gro["params"]).get("mailboxes")
    audit.append(db, "deployment.account_set", actor_name="worker", resource="deployment", resource_id=str(d.id),
                 details={"deployment": d.slug, "username": m.username, "created": res.get("created"), "groups": GROUPS,
                          "mailbox": bool(gwvm), "plan_id": str(plan_row.id)})
    return {"deployment": d.slug, "username": m.username, "email": f"{m.username}@{domain}", "created": res.get("created"), "mailboxes": mailbox}
