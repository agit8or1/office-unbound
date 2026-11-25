"""Organization Admin for a deployment the ICS created: the deployed portal's admin area (owner: "create tenant admin accounts from the console;
those accounts can login and do admin functions").

Same two proofs as service.py, with both trust anchors DERIVED from the deployment instead of configured by hand:
  * the portal's credential `tdk_<deployment id>.<secret>` (configure.portal_key; a per-deployment secret, vault-encrypted, wiped with the
    deployment). It names the deployment and nothing else; compared in constant time.
  * the administrator's own Keycloak access token, verified against the realm signing key the ICS generated for that deployment
    (configure.realm_key: the key Keycloak imported), issuer = https://<auth name of the applied plan>/realms/ou, azp = ou-portal, realm role
    org-admin (the LDAP group org-admin that directory.account.set gives an administrator, mapped to a realm role). No JWKS fetch: the ICS
    need not reach the deployment's Keycloak at all.

Reads (who am I, people, apps, groups, domain) come live from the deployment's directory through its agent (deploy/accounts.people).
Changes are NOT offered here yet: they answer 409 and stay with the console's People panel (typed actions directory.account.*), because the
deployment's people actions are console-administrator actions and a per-deployment requesting principal has not been designed (follow-up)."""
from __future__ import annotations

import hmac
import re
import uuid

from cryptography.hazmat.primitives import serialization
from fastapi import HTTPException, Request
from sqlalchemy import text

from .. import auth
from ..deploy import appaccess, configure
from . import jwtv

KEY_RE = re.compile(r"^tdk_([0-9a-f]{32})\.([A-Za-z0-9_-]{43})$")
CHANGES_LATER = ("Changes to people on this organization are made by your service provider for now (console, People). "
                 "Nothing was changed.")
APP_GROUPS = {"mail": configure.MAIL_GROUP, "files": "opencloudUser"}
FILES_GROUPS = {"opencloudUser", "opencloudAdmin", "opencloudSpaceAdmin"}
HOOKS = {"people": None}   # replaced in tests; None = deploy.accounts.people (agent cfg.ldap_list)


class DeploymentCtx:
    """What an authenticated request of a deployed portal may see: its deployment, the applied plan, the signed-in administrator."""

    kind = "deployment"

    def __init__(self, db, rt, d, plan: dict, ip):
        self.db, self.rt, self.d, self.plan, self.ip = db, rt, d, plan, ip
        self.slug = d.slug
        self.domain = configure.scope(plan, None)["domain"]
        self.sub = self.username = self.name = None
        self.roles: set = set()

    @property
    def issuer(self) -> str:
        return f"https://{configure.fq(self.plan, None, 'auth')}/realms/{configure.REALM}"

    def apps(self) -> dict[str, str]:
        """app -> directory group, only for the apps this deployment has."""
        out = {}
        if configure.vm_of(self.plan, "groupware", None):
            out["mail"] = APP_GROUPS["mail"]
        if configure.vm_of(self.plan, "files", None):
            out["files"] = APP_GROUPS["files"]
        return out

    def identity_details(self) -> dict:
        return {"tenant_user_sub": self.sub, "tenant_user": self.username, "deployment": self.slug, "realm": configure.REALM}


def _pinned_key(rt, db, dep_id: str):
    """The public half of the realm signing key the ICS made (never created here: a deployment without one has no realm to trust)."""
    pem = appaccess._secret_if_present(rt, db, dep_id, configure.sname(None, "realm-signing-key"))
    if pem is None:
        return None
    return serialization.load_pem_private_key(pem.encode(), password=None).public_key()


def authenticate(db, rt, request: Request, key: str, *, need_user: bool = True, mutating: bool = False) -> DeploymentCtx:
    from . import service
    m = KEY_RE.match(key)
    d = None
    if m:
        d = db.execute(text("SELECT * FROM deployments WHERE id = :i AND status NOT IN ('destroyed', 'destroying')"),
                       {"i": str(uuid.UUID(m.group(1)))}).first()
    want = appaccess._secret_if_present(rt, db, str(d.id), configure.PORTAL_ICS_KEY) if d is not None else None
    if want is None or not hmac.compare_digest(want.encode(), m.group(2).encode()):
        service._fail_unauth(db, request)   # same throttle and summary as a bad customer credential (no audit row per attempt)
    plan = appaccess._applied_plan(db, d)
    if plan is None or configure.vm_of(plan, "identity", None) is None:
        raise HTTPException(503, "the organization's sign-in service is not set up yet")
    ctx = DeploymentCtx(db, rt, d, plan, auth.client_ip(request))
    if not need_user:
        return ctx
    pub = _pinned_key(rt, db, str(d.id))
    if pub is None:
        raise HTTPException(503, "the organization's sign-in service is not set up yet")
    try:
        claims = jwtv.verify(request.headers.get("x-ou-user-token", ""), None, issuer=ctx.issuer, client_id=configure.PORTAL_CLIENT, pinned=pub)
    except jwtv.TokenError as e:
        service._fail(db, request, "bad_user_token", 401, detail=str(e), deployment=d.slug)
    roles = jwtv.realm_roles(claims)
    if configure.ORG_ADMIN_GROUP not in roles:
        service._fail(db, request, "missing_org_admin_role", 403, sub=claims["sub"], deployment=d.slug)
    ctx.sub, ctx.roles = claims["sub"], roles
    ctx.username = str(claims.get("preferred_username") or claims["sub"])[:64]
    ctx.name = str(claims.get("name") or ctx.username)[:100]
    if mutating:
        raise HTTPException(409, CHANGES_LATER)
    return ctx


# ---- reads ---------------------------------------------------------------------------------------------------------------------
def _people(ctx: DeploymentCtx) -> list[dict]:
    from ..agentclient import AgentError
    from ..gateway import GatewayError
    from ..deploy import accounts
    fn = HOOKS["people"] or accounts.people
    try:
        return fn(ctx.rt, ctx.db, ctx.slug)["people"]
    except (GatewayError, AgentError):
        raise HTTPException(503, "The directory of your organization could not be reached. Please try again in a minute.") from None


def user_view(ctx: DeploymentCtx, p: dict) -> dict:
    g = set(p.get("groups") or [])
    apps = ctx.apps()
    return {"uid": p["username"], "display_name": p.get("name") or p["username"], "mail": p.get("email") or "",
            "state": "disabled" if p.get("locked") else "active", "groups": sorted(x for x in g if x in set(apps.values())),
            "apps": {a: (bool(g & FILES_GROUPS) if a == "files" else grp in g) for a, grp in apps.items()},
            "administrator": configure.ORG_ADMIN_GROUP in g, "created_at": None, "disabled_at": None, "is_you": p["username"] == ctx.username,
            "history": []}


def users(ctx: DeploymentCtx) -> list[dict]:
    return sorted((user_view(ctx, p) for p in _people(ctx) if p.get("username")), key=lambda u: (u["display_name"].lower(), u["uid"]))


def user(ctx: DeploymentCtx, uid: str) -> dict:
    for u in users(ctx):
        if u["uid"] == uid:
            return u
    raise HTTPException(404, "user not found")


def me(ctx: DeploymentCtx) -> dict:
    counts: dict[str, int] = {}
    for u in users(ctx):
        counts[u["state"]] = counts.get(u["state"], 0) + 1
    return {"customer": ctx.domain, "user": {"sub": ctx.sub, "username": ctx.username, "name": ctx.name}, "domain": ctx.domain, "users": counts,
            "policy": {"self_service_auto": False, "destructive_approval": "msp"}, "pending": 0,
            "planned": ["Adding, changing and removing people here (for now your service provider does this in the console)"],
            "features": {"aliases": False, "shared": False, "mail_quota": False, "files_quota": False}}


def branding(ctx: DeploymentCtx) -> dict:
    apps = ctx.apps()
    from .service import APP_LABELS
    return {"display_name": ctx.domain, "accent": None, "has_logo": False, "apps": {a: True for a in apps},
            "app_labels": {a: APP_LABELS.get(a, a) for a in apps}}


def apps_view(ctx: DeploymentCtx) -> dict:
    from .service import APP_LABELS
    return {"apps": {a: {"label": APP_LABELS.get(a, a), "enabled": True, "group": g} for a, g in ctx.apps().items()}}


def groups(ctx: DeploymentCtx) -> list[dict]:
    from .service import APP_LABELS
    people = _people(ctx)
    return [{"name": g, "label": APP_LABELS.get(a, a), "members": sum(1 for p in people if g in (p.get("groups") or []) and not p.get("locked"))}
            for a, g in ctx.apps().items()]


def domains(ctx: DeploymentCtx, check: bool) -> dict:
    from . import dnscheck, service
    out = {"domains": [{"name": ctx.domain, "primary": True}], "managed_by": "Your service provider adds or removes domains."}
    if check:
        mail = configure.fq(ctx.plan, None, "mail") if configure.vm_of(ctx.plan, "groupware", None) else None
        out["dns"] = {ctx.domain: dnscheck.check_domain(ctx.domain, mail, "default", resolver=service.HOOKS.get("dns", dnscheck.query),
                                                            dkim_available=False)}   # no DKIM key is generated yet
    return out


def not_here() -> HTTPException:
    return HTTPException(404, "This is not available for your organization yet.")
