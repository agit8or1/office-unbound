"""/api/v1/tenant/*: the narrow Organization Admin API used by the portal BFF (service credential + the admin's own Keycloak token), and the
operator-side binding endpoints under /api/v1/customers/{id}/tenant-admin (ICS admin, all-customers scope)."""
import re
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..auth import User, client_ip, get_db, require
from . import deployment as dep, dnscheck, service
from .deployment import DeploymentCtx
from .service import Ctx, TenantError

T = "/api/v1/tenant"
UID = r"^[a-z][a-z0-9._-]{1,31}$"
GROUP = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"


class NewUser(BaseModel):
    model_config = ConfigDict(extra="forbid")
    uid: str = Field(pattern=UID)
    display_name: str = Field(min_length=1, max_length=100)
    apps: dict[str, bool] = Field(default_factory=dict, description="app key -> on/off; mapped to groups by the customer's policy")
    groups: list[str] = Field(default_factory=list, max_length=20)


class GroupChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    add: list[str] = Field(default_factory=list, max_length=20)
    remove: list[str] = Field(default_factory=list, max_length=20)


class Reason(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(default="", max_length=200)


class Reset(BaseModel):
    model_config = ConfigDict(extra="forbid")
    what: str = Field(pattern="^(password|mfa)$")


class Branding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    display_name: str | None = Field(default=None, max_length=60)
    accent: str | None = Field(default=None, max_length=7)


class Apps(BaseModel):
    model_config = ConfigDict(extra="forbid")
    apps: dict[str, bool]


class AliasChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    add: list[str] = Field(default_factory=list, max_length=20)
    remove: list[str] = Field(default_factory=list, max_length=20)


class NewShared(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=UID)
    display_name: str = Field(min_length=1, max_length=100)


class SharedGrant(BaseModel):
    model_config = ConfigDict(extra="forbid")
    uid: str = Field(pattern=UID)
    kind: str = Field(pattern="^(full_access|send_as|send_on_behalf)$")


class MailQuota(BaseModel):
    model_config = ConfigDict(extra="forbid")
    limit_mb: int | None = Field(ge=1, le=10_000_000)


class FilesQuota(BaseModel):
    model_config = ConfigDict(extra="forbid")
    quota_mb: int | None = Field(ge=1, le=10_000_000)


class BindIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    stack: str
    portal_client_id: str = Field(default="ou-portal", pattern=r"^[A-Za-z0-9._-]{1,64}$")
    admin_role: str = Field(default="org-admin", pattern=r"^[A-Za-z0-9._-]{1,64}$")
    destructive_approval: str = "second_admin"
    self_service_auto: bool = True
    dkim_selector: str = Field(default="default", pattern=r"^[A-Za-z0-9-]{1,63}$")
    app_groups: dict[str, str] = Field(default_factory=dict)


def _wrap(fn):
    try:
        return fn()
    except TenantError as e:
        raise HTTPException(e.status, e.msg) from None


def mount(app: FastAPI) -> None:
    rt = app.state.rt

    def ctx_read(request: Request, db: Session = Depends(get_db)) -> Ctx:
        return service.authenticate(db, rt, request)

    def ctx_write(request: Request, db: Session = Depends(get_db)) -> Ctx:
        return service.authenticate(db, rt, request, mutating=True)

    def ctx_service(request: Request, db: Session = Depends(get_db)) -> Ctx:
        return service.authenticate(db, rt, request, need_user=False)

    # ---- who am I / overview --------------------------------------------------------------------------------------------------
    @app.get(f"{T}/me")
    def me(ctx: Ctx = Depends(ctx_read)):
        if isinstance(ctx, DeploymentCtx):
            return dep.me(ctx)
        c = ctx.db.execute(text("SELECT name FROM customers WHERE id = :i"), {"i": ctx.customer_id}).scalar()
        counts = ctx.db.execute(text("SELECT state, count(*) AS n FROM idm_users WHERE stack_id = :s AND state <> 'deleted' GROUP BY state"), {"s": str(ctx.stack_row.id)}).all()
        pol = ctx.policy
        return {"customer": c, "user": {"sub": ctx.sub, "username": ctx.username, "name": ctx.name}, "domain": ctx.cfg["mail_domain"],
                "users": {r.state: r.n for r in counts}, "policy": {"self_service_auto": pol["self_service_auto"], "destructive_approval": pol["destructive_approval"]},
                "pending": sum(1 for r in service.requests_view(ctx, limit=100) if r["can_decide"]),
                "planned": ["Creating/renaming groups and adding domains (done by your service provider)"],
                "features": {"aliases": bool(ctx.cfg.get("gromox_node_id")), "shared": bool(ctx.cfg.get("gromox_node_id")), "mail_quota": bool(ctx.cfg.get("gromox_node_id")),
                             "files_quota": bool(ctx.cfg.get("oc_quota_user") and ctx.cfg.get("files_url"))}}

    # ---- branding for the portal itself (service credential only: any signed-in user's page needs it) ------------------------------
    @app.get(f"{T}/branding")
    def branding(ctx: Ctx = Depends(ctx_service)):
        if isinstance(ctx, DeploymentCtx):
            return dep.branding(ctx)
        n = ctx.db.execute(text("SELECT name FROM customers WHERE id = :i"), {"i": ctx.customer_id}).scalar()
        return service.public_branding(ctx.binding, n)

    @app.get(f"{T}/branding/logo")
    def logo(ctx: Ctx = Depends(ctx_service)):
        if isinstance(ctx, DeploymentCtx) or ctx.binding.logo is None:
            raise HTTPException(404, "no logo")
        return Response(bytes(ctx.binding.logo), media_type=ctx.binding.logo_type, headers={"X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'none'; sandbox"})

    @app.put(f"{T}/branding")
    def put_branding(b: Branding, ctx: Ctx = Depends(ctx_write)):
        return _wrap(lambda: service.set_branding(ctx, b.display_name, b.accent))

    @app.put(f"{T}/branding/logo")
    async def put_logo(request: Request, ctx: Ctx = Depends(ctx_write)):
        cl = request.headers.get("content-length", "")
        if cl.isdigit() and int(cl) > service.MAX_LOGO:
            raise HTTPException(413, "The logo is too large. Use a file under 200 KB.")
        buf = bytearray()
        async for chunk in request.stream():   # review 6 L4: never buffer more than the cap
            buf += chunk
            if len(buf) > service.MAX_LOGO:
                raise HTTPException(413, "The logo is too large. Use a file under 200 KB.")
        data = bytes(buf)
        _wrap(lambda: service.set_logo(ctx, data or None))
        return {"ok": True}

    @app.delete(f"{T}/branding/logo")
    def del_logo(ctx: Ctx = Depends(ctx_write)):
        service.set_logo(ctx, None)
        return {"ok": True}

    @app.get(f"{T}/apps")
    def apps(ctx: Ctx = Depends(ctx_read)):
        if isinstance(ctx, DeploymentCtx):
            return dep.apps_view(ctx)
        return {"apps": {a: {"label": service.APP_LABELS.get(a, a), "enabled": bool((ctx.binding.app_access or {}).get(a)), "group": g}
                         for a, g in (ctx.policy.get("app_groups") or {}).items()}}

    @app.put(f"{T}/apps")
    def put_apps(b: Apps, ctx: Ctx = Depends(ctx_write)):
        return _wrap(lambda: service.set_apps(ctx, b.apps))

    # ---- users ----------------------------------------------------------------------------------------------------------------
    @app.get(f"{T}/users")
    def users(ctx: Ctx = Depends(ctx_read)):
        if isinstance(ctx, DeploymentCtx):
            return dep.users(ctx)
        return service.list_users(ctx)

    @app.get(f"{T}/users/{{uid}}")
    def user(uid: str, ctx: Ctx = Depends(ctx_read)):
        if not re.match(UID, uid):
            raise HTTPException(404, "user not found")
        if isinstance(ctx, DeploymentCtx):
            return dep.user(ctx, uid)
        return _wrap(lambda: service.get_user(ctx, uid))

    def _groups_for(ctx: Ctx, apps_: dict, groups: list[str]) -> list[str]:
        ag, ok = ctx.policy.get("app_groups") or {}, service.assignable_groups(ctx)
        want = {ag[a] for a, on in apps_.items() if on and a in ag}
        if set(apps_) - set(ag):
            raise TenantError(422, "unknown application")
        want |= set(groups)
        if want - set(ok):
            raise TenantError(422, "you cannot assign these groups: " + ", ".join(sorted(want - set(ok))))
        return sorted(want)

    @app.post(f"{T}/users", status_code=202)
    def create_user(b: NewUser, ctx: Ctx = Depends(ctx_write)):
        def go():
            g = _groups_for(ctx, b.apps, b.groups)
            mailbox = ctx.cfg.get("entitlement_group") in g
            return service.submit(ctx, "user.create", "idm.user.create",
                                  {"uid": b.uid, "display_name": b.display_name, "mail": f"{b.uid}@{ctx.cfg['mail_domain']}", "groups": g, "mailbox": mailbox},
                                  f"Add {b.display_name} ({b.uid})", b.uid)
        return _wrap(go)

    def _self_guard(ctx: Ctx, uid: str, what: str):
        if uid == ctx.username:
            raise TenantError(409, f"You cannot {what} your own account. Ask another administrator.")

    @app.post(f"{T}/users/{{uid}}/groups", status_code=202)
    def user_groups(uid: str, b: GroupChange, ctx: Ctx = Depends(ctx_write)):
        def go():
            ok = service.assignable_groups(ctx)
            if (set(b.add) | set(b.remove)) - set(ok):
                raise TenantError(422, "you cannot change these groups: " + ", ".join(sorted((set(b.add) | set(b.remove)) - set(ok))))
            return service.submit(ctx, "user.groups", "idm.user.update_groups", {"uid": uid, "add": b.add, "remove": b.remove}, f"Change access of {uid}", uid)
        return _wrap(go)

    @app.post(f"{T}/users/{{uid}}/disable", status_code=202)
    def user_disable(uid: str, b: Reason, ctx: Ctx = Depends(ctx_write)):
        def go():
            _self_guard(ctx, uid, "disable")
            return service.submit(ctx, "user.disable", "idm.user.disable", {"uid": uid, "reason": b.reason or f"disabled by {ctx.username}"}, f"Disable {uid}", uid)
        return _wrap(go)

    @app.post(f"{T}/users/{{uid}}/enable", status_code=202)
    def user_enable(uid: str, b: Reason, ctx: Ctx = Depends(ctx_write)):
        return _wrap(lambda: service.submit(ctx, "user.enable", "idm.user.enable", {"uid": uid, "reason": b.reason}, f"Re-enable {uid}", uid))

    @app.post(f"{T}/users/{{uid}}/delete", status_code=202)
    def user_delete(uid: str, b: Reason, ctx: Ctx = Depends(ctx_write)):
        def go():
            _self_guard(ctx, uid, "delete")
            return service.submit(ctx, "user.delete", "idm.user.delete", {"uid": uid, "reason": b.reason or f"deleted by {ctx.username}"}, f"Delete {uid}", uid)
        return _wrap(go)

    @app.post(f"{T}/users/{{uid}}/reset", status_code=202)
    def user_reset(uid: str, b: Reset, ctx: Ctx = Depends(ctx_write)):
        label = "password" if b.what == "password" else "two-step verification"
        return _wrap(lambda: service.submit(ctx, f"user.reset_{b.what}", "idm.user.reset_credentials", {"uid": uid, "what": b.what, "reason": f"by {ctx.username}"},
                                            f"Reset {label} for {uid}", uid))

    # ---- aliases, shared mailboxes, quotas -------------------------------------------------------------------------------------
    @app.get(f"{T}/aliases")
    def aliases(ctx: Ctx = Depends(ctx_read)):
        if isinstance(ctx, DeploymentCtx):
            raise dep.not_here()
        return service.aliases_view(ctx)

    @app.post(f"{T}/users/{{uid}}/aliases", status_code=202)
    def user_aliases(uid: str, b: AliasChange, ctx: Ctx = Depends(ctx_write)):
        return _wrap(lambda: service.submit(ctx, "user.aliases", "idm.user.set_aliases", {"uid": uid, "add": b.add, "remove": b.remove}, f"Change addresses of {uid}", uid))

    @app.get(f"{T}/shared")
    def shared(ctx: Ctx = Depends(ctx_read)):
        if isinstance(ctx, DeploymentCtx):
            raise dep.not_here()
        return service.shared_view(ctx)

    @app.post(f"{T}/shared", status_code=202)
    def shared_create(b: NewShared, ctx: Ctx = Depends(ctx_write)):
        return _wrap(lambda: service.submit(ctx, "shared.create", "idm.shared_mailbox.create", {"name": b.name, "display_name": b.display_name},
                                            f"Create shared mailbox {b.name}", None))

    @app.post(f"{T}/shared/{{name}}/delete", status_code=202)
    def shared_delete(name: str, b: Reason, ctx: Ctx = Depends(ctx_write)):
        return _wrap(lambda: service.submit(ctx, "shared.delete", "idm.shared_mailbox.delete", {"name": name, "reason": b.reason or f"deleted by {ctx.username}"},
                                            f"Delete shared mailbox {name}", None))

    @app.post(f"{T}/shared/{{name}}/grant", status_code=202)
    def shared_grant(name: str, b: SharedGrant, ctx: Ctx = Depends(ctx_write)):
        return _wrap(lambda: service.submit(ctx, "shared.grant", "idm.shared_mailbox.grant", {"name": name, "uid": b.uid, "kind": b.kind},
                                            f"Give {b.uid} access to {name}", b.uid))

    @app.post(f"{T}/shared/{{name}}/revoke", status_code=202)
    def shared_revoke(name: str, b: SharedGrant, ctx: Ctx = Depends(ctx_write)):
        return _wrap(lambda: service.submit(ctx, "shared.revoke", "idm.shared_mailbox.revoke", {"name": name, "uid": b.uid, "kind": b.kind},
                                            f"Remove access of {b.uid} to {name}", b.uid))

    @app.get(f"{T}/quotas")
    def quotas(live: bool = True, ctx: Ctx = Depends(ctx_read)):
        if isinstance(ctx, DeploymentCtx):
            raise dep.not_here()
        return service.quotas_view(ctx, live)

    @app.post(f"{T}/users/{{uid}}/quota/mail", status_code=202)
    def quota_mail(uid: str, b: MailQuota, ctx: Ctx = Depends(ctx_write)):
        return _wrap(lambda: service.submit(ctx, "quota.mail", "idm.user.set_mail_quota", {"uid": uid, "limit_mb": b.limit_mb}, f"Set mailbox size of {uid}", uid))

    @app.post(f"{T}/users/{{uid}}/quota/files", status_code=202)
    def quota_files(uid: str, b: FilesQuota, ctx: Ctx = Depends(ctx_write)):
        return _wrap(lambda: service.submit(ctx, "quota.files", "idm.user.set_storage_quota", {"uid": uid, "quota_mb": b.quota_mb}, f"Set file storage of {uid}", uid))

    # ---- groups ---------------------------------------------------------------------------------------------------------------
    @app.get(f"{T}/groups")
    def groups(ctx: Ctx = Depends(ctx_read)):
        if isinstance(ctx, DeploymentCtx):
            return dep.groups(ctx)
        ok = service.assignable_groups(ctx)
        rows = ctx.db.execute(text("SELECT groups FROM idm_users WHERE stack_id = :s AND state = 'active'"), {"s": str(ctx.stack_row.id)}).all()
        return [{"name": g, "label": l, "members": sum(1 for r in rows if g in r.groups)} for g, l in ok.items()]

    # ---- requests (the audit-visible work list) --------------------------------------------------------------------------------
    @app.get(f"{T}/requests")
    def requests(ctx: Ctx = Depends(ctx_read)):
        if isinstance(ctx, DeploymentCtx):
            return []   # no changes are requested through this API on a deployment yet
        return service.requests_view(ctx, limit=100)

    @app.get(f"{T}/requests/{{plan_id}}")
    def request_one(plan_id: UUID, ctx: Ctx = Depends(ctx_read)):
        if isinstance(ctx, DeploymentCtx):
            raise HTTPException(404, "request not found")
        r = service.requests_view(ctx, plan_id=plan_id)
        if not r:
            raise HTTPException(404, "request not found")
        return r[0]

    @app.post(f"{T}/requests/{{plan_id}}/approve")
    def request_approve(plan_id: UUID, ctx: Ctx = Depends(ctx_write)):
        return _wrap(lambda: service.decide(ctx, plan_id, True))

    @app.post(f"{T}/requests/{{plan_id}}/reject")
    def request_reject(plan_id: UUID, ctx: Ctx = Depends(ctx_write)):
        return _wrap(lambda: service.decide(ctx, plan_id, False))

    @app.post(f"{T}/requests/{{plan_id}}/enrollment")
    def request_enrollment(plan_id: UUID, ctx: Ctx = Depends(ctx_write)):
        """The one-time sign-up link ingredients, shown ONCE to an org-admin. The ICS never sends it by e-mail."""
        return _wrap(lambda: service.reveal_enrollment(ctx, plan_id))

    # ---- domains --------------------------------------------------------------------------------------------------------------
    @app.get(f"{T}/domains")
    def domains(check: bool = False, ctx: Ctx = Depends(ctx_read)):
        if isinstance(ctx, DeploymentCtx):
            return dep.domains(ctx, check)
        d = ctx.cfg["mail_domain"]
        out = {"domains": [{"name": d, "primary": True}], "managed_by": "Your service provider adds or removes domains."}
        if check:
            out["dns"] = {d: dnscheck.check_domain(d, ctx.cfg.get("mail_host"), ctx.policy["dkim_selector"], resolver=service.HOOKS.get("dns", dnscheck.query))}
        return out

    # ---- operator side: bind a customer ----------------------------------------------------------------------------------------
    @app.post(f"/api/v1/customers/{{customer_id}}/tenant-admin", status_code=201)
    def bind(customer_id: UUID, b: BindIn, request: Request, user: User = Depends(require("admin")), db: Session = Depends(get_db)):
        if user.customer_ids is not None:
            raise HTTPException(403, "needs the all-customers scope")
        try:
            return service.bind(db, rt, user, customer_id, b.stack, portal_client_id=b.portal_client_id, admin_role=b.admin_role,
                                policy={"destructive_approval": b.destructive_approval, "self_service_auto": b.self_service_auto, "dkim_selector": b.dkim_selector},
                                app_groups=b.app_groups or None, ip=client_ip(request))
        except TenantError as e:
            db.rollback()
            raise HTTPException(e.status, e.msg)

    @app.post(f"/api/v1/customers/{{customer_id}}/tenant-admin/rotate-key")
    def rotate(customer_id: UUID, request: Request, user: User = Depends(require("admin")), db: Session = Depends(get_db)):
        if user.customer_ids is not None:
            raise HTTPException(403, "needs the all-customers scope")
        try:
            return service.rotate_key(db, user, customer_id, client_ip(request))
        except TenantError as e:
            db.rollback()
            raise HTTPException(e.status, e.msg)
