"""Admin area for the customer's own administrators (Keycloak realm role `org-admin`). Server-rendered, no JavaScript.

Everything here goes through the ICS tenant API with the administrator's own token. Nothing in this module can reach infrastructure,
and no page ever shows a password: new people receive a one-time sign-up link (made on demand, shown once, never e-mailed by us)."""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, Form, Request, UploadFile, File
from fastapi.responses import RedirectResponse, Response

from .icsclient import ICS, ICSError, parse_time

log = logging.getLogger("ou-portal.admin")
UID = re.compile(r"^[a-z][a-z0-9._-]{1,31}$")
NAME_PART = re.compile(r"[^a-z0-9]+")
HEX = re.compile(r"^#[0-9a-fA-F]{6}$")


def is_admin(cfg, claims: dict) -> bool:
    r = set(claims.get("roles") or []) | set((claims.get("realm_access") or {}).get("roles") or [])
    return cfg.admin_role in r


def suggest_uid(name: str) -> str:
    parts = [p for p in NAME_PART.sub(" ", name.lower()).split() if p]
    if not parts:
        return ""
    return (parts[0] if len(parts) == 1 else f"{parts[0]}.{parts[-1]}")[:32]


def friendly(e: ICSError) -> tuple[str, str]:
    """-> (title, text) in plain language. The ICS writes 404/409/422 messages for people; others are generic."""
    if e.status in (401, 403):
        return ("Your administrator access could not be confirmed",
                "Administrator rights are checked every time. If they were just changed, sign out and back in. " + (e.msg if e.status == 403 and e.msg and e.msg != "not authorised" else ""))
    if e.status in (404, 409, 422) and e.msg:
        return "That could not be done", e.msg
    if e.status == 429:
        return "Please slow down", "Too many requests. Wait a moment and try again."
    return "The administration service is not available", "Nothing was changed. Please try again in a minute."


def mount(app: FastAPI, cfg, H) -> ICS:
    """H provides: render, current, check_csrf, login_redirect, templates (see main.create_app)."""
    ics = ICS(cfg, transport=H.ics_transport)

    async def gate(request: Request, csrf: str | None = None):
        """-> (session, None) or (None, response). Non-admins get the same 404 as an unknown page: the area is not advertised to them."""
        s = await H.current(request)
        if not s:
            return None, H.login_redirect(request)
        if not is_admin(cfg, s.claims):
            return None, H.render(request, "error.html", {"title": "Page not found", "text": "There is nothing at this address."}, 404, s)
        if csrf is not None and not H.check_csrf(request, s, csrf):
            return None, H.render(request, "error.html", {"title": "Request refused", "text": "Please reload the page and try again."}, 403, s)
        return s, None

    def fail(request, s, e: ICSError):
        t, x = friendly(e)
        return H.render(request, "error.html", {"title": t, "text": x, "back": "/admin"}, 503 if e.status in (0, 502, 503) else 400, s)

    def page(request, s, name, ctx=None, status=200):
        return H.render(request, "admin/" + name, {"section": name.split(".")[0], "flash": request.query_params.get("flash"), **(ctx or {})}, status, s)

    async def get(request, s, path, **kw):
        return await ics.call("GET", path, s.access_token, **kw)

    # ---- overview ----------------------------------------------------------------------------------------------------------------------
    @app.get("/admin")
    async def overview(request: Request):
        s, resp = await gate(request)
        if resp:
            return resp
        try:
            me = await get(request, s, "/me")
            reqs = await get(request, s, "/requests")
        except ICSError as e:
            return fail(request, s, e)
        return page(request, s, "overview.html", {"me": me, "waiting": [r for r in reqs if r["can_decide"]], "recent": reqs[:5]})

    # ---- people ------------------------------------------------------------------------------------------------------------------------
    @app.get("/admin/users")
    async def users(request: Request, q: str = "", show: str = "all"):
        s, resp = await gate(request)
        if resp:
            return resp
        try:
            rows = await get(request, s, "/users")
        except ICSError as e:
            return fail(request, s, e)
        ql = q.strip().lower()[:60]
        if ql:
            rows = [r for r in rows if ql in r["display_name"].lower() or ql in r["uid"] or ql in r["mail"]]
        if show in ("active", "disabled"):
            rows = [r for r in rows if r["state"] == show]
        return page(request, s, "users.html", {"users": rows, "q": q[:60], "show": show})

    @app.get("/admin/users/new")
    async def new_user(request: Request, name: str = ""):
        s, resp = await gate(request)
        if resp:
            return resp
        try:
            apps = (await get(request, s, "/apps"))["apps"]
        except ICSError as e:
            return fail(request, s, e)
        return page(request, s, "new_user.html", {"apps": apps, "form": {"name": name, "uid": suggest_uid(name)}, "error": request.query_params.get("error")})

    @app.post("/admin/users/new")
    async def create_user(request: Request, csrf: str = Form(""), name: str = Form(""), uid: str = Form("")):
        s, resp = await gate(request, csrf)
        if resp:
            return resp
        form = await request.form()
        try:
            apps = (await get(request, s, "/apps"))["apps"]
            name, uid = name.strip(), (uid.strip().lower() or suggest_uid(name))
            if not name or not UID.match(uid):
                return page(request, s, "new_user.html", {"apps": apps, "form": {"name": name, "uid": uid}, "error":
                            "Enter the person's full name and a user name of 2 to 32 letters, digits, dots or dashes, starting with a letter."}, 422)
            chosen = {a: (f"app_{a}" in form) for a in apps}
            r = await ics.call("POST", "/users", s.access_token, json={"uid": uid, "display_name": name, "apps": chosen})
        except ICSError as e:
            if e.status in (404, 409, 422) and e.msg:
                return page(request, s, "new_user.html", {"apps": apps, "form": {"name": name, "uid": uid}, "error": e.msg}, 422)
            return fail(request, s, e)
        return RedirectResponse(f"/admin/requests/{r['id']}", status_code=303)

    @app.get("/admin/users/{uid}")
    async def user_detail(request: Request, uid: str):
        s, resp = await gate(request)
        if resp:
            return resp
        try:
            u = await get(request, s, f"/users/{uid}")
            apps = (await get(request, s, "/apps"))["apps"]
        except ICSError as e:
            return fail(request, s, e) if e.status != 404 else H.render(request, "error.html", {"title": "Person not found", "text": "This person is not in your organisation.", "back": "/admin/users"}, 404, s)
        return page(request, s, "user.html", {"u": u, "apps": apps})

    @app.post("/admin/users/{uid}/apps")
    async def user_apps(request: Request, uid: str, csrf: str = Form("")):
        s, resp = await gate(request, csrf)
        if resp:
            return resp
        form = await request.form()
        try:
            u = await get(request, s, f"/users/{uid}")
            apps = (await get(request, s, "/apps"))["apps"]
            add = [apps[a]["group"] for a in apps if f"app_{a}" in form and not u["apps"].get(a)]
            rem = [apps[a]["group"] for a in apps if f"app_{a}" not in form and u["apps"].get(a)]
            if not add and not rem:
                return RedirectResponse(f"/admin/users/{uid}?flash=nochange", status_code=303)
            r = await ics.call("POST", f"/users/{uid}/groups", s.access_token, json={"add": add, "remove": rem})
        except ICSError as e:
            return fail(request, s, e)
        return RedirectResponse(f"/admin/requests/{r['id']}", status_code=303)

    ACTIONS = {
        "disable": ("Disable {name}?", "They are signed out everywhere within seconds and can no longer open mail, files or any app. Nothing is deleted and you can turn access back on later.", "Disable access", "danger"),
        "enable": ("Turn access back on for {name}?", "They will get a new one-time sign-up link to choose a new password. Their old password does not work again.", "Turn access on", "primary"),
        "delete": ("Delete {name}?", "Their sign-in and account are removed. Their mailbox is kept safely on your mail server and cannot be reused for a new person. This needs a second administrator to confirm.", "Delete person", "danger"),
        "reset-password": ("Create a new sign-up link for {name}?", "You get a one-time link to pass on. {name} chooses a new password with it. We never see or set passwords.", "Create link", "primary"),
        "reset-mfa": ("Reset two-step verification for {name}?", "Their authenticator app is removed and they must set up a new one the next time they sign in. They are signed out now.", "Reset two-step verification", "danger"),
    }

    @app.get("/admin/users/{uid}/do/{what}")
    async def confirm(request: Request, uid: str, what: str):
        s, resp = await gate(request)
        if resp:
            return resp
        if what not in ACTIONS:
            return H.render(request, "error.html", {"title": "Page not found", "text": "There is nothing at this address."}, 404, s)
        try:
            u = await get(request, s, f"/users/{uid}")
        except ICSError as e:
            return fail(request, s, e)
        t, d, label, tone = ACTIONS[what]
        n = u["display_name"]
        return page(request, s, "confirm.html", {"u": u, "what": what, "title": t.format(name=n), "text": d.format(name=n), "label": label, "tone": tone})

    @app.post("/admin/users/{uid}/do/{what}")
    async def act(request: Request, uid: str, what: str, csrf: str = Form(""), reason: str = Form("")):
        s, resp = await gate(request, csrf)
        if resp:
            return resp
        if what not in ACTIONS:
            return RedirectResponse("/admin/users", status_code=303)
        path, body = {"disable": ("disable", {"reason": reason[:200]}), "enable": ("enable", {"reason": reason[:200]}), "delete": ("delete", {"reason": reason[:200] or "removed by an administrator"}),
                      "reset-password": ("reset", {"what": "password"}), "reset-mfa": ("reset", {"what": "mfa"})}[what]
        try:
            r = await ics.call("POST", f"/users/{uid}/{path}", s.access_token, json=body)
        except ICSError as e:
            return fail(request, s, e)
        return RedirectResponse(f"/admin/requests/{r['id']}", status_code=303)

    # ---- requests (progress, second-admin approvals, sign-up links) ---------------------------------------------------------------
    @app.get("/admin/requests")
    async def requests_list(request: Request):
        s, resp = await gate(request)
        if resp:
            return resp
        try:
            rows = await get(request, s, "/requests")
        except ICSError as e:
            return fail(request, s, e)
        return page(request, s, "requests.html", {"rows": rows})

    @app.get("/admin/requests/{rid}")
    async def request_detail(request: Request, rid: str):
        s, resp = await gate(request)
        if resp:
            return resp
        try:
            r = await get(request, s, f"/requests/{rid}")
        except ICSError as e:
            return fail(request, s, e)
        return page(request, s, "request.html", {"r": r, "link": None, "working": r["state"] == "working",
                                                 "can_link": r["state"] == "done" and r["kind"] in ("user.create", "user.enable", "user.reset_password")})

    @app.post("/admin/requests/{rid}/decide")
    async def decide(request: Request, rid: str, csrf: str = Form(""), decision: str = Form("")):
        s, resp = await gate(request, csrf)
        if resp:
            return resp
        try:
            await ics.call("POST", f"/requests/{rid}/" + ("approve" if decision == "approve" else "reject"), s.access_token)
        except ICSError as e:
            return fail(request, s, e)
        return RedirectResponse(f"/admin/requests/{rid}?flash={'approved' if decision == 'approve' else 'declined'}", status_code=303)

    @app.post("/admin/requests/{rid}/link")
    async def make_link(request: Request, rid: str, csrf: str = Form("")):
        s, resp = await gate(request, csrf)
        if resp:
            return resp
        try:
            e = await ics.call("POST", f"/requests/{rid}/enrollment", s.access_token)
            r = await get(request, s, f"/requests/{rid}")
        except ICSError as ex:
            return fail(request, s, ex)
        from urllib.parse import urlencode
        link = f"{cfg.base_url}/welcome?" + urlencode({"s": e["stack"], "u": e["uid"], "t": e["token"]})
        exp = parse_time(e["expires_at"])
        return page(request, s, "request.html", {"r": r, "link": link, "expires": exp, "working": False, "can_link": False})

    # ---- groups and apps ---------------------------------------------------------------------------------------------------------------
    @app.get("/admin/groups")
    async def groups(request: Request):
        s, resp = await gate(request)
        if resp:
            return resp
        try:
            g = await get(request, s, "/groups")
            apps = (await get(request, s, "/apps"))["apps"]
        except ICSError as e:
            return fail(request, s, e)
        return page(request, s, "groups.html", {"groups": g, "apps": apps})

    @app.post("/admin/apps")
    async def set_apps(request: Request, csrf: str = Form("")):
        s, resp = await gate(request, csrf)
        if resp:
            return resp
        form = await request.form()
        try:
            apps = (await get(request, s, "/apps"))["apps"]
            await ics.call("PUT", "/apps", s.access_token, json={"apps": {a: (f"app_{a}" in form) for a in apps}})
            ics.forget_branding()
        except ICSError as e:
            return fail(request, s, e)
        return RedirectResponse("/admin/groups?flash=saved", status_code=303)

    # ---- addresses (aliases), shared mailboxes, storage ---------------------------------------------------------------------------------
    ALIAS_LOCAL = re.compile(r"^[a-z0-9][a-z0-9._+-]{0,63}$")

    def needs(me, feature):
        return (me.get("features") or {}).get(feature)

    @app.get("/admin/addresses")
    async def addresses(request: Request):
        s, resp = await gate(request)
        if resp:
            return resp
        try:
            me = await get(request, s, "/me")
            v = await get(request, s, "/aliases") if needs(me, "aliases") else None
        except ICSError as e:
            return fail(request, s, e)
        return page(request, s, "addresses.html", {"v": v, "error": request.query_params.get("error")})

    @app.post("/admin/addresses/{uid}")
    async def address_change(request: Request, uid: str, csrf: str = Form(""), local: str = Form(""), domain: str = Form("")):
        s, resp = await gate(request, csrf)
        if resp:
            return resp
        form = await request.form()
        add, rem = [], [x for x in form.getlist("remove")][:20]
        local = local.strip().lower()
        if local:
            if not ALIAS_LOCAL.match(local) or not re.match(r"^[a-z0-9.-]{3,200}$", domain.strip().lower()):
                return RedirectResponse(f"/admin/addresses?error=badaddress", status_code=303)
            add = [f"{local}@{domain.strip().lower()}"]
        if not add and not rem:
            return RedirectResponse("/admin/addresses?flash=nochange", status_code=303)
        try:
            r = await ics.call("POST", f"/users/{uid}/aliases", s.access_token, json={"add": add, "remove": rem})
        except ICSError as e:
            if e.status in (404, 409, 422) and e.msg:
                v = await get(request, s, "/aliases")
                return page(request, s, "addresses.html", {"v": v, "error": e.msg}, 422)
            return fail(request, s, e)
        return RedirectResponse(f"/admin/requests/{r['id']}", status_code=303)

    @app.get("/admin/shared")
    async def shared_list(request: Request):
        s, resp = await gate(request)
        if resp:
            return resp
        try:
            me = await get(request, s, "/me")
            v = await get(request, s, "/shared") if needs(me, "shared") else None
        except ICSError as e:
            return fail(request, s, e)
        return page(request, s, "shared.html", {"v": v, "form": {}, "error": None})

    @app.post("/admin/shared")
    async def shared_create(request: Request, csrf: str = Form(""), name: str = Form(""), display_name: str = Form("")):
        s, resp = await gate(request, csrf)
        if resp:
            return resp
        name, display_name = name.strip().lower(), display_name.strip()
        try:
            if not UID.match(name) or not display_name:
                v = await get(request, s, "/shared")
                return page(request, s, "shared.html", {"v": v, "form": {"name": name, "display_name": display_name},
                            "error": "Enter a display name and an address of 2 to 32 letters, digits, dots or dashes, starting with a letter."}, 422)
            r = await ics.call("POST", "/shared", s.access_token, json={"name": name, "display_name": display_name})
        except ICSError as e:
            if e.status in (404, 409, 422) and e.msg:
                v = await get(request, s, "/shared")
                return page(request, s, "shared.html", {"v": v, "form": {"name": name, "display_name": display_name}, "error": e.msg}, 422)
            return fail(request, s, e)
        return RedirectResponse(f"/admin/requests/{r['id']}", status_code=303)

    @app.get("/admin/shared/{name}")
    async def shared_detail(request: Request, name: str):
        s, resp = await gate(request)
        if resp:
            return resp
        try:
            v = await get(request, s, "/shared")
        except ICSError as e:
            return fail(request, s, e)
        mb = next((m for m in v["mailboxes"] if m["name"] == name), None)
        if mb is None:
            return H.render(request, "error.html", {"title": "Shared mailbox not found", "text": "This shared mailbox does not exist (any more).", "back": "/admin/shared"}, 404, s)
        names = {p["uid"]: p["display_name"] for p in v["people"]}
        return page(request, s, "shared_detail.html", {"mb": mb, "kinds": v["kinds"], "people": v["people"], "names": names, "error": None})

    @app.post("/admin/shared/{name}/{what}")
    async def shared_change(request: Request, name: str, what: str, csrf: str = Form(""), uid: str = Form(""), kind: str = Form(""), reason: str = Form("")):
        s, resp = await gate(request, csrf)
        if resp:
            return resp
        if what not in ("grant", "revoke", "delete"):
            return H.render(request, "error.html", {"title": "Page not found", "text": "There is nothing at this address."}, 404, s)
        body = {"reason": reason[:200] or "removed by an administrator"} if what == "delete" else {"uid": uid, "kind": kind}
        try:
            r = await ics.call("POST", f"/shared/{name}/{what}", s.access_token, json=body)
        except ICSError as e:
            if e.status in (404, 409, 422) and e.msg:
                v = await get(request, s, "/shared")
                mb = next((m for m in v["mailboxes"] if m["name"] == name), None)
                if mb:
                    return page(request, s, "shared_detail.html", {"mb": mb, "kinds": v["kinds"], "people": v["people"], "names": {p["uid"]: p["display_name"] for p in v["people"]}, "error": e.msg}, 422)
            return fail(request, s, e)
        return RedirectResponse(f"/admin/requests/{r['id']}", status_code=303)

    @app.get("/admin/storage")
    async def storage(request: Request):
        s, resp = await gate(request)
        if resp:
            return resp
        try:
            q = await get(request, s, "/quotas")
        except ICSError as e:
            return fail(request, s, e)
        return page(request, s, "storage.html", {"q": q, "error": request.query_params.get("error")})

    @app.post("/admin/storage/{uid}")
    async def storage_set(request: Request, uid: str, csrf: str = Form(""), mail_mb: str = Form(""), files_mb: str = Form("")):
        s, resp = await gate(request, csrf)
        if resp:
            return resp
        calls = []
        for field, path, key in ((mail_mb, "mail", "limit_mb"), (files_mb, "files", "quota_mb")):
            field = field.strip()
            if not field:
                continue
            if not field.isdigit() or int(field) > 10_000_000:
                return RedirectResponse("/admin/storage?error=badnumber", status_code=303)
            calls.append((path, {key: (int(field) or None)}))      # 0 = no limit
        if not calls:
            return RedirectResponse("/admin/storage?flash=nochange", status_code=303)
        rid = None
        try:
            for path, body in calls:
                r = await ics.call("POST", f"/users/{uid}/quota/{path}", s.access_token, json=body)
                rid = rid or r["id"]
        except ICSError as e:
            if e.status in (404, 409, 422) and e.msg:
                q = await get(request, s, "/quotas")
                return page(request, s, "storage.html", {"q": q, "error": e.msg}, 422)
            return fail(request, s, e)
        return RedirectResponse(f"/admin/requests/{rid}", status_code=303)

    # ---- domains -----------------------------------------------------------------------------------------------------------------------
    @app.get("/admin/domains")
    async def domains(request: Request, check: str = ""):
        s, resp = await gate(request)
        if resp:
            return resp
        try:
            d = await get(request, s, "/domains", params={"check": "true"} if check else None)
        except ICSError as e:
            return fail(request, s, e)
        return page(request, s, "domains.html", {"d": d, "checked": bool(check)})

    # ---- branding ----------------------------------------------------------------------------------------------------------------------
    @app.get("/admin/branding")
    async def branding(request: Request):
        s, resp = await gate(request)
        if resp:
            return resp
        try:
            b = await ics.call("GET", "/branding")
        except ICSError as e:
            return fail(request, s, e)
        return page(request, s, "branding.html", {"b": b, "error": request.query_params.get("error")})

    @app.post("/admin/branding")
    async def save_branding(request: Request, csrf: str = Form(""), display_name: str = Form(""), accent: str = Form(""),
                            logo: UploadFile | None = File(None), remove_logo: str = Form("")):
        s, resp = await gate(request, csrf)
        if resp:
            return resp
        try:
            await ics.call("PUT", "/branding", s.access_token, json={"display_name": display_name or None, "accent": accent or None})
            if remove_logo:
                await ics.call("DELETE", "/branding/logo", s.access_token)
            elif logo is not None and logo.filename:
                data = await logo.read(200_001)
                await ics.call("PUT", "/branding/logo", s.access_token, content=data)
        except ICSError as e:
            ics.forget_branding()
            if e.status == 422 and e.msg:
                b = await ics.call("GET", "/branding")
                return page(request, s, "branding.html", {"b": b, "error": e.msg}, 422)
            return fail(request, s, e)
        ics.forget_branding()
        return RedirectResponse("/admin/branding?flash=saved", status_code=303)

    return ics
