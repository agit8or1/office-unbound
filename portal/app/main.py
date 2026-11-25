"""Office Unbound user portal: BFF with OIDC (code + PKCE), server-rendered, no JavaScript, strict CSP."""
from __future__ import annotations

import hmac
import logging
import re
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import admin, devices, office_apps, services
from .config import Settings, load
from .version import PORTAL_VERSION, build_info
from .icsclient import parse_time as admin_time
from .oidc import OIDC, OIDCError, new_pkce
from .sessions import COOKIE, FLOW_COOKIE, Session, Store

log = logging.getLogger("ou-portal")
HERE = Path(__file__).parent
VERSION = PORTAL_VERSION
KINDS = ("document", "spreadsheet", "presentation")
HEXRE = re.compile(r"^#[0-9a-fA-F]{6}$")


def css_string(text: str) -> str:
    """A CSS string literal of untrusted text: letters, digits and spaces as they are, everything else as a CSS hex escape, so nothing can
    end the string, the declaration or the rule."""
    return '"' + "".join(ch if (ch.isalnum() and ch.isascii()) or ch == " " else f"\\{ord(ch):x} " for ch in text) + '"'


PREFS_COOKIE = "ou_prefs"
NOTES_TTL = 60   # seconds between two reads of the Files notifications for one session (the bell in the top bar)
THEMES = ("system", "light", "dark")
WIDGETS = {"inbox": "Inbox", "calendar": "Calendar", "recent": "Recent files", "favorites": "Favourites", "shared": "Shared with me",
           "create": "Quick create"}


def parse_prefs(raw: str | None) -> dict:
    """The appearance cookie, `<theme>:<hidden widget>.<...>` (cookie-safe characters only): anything else is ignored, it is only a
    preference and never trusted."""
    theme, _, hidden = (raw or "")[:200].partition(":")
    return {"theme": theme if theme in THEMES else "system", "hidden": [w for w in hidden.split(".") if w in WIDGETS]}


def dump_prefs(p: dict) -> str:
    return f"{p['theme']}:{'.'.join(p['hidden'])}"


def week_days(now: float | None = None) -> list[dict]:
    """Today and the six days after it, for the dashboard's week strip (dates only: no events are shown that were not read)."""
    t = time.localtime(now if now is not None else time.time())
    base = time.mktime((t.tm_year, t.tm_mon, t.tm_mday, 12, 0, 0, 0, 0, -1))
    days = [time.localtime(base + i * 86400) for i in range(7)]
    return [{"wd": time.strftime("%a", d), "day": d.tm_mday, "today": i == 0} for i, d in enumerate(days)]


def safe_next(p: str | None) -> str:
    """Only same-site absolute paths: blocks open redirects (//evil, /\\evil, schemes)."""
    if (p and p.startswith("/") and not p.startswith("//") and "\\" not in p
            and all(0x20 < ord(c) < 0x7f or ord(c) > 0xa0 for c in p)      # review 3 L7: no control chars (incl. TAB), space or DEL
            and not urlsplit(p).netloc and not urlsplit(p).scheme):
        return p
    return "/"


def create_app(cfg: Settings | None = None, transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    cfg = cfg or load()
    store = Store(cfg.session_ttl)
    state: dict = {}

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        client = httpx.AsyncClient(timeout=cfg.http_timeout, verify=cfg.ca_bundle or True, transport=transport,
                                   follow_redirects=False, headers={"User-Agent": f"ou-portal/{VERSION}"})
        state["http"], state["oidc"] = client, OIDC(cfg, client)
        yield
        await client.aclose()
        if state.get("ics"):
            await state["ics"].close()

    app = FastAPI(title="Office Unbound portal", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=str(HERE / "templates"))
    templates.env.globals.update(cfg=cfg, version=VERSION)
    templates.env.filters["ago"] = lambda d: services.ago(d)
    templates.env.filters["size"] = services.human_size
    templates.env.filters["isoago"] = lambda v: services.ago(admin_time(v)) if v else "never"
    app.state.store, app.state.state = store, state

    csp = ("default-src 'none'; style-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
           f"form-action 'self' {cfg.issuer_origin} {cfg.files_url}; manifest-src 'self'" + (f"; frame-src {cfg.chat_origin}" if cfg.chat_url else ""))

    @app.middleware("http")
    async def headers(request: Request, call_next):
        resp = await call_next(request)
        h = resp.headers
        h.setdefault("Content-Security-Policy", csp)   # a route may only TIGHTEN it (the logo is served with a sandboxing policy)
        h["X-Content-Type-Options"] = "nosniff"
        h.setdefault("Referrer-Policy", "same-origin")
        h["Strict-Transport-Security"] = "max-age=31536000"
        h["Cross-Origin-Opener-Policy"] = "same-origin"
        # /brand/*: the organisation branding every other app of the deployment loads (cloud., mail., auth. are other origins)
        h["Cross-Origin-Resource-Policy"] = "cross-origin" if request.url.path.startswith("/brand/") else "same-origin"
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        if not request.url.path.startswith("/static/") and "Cache-Control" not in h:
            h["Cache-Control"] = "no-store"
        return resp

    @app.middleware("http")
    async def brand_mw(request: Request, call_next):
        ics = state.get("ics")
        page = not request.url.path.startswith(("/static/", "/healthz", "/branding", "/brand/"))
        request.state.brand = await ics.branding() if ics and page else None
        request.state.chat = await services.chat_available(cfg, state["http"]) if page and cfg.chat_url and state.get("http") else False
        return await call_next(request)

    # ---- helpers --------------------------------------------------------------------------------------------------
    def render(request: Request, name: str, ctx: dict | None = None, status: int = 200, sess: Session | None = None) -> Response:
        b = getattr(request.state, "brand", None) or {}
        brand = {"name": b.get("display_name") or cfg.org_name, "accent": b.get("accent") if HEXRE.match(b.get("accent") or "") else None,
                 "logo": bool(b.get("has_logo")), "apps": b.get("apps")}
        c = {"request": request, "sess": sess, "user": user_ctx(sess) if sess else None, "brand": brand,
             "prefs": parse_prefs(request.cookies.get(PREFS_COOKIE)), "widgets": WIDGETS,
             "chat": bool(sess and getattr(request.state, "chat", False)), "notes": sess.notes if sess else [],
             "is_admin": bool(sess and cfg.ics_url and admin.is_admin(cfg, sess.claims)), **(ctx or {})}
        return templates.TemplateResponse(name, c, status_code=status)

    def user_ctx(s: Session) -> dict:
        c = s.claims
        name = c.get("name") or c.get("preferred_username") or c.get("email") or "there"
        return {"name": name, "first": (c.get("given_name") or name.split(" ")[0]), "username": c.get("preferred_username", ""),
                "email": c.get("email", ""), "initial": name[:1].upper()}

    def set_cookie(resp: Response, name: str, value: str, max_age: int) -> None:
        # __Host- prefix: Secure, Path=/, no Domain; HttpOnly; Lax so the top-level redirect back from Keycloak carries it.
        resp.set_cookie(name, value, max_age=max_age, secure=True, httponly=True, samesite="lax", path="/")

    def clear_cookie(resp: Response, name: str) -> None:
        resp.delete_cookie(name, secure=True, httponly=True, samesite="lax", path="/")

    async def current(request: Request) -> Session | None:
        s = store.get(request.cookies.get(COOKIE))
        if not s:
            return None
        if s.access_exp - time.time() < 30:                  # refresh server-side; the browser never sees tokens
            async with s.lock:
                if s.access_exp - time.time() < 30:
                    if not s.refresh_token:
                        store.drop(s.sid)
                        return None
                    try:
                        t = await state["oidc"].refresh(s.refresh_token)
                    except (OIDCError, httpx.HTTPError):
                        store.drop(s.sid)
                        return None
                    s.access_token, s.access_exp = t["access_token"], time.time() + int(t.get("expires_in", 300))
                    s.refresh_token = t.get("refresh_token", s.refresh_token)
        if request.method == "GET" and state.get("http") and time.time() - s.notes_at > NOTES_TTL:
            s.notes_at = time.time()                          # also on failure: a slow Files is asked again only after the TTL
            try:
                s.notes = await services.notifications(cfg, state["http"], s.access_token)
            except (services.ServiceError, httpx.HTTPError) as e:
                log.warning("notifications unavailable: %s", e)
                s.notes = None
        return s

    def login_redirect(request: Request) -> Response:
        nxt = request.url.path + (("?" + request.url.query) if request.url.query else "")
        return RedirectResponse("/login?" + httpx.QueryParams({"next": nxt}).__str__(), status_code=303)

    def check_csrf(request: Request, s: Session, token: str) -> bool:
        origin = request.headers.get("origin")
        if origin and origin != cfg.base_url:
            return False
        return hmac.compare_digest(token or "", s.csrf)

    # ---- public ----------------------------------------------------------------------------------------------------
    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> Response:
        return Response("ok\n", media_type="text/plain")

    @app.get("/about", response_class=HTMLResponse)
    async def about(request: Request) -> Response:
        s = await current(request)
        info = build_info()
        if not s:  # signed-out visitors see the product and version only
            info = {k: info[k] for k in ("product", "version")}
        return render(request, "about.html", {"info": info}, sess=s)

    @app.get("/.well-known/autoconfig/mail/config-v1.1.xml", include_in_schema=False)
    @app.get("/mail/config-v1.1.xml", include_in_schema=False)
    async def autoconfig() -> Response:
        # Public by design: Thunderbird fetches it before the user has any credential. Contains server names only.
        return Response(devices.autoconfig_xml(cfg), media_type="application/xml",
                        headers={"Cache-Control": "public, max-age=3600"})

    async def start_flow(request: Request, next: str, kc_action: str | None = None) -> Response:
        verifier, challenge = new_pkce()
        nonce = secrets.token_urlsafe(24)
        st = store.new_flow(verifier, nonce, safe_next(next), request.client.host if request.client else "")
        try:
            url = await state["oidc"].auth_url(st, nonce, challenge, kc_action)
        except (httpx.HTTPError, OIDCError):
            return render(request, "error.html", {"title": "Sign-in is unavailable", "text": "The sign-in service did not answer. Please try again in a minute."}, 503)
        resp = RedirectResponse(url, status_code=303)
        set_cookie(resp, FLOW_COOKIE, st, 600)               # binds the flow to THIS browser (login-CSRF protection)
        return resp

    @app.get("/login")
    async def login(request: Request, next: str = "/") -> Response:
        return await start_flow(request, next)

    # Change password / set up two-step verification: the sign-in service's own pages (it checks the current password and writes the directory),
    # then straight back to the account page. Only these fixed actions; the user is asked to sign in again first if the session is old.
    ACCOUNT_ACTIONS = {"password": ("UPDATE_PASSWORD", "password"), "two-step": ("CONFIGURE_TOTP", "two-step")}

    @app.get("/account/{what}")
    async def account_action(request: Request, what: str) -> Response:
        if what not in ACCOUNT_ACTIONS:
            return render(request, "error.html", {"title": "Not found", "text": "There is no such page."}, 404)
        s = await current(request)
        if not s:
            return login_redirect(request)
        action, flash = ACCOUNT_ACTIONS[what]
        return await start_flow(request, f"/account?flash={flash}", action)

    @app.get("/auth/callback")
    async def callback(request: Request) -> Response:
        q = request.query_params
        st = q.get("state", "")
        flow = store.pop_flow(st)
        bound = request.cookies.get(FLOW_COOKIE, "")
        fail = lambda msg: render(request, "error.html", {"title": "We could not sign you in", "text": msg, "retry": True}, 400)  # noqa: E731
        if not flow or not hmac.compare_digest(bound, st):
            return fail("The sign-in link has expired or was opened in a different browser. Please start again.")
        if q.get("error") or not q.get("code"):
            return fail("Sign-in was cancelled or refused.")
        try:
            tok = await state["oidc"].exchange_code(q["code"], flow.verifier)
            claims = await state["oidc"].verify_id_token(tok["id_token"], flow.nonce)
        except (OIDCError, httpx.HTTPError, KeyError) as e:
            log.warning("login failed: %s", type(e).__name__)
            return fail("The sign-in service could not confirm your identity. Please try again.")
        s = store.create(claims=claims, id_token=tok["id_token"], access_token=tok["access_token"],
                         refresh_token=tok.get("refresh_token"), access_exp=time.time() + int(tok.get("expires_in", 300)))
        store.drop(request.cookies.get(COOKIE))              # an account action re-signs in: the new session replaces the old one
        nxt = flow.next
        if q.get("kc_action_status") and q["kc_action_status"] != "success" and nxt.startswith("/account?flash="):
            nxt = "/account?flash=" + ("cancelled" if q["kc_action_status"] == "cancelled" else "failed")
        resp = RedirectResponse(nxt, status_code=303)
        set_cookie(resp, COOKIE, s.sid, cfg.session_ttl)
        clear_cookie(resp, FLOW_COOKIE)
        return resp

    @app.post("/logout")
    async def logout(request: Request, csrf: str = Form("")) -> Response:
        s = store.get(request.cookies.get(COOKIE))
        if s and not check_csrf(request, s, csrf):
            return render(request, "error.html", {"title": "Request refused", "text": "Please reload the page and try again."}, 403, s)
        try:
            url = await state["oidc"].logout_url(s.id_token if s else None)
        except (httpx.HTTPError, OIDCError):
            url = "/"
        store.drop(s.sid if s else None)
        resp = RedirectResponse(url, status_code=303)
        clear_cookie(resp, COOKIE)
        return resp

    # ---- signed in -------------------------------------------------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request) -> Response:
        s = await current(request)
        if not s:
            # owner 2026-11-20: "https://app.<domain>/ should go right to auth": no intermediate page, straight to the sign-in service
            return RedirectResponse("/login", status_code=303)
        prefs = parse_prefs(request.cookies.get(PREFS_COOKIE))
        notices, recent, shared, favorites = [], [], [], []
        user = s.claims.get("preferred_username", "")
        if "recent" not in prefs["hidden"]:
            try:
                recent = await services.recent_files(cfg, state["http"], s.access_token, user, limit=8)
            except (services.ServiceError, httpx.HTTPError) as e:
                log.warning("recent files unavailable: %s", e)
                recent = None
        if "shared" not in prefs["hidden"]:
            try:
                shared = await services.shared_with_me(cfg, state["http"], s.access_token)
            except (services.ServiceError, httpx.HTTPError) as e:
                log.warning("shared-with-me unavailable: %s", e)
                shared = None
        if "favorites" not in prefs["hidden"]:
            try:
                favorites = await services.favorite_files(cfg, state["http"], s.access_token, user)
            except (services.ServiceError, httpx.HTTPError) as e:
                log.warning("favourites unavailable: %s", e)
                favorites = None
        return render(request, "home.html", {"recent": recent, "shared": shared, "favorites": favorites, "notices": notices, "kinds": KINDS,
                                             "today": time.strftime("%A, %d %B %Y"), "week": week_days(),
                                             "flash": request.query_params.get("flash")}, sess=s)

    @app.get("/search", response_class=HTMLResponse)
    async def search(request: Request, q: str = "") -> Response:
        s = await current(request)
        if not s:
            return login_redirect(request)
        term, results, failed = services.search_term(q), [], False
        if term:
            try:
                results = await services.search_files(cfg, state["http"], s.access_token, s.claims.get("preferred_username", ""), term)
            except (services.ServiceError, httpx.HTTPError) as e:
                log.warning("search failed: %s", e)
                failed = True
        return render(request, "search.html", {"q": term, "fileq": term, "results": results, "failed": failed}, sess=s)

    @app.post("/prefs")
    async def save_prefs(request: Request) -> Response:
        s = await current(request)
        if not s:
            return login_redirect(request)
        form = await request.form()
        if not check_csrf(request, s, str(form.get("csrf", ""))):
            return render(request, "error.html", {"title": "Request refused", "text": "Please reload the page and try again."}, 403, s)
        p = parse_prefs(request.cookies.get(PREFS_COOKIE))
        if str(form.get("theme", "")) in THEMES:
            p["theme"] = str(form["theme"])
        if form.get("widgets_form"):                     # the Customise panel lists every widget: an unticked one is hidden
            shown = {str(v) for v in form.getlist("show")}
            p["hidden"] = [w for w in WIDGETS if w not in shown]
        resp = RedirectResponse(safe_next(str(form.get("next", "/"))), status_code=303)
        resp.set_cookie(PREFS_COOKIE, dump_prefs(p), max_age=400 * 86400, secure=True, httponly=True, samesite="lax", path="/")
        return resp

    @app.post("/new/{kind}")
    async def new_doc(request: Request, kind: str, csrf: str = Form("")) -> Response:
        s = await current(request)
        if not s:
            return login_redirect(request)
        if kind not in KINDS:
            return render(request, "error.html", {"title": "Not found", "text": "Unknown document type."}, 404, s)
        if not check_csrf(request, s, csrf):
            return render(request, "error.html", {"title": "Request refused", "text": "Please reload the page and try again."}, 403, s)
        try:
            if not s.drive:
                s.drive = await services.my_drive(cfg, state["http"], s.access_token)
            url = await services.create_document(cfg, state["http"], s.access_token, s.drive, kind)
        except (services.ServiceError, httpx.HTTPError) as e:
            log.warning("create %s failed: %s", kind, e)
            return render(request, "error.html", {"title": "Could not create the document",
                                                  "text": "Files did not accept the request. Please try again in a moment."}, 502, s)
        return RedirectResponse(url, status_code=303)

    @app.get("/account", response_class=HTMLResponse)
    async def account(request: Request) -> Response:
        s = await current(request)
        if not s:
            return login_redirect(request)
        notices, sessions, mfa, profile = [], [], None, None
        try:
            profile = (await services.get_profile(cfg, state["http"], s.access_token))["fields"]
        except (services.ServiceError, httpx.HTTPError, ValueError) as e:
            log.warning("profile unavailable: %s", e)
        try:
            sessions = await services.account_sessions(cfg, state["http"], s.access_token)
            mfa = (await services.credential_summary(cfg, state["http"], s.access_token))["second_factor"]
        except (services.ServiceError, httpx.HTTPError) as e:
            log.warning("account api unavailable: %s", e)
            notices.append("Your sign-in activity could not be loaded right now.")
        back = f"?referrer={cfg.client_id}&referrer_uri={cfg.base_url}/account"
        links = {"password": "/account/password", "two_step": "/account/two-step",
                 "mfa": cfg.account_url + "/account-security/signing-in" + back,
                 "activity": cfg.account_url + "/account-security/device-activity" + back,
                 "profile": cfg.account_url + "/" + back}
        c = s.claims
        roles = sorted(r for r in c.get("roles", []) if not r.startswith(("default-roles", "uma_", "offline_")))
        errors = request.query_params.get("err", "")
        return render(request, "account.html", {"claims": c, "roles": roles, "sessions": sessions[:8], "mfa": mfa, "links": links, "profile": profile,
                                                "editable": any(f["editable"] for f in profile or []),
                                                "errors": [e for e in errors.split(",") if e in services.PROFILE_FIELDS],
                                                "notices": notices, "current_sid": c.get("sid"), "total_sessions": len(sessions),
                                                "flash": request.query_params.get("flash")}, sess=s)

    @app.post("/account/profile")
    async def save_profile(request: Request) -> Response:
        s = await current(request)
        if not s:
            return login_redirect(request)
        form = await request.form()
        if not check_csrf(request, s, str(form.get("csrf", ""))):
            return render(request, "error.html", {"title": "Request refused", "text": "Please reload the page and try again."}, 403, s)
        try:
            await services.update_profile(cfg, state["http"], s.access_token, {k: str(form.get(k, "")) for k in services.PROFILE_FIELDS if k in form})
        except services.ProfileRejected as e:
            bad = sorted({x["field"] for x in e.errors if x["field"] in services.PROFILE_FIELDS})
            return RedirectResponse("/account?flash=invalid" + ("&err=" + ",".join(bad) if bad else "") + "#h-profile", status_code=303)
        except (services.ServiceError, httpx.HTTPError):
            return RedirectResponse("/account?flash=failed#h-profile", status_code=303)
        # the names in this session's ID token are now stale: the header shows the new ones after the next sign-in; the page reads them fresh
        return RedirectResponse("/account?flash=saved#h-profile", status_code=303)

    @app.post("/account/sessions/end-others")
    async def end_others(request: Request, csrf: str = Form("")) -> Response:
        s = await current(request)
        if not s:
            return login_redirect(request)
        if not check_csrf(request, s, csrf):
            return render(request, "error.html", {"title": "Request refused", "text": "Please reload the page and try again."}, 403, s)
        try:
            await services.end_other_sessions(cfg, state["http"], s.access_token)
        except (services.ServiceError, httpx.HTTPError):
            return RedirectResponse("/account?flash=failed", status_code=303)
        return RedirectResponse("/account?flash=ended", status_code=303)

    @app.get("/devices", response_class=HTMLResponse)
    async def devices_page(request: Request) -> Response:
        s = await current(request)
        if not s:
            return login_redirect(request)
        hint = devices.platform_hint(request.headers.get("user-agent", ""))
        q = request.query_params
        office = {"apps": office_apps.filtered(q.get("os"), q.get("kind")), "os": q.get("os") if q.get("os") in office_apps.OS_KEYS else "",
                  "kind": q.get("kind") if q.get("kind") in office_apps.KINDS else "", "os_keys": office_apps.OS_KEYS, "kinds": office_apps.KINDS,
                  "cols": office_apps.MATRIX_COLS, "verified": office_apps.VERIFIED}
        return render(request, "devices.html", {"hint": hint, "desktop": devices.DESKTOP_DOWNLOADS, "release": devices.DESKTOP_RELEASE, "office": office,
                                                "releases_page": devices.DESKTOP_RELEASES_PAGE, "apps": devices.MOBILE_APPS,
                                                "email": s.claims.get("email", "")}, sess=s)

    @app.get("/devices/apple.mobileconfig")
    async def apple_profile(request: Request) -> Response:
        s = await current(request)
        if not s:
            return login_redirect(request)
        email = s.claims.get("email")
        if not email:
            return render(request, "error.html", {"title": "No e-mail address", "text": "Your account has no e-mail address yet."}, 409, s)
        body = devices.mobileconfig(cfg, email, s.claims.get("name") or email)
        return Response(body, media_type="application/x-apple-aspen-config",
                        headers={"Content-Disposition": 'attachment; filename="office-unbound.mobileconfig"'})

    @app.get("/devices/thunderbird.xml")
    async def thunderbird_xml(request: Request) -> Response:
        s = await current(request)
        if not s:
            return login_redirect(request)
        return Response(devices.autoconfig_xml(cfg), media_type="application/xml",
                        headers={"Content-Disposition": 'attachment; filename="config-v1.1.xml"'})

    # ---- organisation branding for the OTHER apps (sign-in pages, Files, Docs, webmail: ics/ics/deploy/brand.py skins @import this) ----
    @app.get("/brand/org.css", include_in_schema=False)
    async def brand_org_css() -> Response:
        """--ou-org-* custom properties: the organisation accent (light/dark, soft tints) and logo; empty when none is set. Public: the same
        values the signed-out portal pages show. Light and dark tints mix with the portal's own background tokens."""
        b = (await state["ics"].branding() if state.get("ics") else None) or {}
        a = b.get("accent") or ""
        props = []
        if HEXRE.match(a):
            props += [f"--ou-org-accent:{a}", f"--ou-org-accent-dark:color-mix(in srgb,{a} 55%,#fff)",
                      f"--ou-org-soft:color-mix(in srgb,{a} 14%,#f7f5f0)", f"--ou-org-soft-dark:color-mix(in srgb,{a} 28%,#0f1926)"]
        if b.get("has_logo") and re.fullmatch(r"https://[a-z0-9.-]+(:[0-9]{1,5})?", cfg.base_url):
            props.append(f'--ou-org-logo:url("{cfg.base_url}/brand/logo")')
        name = (b.get("display_name") or "").strip()
        # the organisation's name for the other apps' headers (sign-in page). A deployment without a name of its own reports its mail
        # domain: that is not a name, the apps then say Office Unbound.
        if name and name.lower() != (cfg.mail_domain or "").lower():
            props.append(f"--ou-org-name:{css_string(name[:80])}")
        css = (":root{" + ";".join(props) + "}\n") if props else ""
        return Response(css, media_type="text/css", headers={"Cache-Control": "no-cache"})

    @app.get("/brand/logo", include_in_schema=False)
    async def brand_logo() -> Response:
        r = await state["ics"].logo() if state.get("ics") else None
        if not r:
            return Response(status_code=404)
        return Response(r[0], media_type=r[1], headers={"Cache-Control": "no-cache", "Content-Security-Policy": "default-src 'none'; sandbox"})

    if cfg.ics_url:
        class H:  # what the admin area needs from this module
            pass
        h = H()
        h.render, h.current, h.check_csrf, h.login_redirect, h.ics_transport = render, current, check_csrf, login_redirect, transport
        state["ics"] = admin.mount(app, cfg, h)

        @app.get("/branding.css", include_in_schema=False)
        async def branding_css() -> Response:
            """Per-customer accent colour as CSS variables (strict CSP forbids inline styles, so this is a same-origin stylesheet)."""
            b = await state["ics"].branding()
            a = (b or {}).get("accent") or ""
            css = ""
            if HEXRE.match(a):
                css = (f":root{{--accent:{a};--accent-ink:#fff;--accent-soft:color-mix(in srgb,{a} 14%,var(--bg))}}"
                       f"@media (prefers-color-scheme:dark){{:root{{--accent:color-mix(in srgb,{a} 55%,#fff);--accent-ink:#0f1926;"
                       f"--accent-soft:color-mix(in srgb,{a} 28%,var(--bg))}}}}")
            return Response(css, media_type="text/css", headers={"Cache-Control": "no-cache"})

        @app.get("/branding/logo", include_in_schema=False)
        async def branding_logo() -> Response:
            r = await state["ics"].logo()
            if not r:
                return Response(status_code=404)
            return Response(r[0], media_type=r[1], headers={"Cache-Control": "no-cache", "Content-Security-Policy": "default-src 'none'; sandbox"})

        # ---- one-time sign-up link: the new person chooses their OWN password (relayed to the ICS, never stored or logged here) ----
        def welcome_ctx(s: str, u: str, t: str, error: str | None = None) -> dict:
            return {"s": s, "u": u, "t": t, "error": error}

        @app.get("/welcome", response_class=HTMLResponse)
        async def welcome(request: Request, s: str = "", u: str = "", t: str = "") -> Response:
            if not (s and u and t) or len(t) > 200:
                return render(request, "error.html", {"title": "This link is not complete", "text": "Ask your administrator for a new sign-up link."}, 400)
            resp = render(request, "welcome.html", welcome_ctx(s, u, t))
            resp.headers["Referrer-Policy"] = "no-referrer"
            return resp

        @app.post("/welcome")
        async def welcome_post(request: Request, s: str = Form(""), u: str = Form(""), t: str = Form(""), password: str = Form(""), again: str = Form("")) -> Response:
            origin = request.headers.get("origin")   # "null" is what browsers send after Referrer-Policy: no-referrer; the one-time token is the real CSRF secret here
            if (origin and origin not in (cfg.base_url, "null")) or request.headers.get("sec-fetch-site") == "cross-site":
                return render(request, "error.html", {"title": "Request refused", "text": "Please open the link again."}, 403)
            if password != again:
                return render(request, "welcome.html", welcome_ctx(s, u, t, "The two passwords are not the same."), 422)
            try:
                r = await state["http"].post(cfg.ics_url + "/api/v1/identity/enroll", json={"stack": s, "uid": u, "token": t, "password": password},
                                             **({"timeout": 20}))
            except httpx.HTTPError:
                return render(request, "welcome.html", welcome_ctx(s, u, t, "We could not reach the service just now. Please try again."), 503)
            if r.status_code == 200:
                return render(request, "welcome_done.html", {"u": u})
            if r.status_code == 403:
                return render(request, "error.html", {"title": "This link no longer works", "text": "It may have been used already or has expired. Ask your administrator for a new one."}, 403)
            if r.status_code == 422:
                try:
                    msg = r.json().get("detail")
                except ValueError:
                    msg = None
                return render(request, "welcome.html", welcome_ctx(s, u, t, msg if isinstance(msg, str) else "That password is not allowed."), 422)
            return render(request, "welcome.html", welcome_ctx(s, u, t, "We could not save the password. Please try again in a minute."), 503)

    return app
