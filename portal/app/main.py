"""Office Unbound user portal: BFF with OIDC (code + PKCE), server-rendered, no JavaScript, strict CSP."""
from __future__ import annotations

import hmac
import logging
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

from . import devices, services
from .config import Settings, load
from .version import PORTAL_VERSION, build_info
from .oidc import OIDC, OIDCError, new_pkce
from .sessions import COOKIE, FLOW_COOKIE, Session, Store

log = logging.getLogger("ou-portal")
HERE = Path(__file__).parent
VERSION = PORTAL_VERSION
KINDS = ("document", "spreadsheet", "presentation")


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

    app = FastAPI(title="Office Unbound portal", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=str(HERE / "templates"))
    templates.env.globals.update(cfg=cfg, version=VERSION)
    templates.env.filters["ago"] = lambda d: services.ago(d)
    templates.env.filters["size"] = services.human_size
    app.state.store, app.state.state = store, state

    csp = ("default-src 'none'; style-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
           f"form-action 'self' {cfg.issuer_origin} {cfg.files_url}; manifest-src 'self'")

    @app.middleware("http")
    async def headers(request: Request, call_next):
        resp = await call_next(request)
        h = resp.headers
        h["Content-Security-Policy"] = csp
        h["X-Content-Type-Options"] = "nosniff"
        h["Referrer-Policy"] = "same-origin"
        h["Strict-Transport-Security"] = "max-age=31536000"
        h["Cross-Origin-Opener-Policy"] = "same-origin"
        h["Cross-Origin-Resource-Policy"] = "same-origin"
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        if not request.url.path.startswith("/static/") and "Cache-Control" not in h:
            h["Cache-Control"] = "no-store"
        return resp

    # ---- helpers --------------------------------------------------------------------------------------------------
    def render(request: Request, name: str, ctx: dict | None = None, status: int = 200, sess: Session | None = None) -> Response:
        c = {"request": request, "sess": sess, "user": user_ctx(sess) if sess else None, **(ctx or {})}
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

    @app.get("/login")
    async def login(request: Request, next: str = "/") -> Response:
        verifier, challenge = new_pkce()
        nonce = secrets.token_urlsafe(24)
        st = store.new_flow(verifier, nonce, safe_next(next), request.client.host if request.client else "")
        try:
            url = await state["oidc"].auth_url(st, nonce, challenge)
        except (httpx.HTTPError, OIDCError):
            return render(request, "error.html", {"title": "Sign-in is unavailable", "text": "The sign-in service did not answer. Please try again in a minute."}, 503)
        resp = RedirectResponse(url, status_code=303)
        set_cookie(resp, FLOW_COOKIE, st, 600)               # binds the flow to THIS browser (login-CSRF protection)
        return resp

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
        resp = RedirectResponse(flow.next, status_code=303)
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
            return render(request, "landing.html")
        notices, recent = [], []
        try:
            recent = await services.recent_files(cfg, state["http"], s.access_token, s.claims.get("preferred_username", ""))
        except (services.ServiceError, httpx.HTTPError) as e:
            log.warning("recent files unavailable: %s", e)
            notices.append("Your recent files could not be loaded right now. Files itself may still work.")
        return render(request, "home.html", {"recent": recent, "notices": notices, "kinds": KINDS,
                                             "flash": request.query_params.get("flash")}, sess=s)

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
        notices, sessions, mfa = [], [], None
        try:
            sessions = await services.account_sessions(cfg, state["http"], s.access_token)
            mfa = (await services.credential_summary(cfg, state["http"], s.access_token))["second_factor"]
        except (services.ServiceError, httpx.HTTPError) as e:
            log.warning("account api unavailable: %s", e)
            notices.append("Your sign-in activity could not be loaded right now.")
        back = f"?referrer={cfg.client_id}&referrer_uri={cfg.base_url}/account"
        links = {"password": cfg.account_url + "/account-security/signing-in" + back,
                 "mfa": cfg.account_url + "/account-security/signing-in" + back,
                 "activity": cfg.account_url + "/account-security/device-activity" + back,
                 "profile": cfg.account_url + "/" + back}
        c = s.claims
        roles = sorted(r for r in c.get("roles", []) if not r.startswith(("default-roles", "uma_", "offline_")))
        return render(request, "account.html", {"claims": c, "roles": roles, "sessions": sessions[:8], "mfa": mfa, "links": links,
                                                "notices": notices, "current_sid": c.get("sid"), "total_sessions": len(sessions),
                                                "flash": request.query_params.get("flash")}, sess=s)

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
        return render(request, "devices.html", {"hint": hint, "desktop": devices.DESKTOP_DOWNLOADS, "release": devices.DESKTOP_RELEASE,
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

    return app
