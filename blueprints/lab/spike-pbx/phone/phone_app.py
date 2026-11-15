"""Office Unbound web softphone host + SIP credential endpoint (spike).

Keycloak OIDC (confidential client `ou-phone`, code + PKCE) -> the logged-in user may fetch THEIR OWN SIP credential:
  GET  /            softphone page (login redirect if no session)
  GET  /login, /callback, /logout
  GET  /api/me          {user, extension, csrf}
  POST /api/credential  header X-OU-CSRF: <csrf>; same-origin only. Rotates the user's `web` device credential and returns it ONCE.
Every credential issue re-validates the Keycloak session (userinfo) AND the LDAP state (user must have an unlocked extension).
The identity used for SIP is the Keycloak `preferred_username` = LDAP uid; a user can never ask for somebody else's credential.
Strict CSP: scripts/styles only from 'self', WSS only to the PBX.
"""
import base64, hashlib, os, secrets, sys, time
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles

sys.path.insert(0, os.environ.get("OU_PBX_LIB", "/opt/ou-pbx"))
import ou_pbx  # noqa: E402

ISSUER = os.environ.get("KC_ISSUER", "https://auth.ou-lab.internal/realms/ou-lab")
CLIENT_ID = os.environ.get("CLIENT_ID", "ou-phone")
PUBLIC_BASE = os.environ.get("PUBLIC_BASE", "https://phone.ou-lab.internal")
STATIC = os.environ.get("STATIC_DIR", "/opt/ou-phone/static")
SESSION_TTL = int(os.environ.get("SESSION_TTL", "3600"))
CLIENT_SECRET = open(os.environ["CLIENT_SECRET_FILE"]).read().strip()
WSS_ORIGIN = ou_pbx.cfg()["wss_url"]

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self' %s; img-src 'self'; media-src 'self' blob:; "
       "base-uri 'none'; form-action 'self'; frame-ancestors 'none'" % WSS_ORIGIN)
HEADERS = {"Content-Security-Policy": CSP, "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
           "Permissions-Policy": "microphone=(self), camera=(), geolocation=()", "Cache-Control": "no-store",
           "Strict-Transport-Security": "max-age=31536000"}

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
_disc = {}
SESSIONS: dict = {}
PENDING: dict = {}


@app.middleware("http")
async def sec_headers(req, call_next):
    resp = await call_next(req)
    for k, v in HEADERS.items():
        resp.headers.setdefault(k, v)
    return resp


def disco():
    if not _disc:
        _disc.update(httpx.get(ISSUER + "/.well-known/openid-configuration", timeout=10).json())
    return _disc


def session(req: Request):
    s = SESSIONS.get(req.cookies.get("ouphone", ""))
    return s if s and s["exp"] > time.time() else None


def validate(s) -> bool:
    try:
        r = httpx.get(disco()["userinfo_endpoint"], headers={"Authorization": "Bearer " + s["access_token"]}, timeout=10)
    except httpx.HTTPError:
        return False
    return r.status_code == 200 and r.json().get("sub") == s["sub"]


@app.get("/healthz")
def healthz():
    return PlainTextResponse("ok")


@app.get("/login")
def login():
    verifier = secrets.token_urlsafe(48)
    state = secrets.token_urlsafe(24)
    PENDING[state] = {"verifier": verifier, "exp": time.time() + 600}
    for k in [k for k, v in PENDING.items() if v["exp"] < time.time()]:
        PENDING.pop(k, None)
    ch = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    q = httpx.QueryParams({"client_id": CLIENT_ID, "response_type": "code", "scope": "openid profile email",
                           "redirect_uri": PUBLIC_BASE + "/callback", "state": state, "code_challenge": ch, "code_challenge_method": "S256"})
    return RedirectResponse(disco()["authorization_endpoint"] + "?" + str(q), status_code=302)


@app.get("/callback")
def callback(code: str = "", state: str = "", error: str = ""):
    p = PENDING.pop(state, None)
    if error or not p or p["exp"] < time.time() or not code:
        return PlainTextResponse("login failed", status_code=400)
    d = disco()
    t = httpx.post(d["token_endpoint"], data={"grant_type": "authorization_code", "code": code, "redirect_uri": PUBLIC_BASE + "/callback",
                                              "code_verifier": p["verifier"]}, auth=(CLIENT_ID, CLIENT_SECRET), timeout=10)
    if t.status_code != 200:
        return PlainTextResponse("token exchange failed", status_code=502)
    at = t.json()["access_token"]
    ui = httpx.get(d["userinfo_endpoint"], headers={"Authorization": "Bearer " + at}, timeout=10).json()
    uid = ui.get("preferred_username", "")
    if not ou_pbx.UID_RE.match(uid):
        return PlainTextResponse("unsupported account name", status_code=403)
    sid = secrets.token_urlsafe(32)
    SESSIONS[sid] = {"access_token": at, "sub": ui["sub"], "uid": uid, "csrf": secrets.token_urlsafe(24), "exp": time.time() + SESSION_TTL}
    resp = RedirectResponse(PUBLIC_BASE + "/", status_code=302)
    resp.set_cookie("ouphone", sid, httponly=True, secure=True, samesite="strict", max_age=SESSION_TTL, path="/")
    return resp


@app.get("/logout")
def logout(req: Request):
    SESSIONS.pop(req.cookies.get("ouphone", ""), None)
    resp = RedirectResponse(PUBLIC_BASE + "/", status_code=302)
    resp.delete_cookie("ouphone", path="/")
    return resp


@app.get("/")
def index(req: Request):
    s = session(req)
    if not (s and validate(s)):
        return RedirectResponse(PUBLIC_BASE + "/login", status_code=302)
    return FileResponse(os.path.join(STATIC, "index.html"))


@app.get("/api/me")
def me(req: Request):
    s = session(req)
    if not (s and validate(s)):
        return JSONResponse({"error": "login required"}, status_code=401)
    try:
        u = ou_pbx.ldap_users().get(s["uid"])
    except Exception:  # noqa: BLE001
        return JSONResponse({"error": "directory unavailable"}, status_code=503)
    ext = u["ext"] if u and not u["locked"] else None
    return {"user": s["uid"], "extension": ext, "csrf": s["csrf"]}


@app.post("/api/credential")
def credential(req: Request):
    s = session(req)
    if not (s and validate(s)):
        return JSONResponse({"error": "login required"}, status_code=401)
    if req.headers.get("x-ou-csrf") != s["csrf"] or req.headers.get("origin", PUBLIC_BASE) != PUBLIC_BASE:
        return JSONResponse({"error": "csrf"}, status_code=403)
    try:
        cred = ou_pbx.issue(s["uid"], "web")
    except PermissionError:
        return JSONResponse({"error": "no active extension"}, status_code=403)
    except Exception:  # noqa: BLE001
        return JSONResponse({"error": "provisioning failed"}, status_code=503)
    return JSONResponse(cred, headers={"Cache-Control": "no-store"})


app.mount("/static", StaticFiles(directory=STATIC), name="static")
