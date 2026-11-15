"""Office Unbound web softphone host + SIP credential endpoint (spike).

Keycloak OIDC (confidential client `ou-phone`, code + PKCE) -> the logged-in user may fetch THEIR OWN SIP credential:
  GET  /            softphone page (login redirect if no session)
  GET  /login, /callback, /logout
  GET  /api/me          {user, extension, csrf}
  POST /api/credential  header X-OU-CSRF: <csrf>; same-origin only. Rotates the user's `web` device credential and returns it ONCE.
Every credential issue re-validates the Keycloak session (userinfo) AND the LDAP state (user must have an unlocked extension).
The identity used for SIP is the Keycloak `preferred_username` = LDAP uid; a user can never ask for somebody else's credential.
Strict CSP: scripts/styles only from 'self', WSS only to the PBX.

Security review 4:
  * M11: this process is UNPRIVILEGED (no asterisk group, no config/state write access, no LDAP password). Provisioning is done by the separate
    ou-pbx-helper over a unix socket that accepts only me/issue/revoke for one validated uid (pbx/ou_pbx_helper.py).
  * M10: the SIP web credential lives exactly as long as this app session (TTL = remaining session time, enforced by the PBX), is rotated per
    session, is revoked on /logout and on a Keycloak back-channel logout (POST /backchannel-logout, signed logout_token).
  * L7: bounded PENDING/SESSIONS.
"""
import base64, hashlib, json, os, re, secrets, socket, time, urllib.parse
import httpx
import jwt
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles

ISSUER = os.environ.get("KC_ISSUER", "https://auth.ou-lab.internal/realms/ou-lab")
CLIENT_ID = os.environ.get("CLIENT_ID", "ou-phone")
PUBLIC_BASE = os.environ.get("PUBLIC_BASE", "https://phone.ou-lab.internal")
STATIC = os.environ.get("STATIC_DIR", "/opt/ou-phone/static")
SESSION_TTL = int(os.environ.get("SESSION_TTL", "3600"))
CLIENT_SECRET = open(os.environ["CLIENT_SECRET_FILE"]).read().strip()
WSS_ORIGIN = os.environ.get("WSS_URL", "wss://pbx.ou-lab.internal:8089/ws")
HELPER_SOCKET = os.environ.get("OU_HELPER_SOCKET", "/run/ou-pbx/helper.sock")
UID_RE = re.compile(r"^[a-z][a-z0-9_-]{0,30}$")
MAX_SESSIONS, MAX_PENDING = 2000, 500

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


def helper(op: str, uid: str, **kw) -> dict:
    """One JSON line to the unprivileged-side socket of ou-pbx-helper. Raises OSError/ValueError when the helper is unavailable."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as c:
        c.settimeout(25)
        c.connect(HELPER_SOCKET)
        c.sendall(json.dumps({"op": op, "uid": uid, **kw}).encode() + b"\n")
        buf = b""
        while not buf.endswith(b"\n") and len(buf) < 65536:
            chunk = c.recv(4096)
            if not chunk:
                break
            buf += chunk
    return json.loads(buf)


def prune():
    now = time.time()
    for store, cap in ((SESSIONS, MAX_SESSIONS), (PENDING, MAX_PENDING)):
        for k in [k for k, v in store.items() if v["exp"] < now]:
            store.pop(k, None)
        while len(store) >= cap:                       # unauthenticated /login floods must not grow memory without bound
            store.pop(min(store, key=lambda k: store[k]["exp"]), None)


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
    prune()
    PENDING[state] = {"verifier": verifier, "exp": time.time() + 600}
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
    if not UID_RE.match(uid):
        return PlainTextResponse("unsupported account name", status_code=403)
    sid = secrets.token_urlsafe(32)
    prune()
    SESSIONS[sid] = {"access_token": at, "sub": ui["sub"], "uid": uid, "csrf": secrets.token_urlsafe(24), "exp": time.time() + SESSION_TTL}
    resp = RedirectResponse(PUBLIC_BASE + "/", status_code=302)
    resp.set_cookie("ouphone", sid, httponly=True, secure=True, samesite="strict", max_age=SESSION_TTL, path="/")
    return resp


@app.get("/logout")
def logout(req: Request):
    s = SESSIONS.pop(req.cookies.get("ouphone", ""), None)
    if s:
        revoke_web_credential(s["uid"])
    resp = RedirectResponse(PUBLIC_BASE + "/", status_code=302)
    resp.delete_cookie("ouphone", path="/")
    return resp


def revoke_web_credential(uid: str):
    """The SIP web credential must not outlive the login: remove it and kick its registration (best effort; the PBX TTL is the backstop)."""
    try:
        helper("revoke", uid)
    except (OSError, ValueError):
        pass


@app.post("/backchannel-logout")
async def backchannel_logout(req: Request):
    """OIDC back-channel logout (Keycloak: client attribute backchannel.logout.url). Signed logout_token -> end all sessions of that subject
    and revoke their SIP credential. Anything unverifiable is refused with 400 and changes nothing."""
    raw = await req.body()                        # form body parsed by hand: no python-multipart dependency, hard size cap
    if len(raw) > 16384:
        return PlainTextResponse("too large", status_code=413)
    tok = (urllib.parse.parse_qs(raw.decode("utf-8", "replace")).get("logout_token") or [""])[0]
    try:
        jwks = httpx.get(disco()["jwks_uri"], timeout=10).json()["keys"]
        hdr = jwt.get_unverified_header(tok)
        key = next(jwt.PyJWK(k).key for k in jwks if k.get("kid") == hdr.get("kid") and k.get("use", "sig") == "sig")
        claims = jwt.decode(tok, key, algorithms=["RS256"], audience=CLIENT_ID, issuer=ISSUER, options={"require": ["exp", "iat", "iss", "aud"]})
        if "http://schemas.openid.net/event/backchannel-logout" not in (claims.get("events") or {}) or "nonce" in claims or not claims.get("sub"):
            raise ValueError("not a logout token")
    except (jwt.PyJWTError, ValueError, StopIteration, KeyError, httpx.HTTPError):
        return PlainTextResponse("invalid logout_token", status_code=400)
    uids = set()
    for k in [k for k, v in SESSIONS.items() if v["sub"] == claims["sub"]]:
        uids.add(SESSIONS.pop(k)["uid"])
    for uid in uids:
        revoke_web_credential(uid)
    return PlainTextResponse("", status_code=200, headers={"Cache-Control": "no-store"})


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
        ext = helper("me", s["uid"]).get("extension")
    except (OSError, ValueError):
        return JSONResponse({"error": "directory unavailable"}, status_code=503)
    return {"user": s["uid"], "extension": ext, "csrf": s["csrf"]}


@app.post("/api/credential")
def credential(req: Request):
    s = session(req)
    if not (s and validate(s)):
        return JSONResponse({"error": "login required"}, status_code=401)
    if req.headers.get("x-ou-csrf") != s["csrf"] or req.headers.get("origin", PUBLIC_BASE) != PUBLIC_BASE:
        return JSONResponse({"error": "csrf"}, status_code=403)
    ttl = int(s["exp"] - time.time())          # the SIP credential expires with this login session (min 60 s enforced by the helper)
    try:
        cred = helper("issue", s["uid"], ttl=ttl)
    except (OSError, ValueError):
        return JSONResponse({"error": "provisioning failed"}, status_code=503)
    if cred.get("error") == "no active extension":
        return JSONResponse({"error": "no active extension"}, status_code=403)
    if cred.get("error") == "rate limited":
        return JSONResponse({"error": "too many requests"}, status_code=429, headers={"Retry-After": "5"})
    if cred.get("error"):
        return JSONResponse({"error": "provisioning failed"}, status_code=503)
    return JSONResponse(cred, headers={"Cache-Control": "no-store"})


app.mount("/static", StaticFiles(directory=STATIC), name="static")
