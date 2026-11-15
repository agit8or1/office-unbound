"""Office Unbound Jitsi token service (spike).

A Keycloak-authenticated user (OIDC code flow + PKCE, confidential client `ou-meet`) gets a SHORT-LIVED, ROOM-SCOPED Jitsi JWT.
Jitsi/Prosody (authentication=token, allow_empty_token=false) refuses every participant without such a token, so anonymous users can
neither create nor join rooms.

  GET /join?room=<name>      -> (login if needed) -> 302 https://<jitsi>/<room>?jwt=<token>
  GET /api/token?room=<name> -> JSON {"jwt","room","expires_in"} (401 + login_url if no valid session)
  GET /healthz

Revocation: every mint re-validates the user against Keycloak (userinfo with the stored access token). A disabled user / revoked
session fails userinfo, so no new token is minted; tokens already minted live at most TOKEN_TTL seconds (+ the Jitsi session).
Config via env (see the systemd unit): KC_ISSUER, CLIENT_ID, CLIENT_SECRET_FILE, JWT_SECRET_FILE, PUBLIC_BASE, JITSI_BASE, TOKEN_TTL.
"""
import base64, hashlib, os, re, secrets, time
import httpx, jwt
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse, PlainTextResponse

ISSUER = os.environ.get("KC_ISSUER", "https://auth.ou-lab.internal/realms/ou-lab")
CLIENT_ID = os.environ.get("CLIENT_ID", "ou-meet")
PUBLIC_BASE = os.environ.get("PUBLIC_BASE", "https://meet-auth.ou-lab.internal")
JITSI_BASE = os.environ.get("JITSI_BASE", "https://meet.ou-lab.internal")
JITSI_APP_ID = os.environ.get("JITSI_APP_ID", "ou-meet")
JITSI_SUB = os.environ.get("JITSI_SUB", "meet.ou-lab.internal")
TTL = int(os.environ.get("TOKEN_TTL", "120"))
SESSION_TTL = int(os.environ.get("SESSION_TTL", "3600"))
ROOM_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,62}$")
CLIENT_SECRET = open(os.environ["CLIENT_SECRET_FILE"]).read().strip()
JWT_SECRET = open(os.environ["JWT_SECRET_FILE"]).read().strip()

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
_disc = {}
SESSIONS: dict[str, dict] = {}   # sid -> {access_token, user, exp}
PENDING: dict[str, dict] = {}    # state -> {verifier, room, exp}


def disco():
    if not _disc:
        _disc.update(httpx.get(ISSUER + "/.well-known/openid-configuration", timeout=10).json())
    return _disc


def session(req: Request):
    s = SESSIONS.get(req.cookies.get("oumeet", ""))
    return s if s and s["exp"] > time.time() else None


def login_redirect(room: str, api: bool = False):
    verifier = secrets.token_urlsafe(48)
    state = secrets.token_urlsafe(24)
    PENDING[state] = {"verifier": verifier, "room": room, "exp": time.time() + 600}
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    q = httpx.QueryParams({"client_id": CLIENT_ID, "response_type": "code", "scope": "openid profile email",
                           "redirect_uri": PUBLIC_BASE + "/callback", "state": state,
                           "code_challenge": challenge, "code_challenge_method": "S256"})
    return disco()["authorization_endpoint"] + "?" + str(q)


def validate(sess) -> bool:
    """Re-check the user against Keycloak. Disabled user / revoked session / expired access token -> False."""
    try:
        r = httpx.get(disco()["userinfo_endpoint"], headers={"Authorization": "Bearer " + sess["access_token"]}, timeout=10)
    except httpx.HTTPError:
        return False
    return r.status_code == 200 and r.json().get("sub") == sess["user"]["id"]


def mint(sess, room: str) -> str:
    now = int(time.time())
    u = sess["user"]
    return jwt.encode({"iss": JITSI_APP_ID, "aud": JITSI_APP_ID, "sub": JITSI_SUB, "room": room, "iat": now, "nbf": now - 5, "exp": now + TTL,
                       "context": {"user": {"id": u["id"], "name": u["name"], "email": u["email"]}}},
                      JWT_SECRET, algorithm="HS256")


def check_room(room):
    return bool(room) and bool(ROOM_RE.match(room))


@app.get("/healthz")
def healthz():
    return PlainTextResponse("ok")


@app.get("/join")
def join(req: Request, room: str = ""):
    if not check_room(room):
        return PlainTextResponse("invalid room name", status_code=400)
    s = session(req)
    if s and validate(s):
        return RedirectResponse(f"{JITSI_BASE}/{room}?jwt={mint(s, room)}", status_code=302)
    return RedirectResponse(login_redirect(room), status_code=302)


@app.get("/api/token")
def api_token(req: Request, room: str = ""):
    if not check_room(room):
        return JSONResponse({"error": "invalid room name"}, status_code=400)
    s = session(req)
    if not (s and validate(s)):
        return JSONResponse({"error": "login required", "login_url": f"{PUBLIC_BASE}/join?room={room}"}, status_code=401)
    return {"jwt": mint(s, room), "room": room, "expires_in": TTL}


@app.get("/callback")
def callback(req: Request, code: str = "", state: str = "", error: str = ""):
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
    sid = secrets.token_urlsafe(32)
    SESSIONS[sid] = {"access_token": at, "exp": time.time() + SESSION_TTL,
                     "user": {"id": ui["sub"], "name": ui.get("name") or ui.get("preferred_username", ""), "email": ui.get("email", "")}}
    resp = RedirectResponse(f"{PUBLIC_BASE}/join?room={p['room']}", status_code=302)
    resp.set_cookie("oumeet", sid, httponly=True, secure=True, samesite="lax", max_age=SESSION_TTL)
    return resp
