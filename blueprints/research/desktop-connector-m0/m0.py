"""Desktop Connector spike M0 (owner-approved 2026-11-23), Linux part: an rclone WebDAV mount of a real deployment's personal space,
authenticated with an OIDC token of the realm's existing native client (OpenCloudDesktop: public, PKCE S256, loopback redirect,
offline_access). No password is given to rclone; the refresh token stands in for the OS keychain (0600 file in the work directory).

Usage (ICS venv python; Playwright from ics/e2e/node_modules drives the sign-in page only):
  m0.py login  <workdir> <auth-base> <user> <password-file>   # one browser sign-in, stores the device's refresh token
  m0.py token  <workdir>                                      # bearer_token_command: prints a fresh access token
  m0.py revoke <workdir>                                      # ends this device's sign-in (Keycloak logout with the refresh token)
Never prints a secret except `token`, whose stdout goes to rclone only."""
import base64
import hashlib
import http.server
import json
import os
import secrets
import subprocess
import sys
import threading
import time
import urllib.parse

import httpx

CLIENT = "OpenCloudDesktop"
REALM = "ou"
NODE_MODULES = "/home/administrator/office-unbound/ics/e2e/node_modules"


def _save(work, d):
    p = os.path.join(work, "device.json")
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(d, f)


def _load(work):
    with open(os.path.join(work, "device.json")) as f:
        return json.load(f)


def login(work, auth, user, pwfile):
    os.makedirs(work, mode=0o700, exist_ok=True)
    iss = f"{auth.rstrip('/')}/realms/{REALM}"
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(16)
    got = {}

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            got.update({k: v[0] for k, v in q.items()})
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"signed in, you can close this window")

        def log_message(self, *a):
            pass
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    redirect = f"http://127.0.0.1:{srv.server_port}"
    threading.Thread(target=srv.handle_request, daemon=True).start()
    url = f"{iss}/protocol/openid-connect/auth?" + urllib.parse.urlencode({
        "client_id": CLIENT, "response_type": "code", "redirect_uri": redirect, "scope": "openid profile email offline_access",
        "state": state, "code_challenge": challenge, "code_challenge_method": "S256"})
    js = f"""
const {{ chromium }} = require('{NODE_MODULES}/playwright');
(async () => {{ const b = await chromium.launch(); const p = await b.newPage();
  await p.goto(process.env.U); await p.fill('#username', process.env.N); await p.fill('#password', require('fs').readFileSync(process.env.F,'utf8').trim());
  await Promise.all([p.waitForURL(/^http:\\/\\/127\\.0\\.0\\.1/), p.click('#kc-login')]); await b.close(); }})();"""
    t0 = time.monotonic()
    subprocess.run(["node", "-e", js], env={**os.environ, "U": url, "N": user, "F": pwfile}, check=True, timeout=120)
    srv.server_close()
    if got.get("state") != state or "code" not in got:
        sys.exit(f"sign-in failed: {got.get('error', 'no code')}")
    r = httpx.post(f"{iss}/protocol/openid-connect/token", data={"grant_type": "authorization_code", "client_id": CLIENT, "code": got["code"],
                                                                  "redirect_uri": redirect, "code_verifier": verifier}, timeout=20)
    r.raise_for_status()
    tok = r.json()
    _save(work, {"iss": iss, "refresh_token": tok["refresh_token"]})
    print(json.dumps({"signed_in": True, "seconds": round(time.monotonic() - t0, 1), "refresh_token_type": _typ(tok["refresh_token"]),
                      "access_token_lifetime_s": tok.get("expires_in")}))


def _typ(jwt):
    try:
        return json.loads(base64.urlsafe_b64decode(jwt.split(".")[1] + "==")).get("typ")
    except (ValueError, IndexError):
        return None


def token(work):
    d = _load(work)
    r = httpx.post(f"{d['iss']}/protocol/openid-connect/token", data={"grant_type": "refresh_token", "client_id": CLIENT,
                                                                       "refresh_token": d["refresh_token"]}, timeout=20)
    if r.status_code != 200:
        sys.exit(f"refresh refused: HTTP {r.status_code}")
    t = r.json()
    if t.get("refresh_token"):
        _save(work, {**d, "refresh_token": t["refresh_token"]})
    sys.stdout.write(t["access_token"])


def revoke(work):
    d = _load(work)
    r = httpx.post(f"{d['iss']}/protocol/openid-connect/logout", data={"client_id": CLIENT, "refresh_token": d["refresh_token"]}, timeout=20)
    print(json.dumps({"revoked_http": r.status_code, "at": time.time()}))


if __name__ == "__main__":
    cmd, args = sys.argv[1], sys.argv[2:]
    {"login": login, "token": token, "revoke": revoke}[cmd](*args)
