#!/usr/bin/env python3
"""C03 Jitsi Meet with Office Unbound JWT: anonymous refused; token service gated by Keycloak; room-scoped short-lived JWT;
two headless browsers (bob, carol; fake camera/mic) in one conference (verified in-page and via JVB colibri stats)."""
import base64
import json
import os
import subprocess
import sys
import threading
import time
import uuid

import jwt as pyjwt
import websocket
from playwright.sync_api import sync_playwright

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import collab_lib as L

rep = L.Report("C03 Jitsi Meet: JWT-only access, token service, two participants")
ROOM = "ou-spike-" + uuid.uuid4().hex[:8]
OTHER = "ou-spike-" + uuid.uuid4().hex[:8]
WSS = "wss://meet.ou-lab.internal/xmpp-websocket"
SSLOPT = {"ca_certs": L.CA}


def xmpp_auth(room, token=None):
    """Raw XMPP-over-WebSocket (RFC 7395) handshake as Jitsi's lib-jitsi-meet does. Returns 'success' | 'failure:<cond>' | 'closed'."""
    url = WSS + "?room=" + room + (("&token=" + token) if token else "")
    try:
        ws = websocket.create_connection(url, subprotocols=["xmpp"], sslopt=SSLOPT, timeout=10, origin=L.MEET)
        ws.send('<open to="meet.ou-lab.internal" version="1.0" xmlns="urn:ietf:params:xml:ns:xmpp-framing"/>')
        feat = ws.recv() + ws.recv()
        if "<mechanisms" not in feat:
            ws.close()
            return "failure:no SASL mechanism offered (session cannot authenticate)"
        mech = "ANONYMOUS" if "ANONYMOUS" in feat else ("OAUTHBEARER" if "OAUTHBEARER" in feat else "PLAIN")
        ws.send('<auth mechanism="%s" xmlns="urn:ietf:params:xml:ns:xmpp-sasl"/>' % mech)
        r = ws.recv()
        ws.close()
    except Exception as e:  # noqa
        return "closed:" + type(e).__name__
    if "<success" in r:
        return "success"
    return "failure:" + r[:120].replace("\n", " ")


def join_click(pg):
    pg.wait_for_selector("[data-testid='prejoin.joinMeeting']", timeout=30000)
    pg.click("[data-testid='prejoin.joinMeeting']")


def mint(secret, room, **over):
    now = int(time.time())
    p = {"iss": "ou-meet", "aud": "ou-meet", "sub": "meet.ou-lab.internal", "room": room, "iat": now, "nbf": now - 5, "exp": now + 120,
         "context": {"user": {"id": "x", "name": "x", "email": "x@x"}}}
    p.update(over)
    return pyjwt.encode(p, secret, algorithm="HS256")


# ---- 1. anonymous / bogus tokens refused at the XMPP layer (this is what room creation requires)
r = xmpp_auth(ROOM)
rep.check("anonymous XMPP session (no token) refused", r.startswith("failure") or r.startswith("closed"), r)
r = xmpp_auth(ROOM, mint("not-the-real-secret-" + "x" * 20, ROOM))
rep.check("JWT signed with a wrong secret refused", r.startswith("failure") or r.startswith("closed"), r)
r = xmpp_auth(ROOM, mint("not-the-real-secret-" + "x" * 20, ROOM, exp=int(time.time()) - 60))
rep.check("expired JWT refused", r.startswith("failure") or r.startswith("closed"), r)

# ---- 2. token service is gated
q = L.S.get(L.MEETAUTH + "/api/token?room=" + ROOM, timeout=30)
rep.check("token service refuses unauthenticated caller (401)", q.status_code == 401, q.status_code)
rep.check("token service rejects bad room name (400)", L.S.get(L.MEETAUTH + "/api/token?room=..%2Fx", timeout=30).status_code == 400)
rj = L.S.get(L.MEETAUTH + "/join?room=" + ROOM, allow_redirects=False, timeout=30)
rep.check("/join without session redirects to Keycloak", rj.status_code == 302 and rj.headers.get("location", "").startswith(L.KC), rj.headers.get("location", "")[:60])
has_jwt = "jwt=" in rj.headers.get("location", "")
rep.check("anonymous /join does not leak a jwt", not has_jwt)


def get_token(p, user, room):
    """Real login as `user` through Keycloak at the token service; returns the jwt from the final redirect to Jitsi."""
    b = L.browser(p)
    ctx = b.new_context()
    page = ctx.new_page()
    cap = {}

    def route(r):
        if "jwt=" in r.request.url and "url" not in cap:
            cap["url"] = r.request.url
        r.abort()
    page.route(L.MEET + "/**", route)
    t0 = time.time()
    try:
        page.goto(L.MEETAUTH + "/join?room=" + room, wait_until="commit")
    except Exception:  # noqa
        pass
    for _ in range(60):
        if "url" in cap:
            break
        page.wait_for_timeout(500)
        if page.url.startswith(L.KC) and page.query_selector("input[name=username]"):
            L.kc_login(page, user, L.password(user))
    ck = {c["name"]: c["value"] for c in ctx.cookies()}
    b.close()
    if "url" not in cap:
        raise RuntimeError("no redirect to jitsi for %s (last %s)" % (user, page.url))
    if "jwt=" not in cap["url"]:
        raise RuntimeError("captured %s" % cap["url"][:100])
    tok = cap["url"].split("jwt=", 1)[1].split("&")[0]
    return tok, time.time() - t0, ck


with sync_playwright() as p:
    btok, secs, cookies = get_token(p, "bob", ROOM)
    claims = pyjwt.decode(btok, options={"verify_signature": False}, audience="ou-meet")
    rep.check("bob (Keycloak login) receives a Jitsi JWT", True, "%.1fs" % secs)
    rep.check("JWT is room-scoped", claims.get("room") == ROOM, claims.get("room"))
    rep.check("JWT is short-lived (<=120 s)", 0 < claims["exp"] - claims["iat"] <= 120, "%ds" % (claims["exp"] - claims["iat"]))
    rep.check("JWT carries bob's identity from Keycloak", claims["context"]["user"]["email"].startswith("bob@") and claims["context"]["user"]["name"], claims["context"]["user"]["name"])
    ctok, _, _ = get_token(p, "carol", ROOM)

    # ---- 3. token accepted for its room, refused for another room
    rep.check("bob's JWT accepted by Prosody for its room", xmpp_auth(ROOM, btok) == "success", xmpp_auth(ROOM, btok))
    # room scope is enforced at MUC join (token_verification), not at the XMPP auth step: checked with a real browser below
    b0 = L.browser(p, args=["--use-fake-device-for-media-stream", "--use-fake-ui-for-media-stream"])
    pg0 = b0.new_context(permissions=["camera", "microphone"]).new_page()
    pg0.goto("%s/%s?jwt=%s#config.requireDisplayName=false" % (L.MEET, OTHER, btok), wait_until="domcontentloaded")
    try:
        join_click(pg0)
    except Exception:  # noqa
        pass
    time.sleep(12)
    try:
        st0 = pg0.evaluate("(()=>{const c=APP.store.getState()['features/base/conference'];return {joined:!!(c&&c.conference)}})()")
    except Exception as e:  # noqa
        st0 = {"joined": False, "err": str(e)[:60]}
    rep.check("bob's JWT (room A) does NOT admit a browser to room B", not st0.get("joined"), json.dumps(st0) + " | " + pg0.inner_text("body")[:80].replace("\n", " "))
    b0.close()

    # ---- 4. two real browsers in the conference, fake media, P2P off so media goes through the videobridge
    args = ["--use-fake-device-for-media-stream", "--use-fake-ui-for-media-stream", "--autoplay-policy=no-user-gesture-required"]
    cfg = "#config.p2p.enabled=false&config.requireDisplayName=false"
    pages = []
    for name, tok in (("bob", btok), ("carol", ctok)):
        b = L.browser(p, args=args)
        ctx = b.new_context(permissions=["camera", "microphone"])
        pg = ctx.new_page()
        pg.on("console", lambda m: None)
        pg.goto("%s/%s?jwt=%s%s" % (L.MEET, ROOM, tok, cfg), wait_until="domcontentloaded")
        join_click(pg)
        pages.append((name, b, pg))
    ST = "(()=>{const s=APP.store.getState();const c=s['features/base/conference'];const pa=s['features/base/participants'];" \
         "const tr=s['features/base/tracks'];return {joined:!!(c&&c.conference), ice:!!(c&&c.iceConnected), remote:pa.remote.size, remote_tracks:tr.filter(t=>!t.local&&t.jitsiTrack).length," \
         "local_tracks:tr.filter(t=>t.local&&t.jitsiTrack).length, name:(pa.local&&pa.local.name)||null, room:c&&c.room}})()"
    res = {}
    deadline = time.time() + 60
    while time.time() < deadline:
        ok = True
        for name, b, pg in pages:
            try:
                res[name] = pg.evaluate(ST)
            except Exception as e:  # noqa
                res[name] = {"err": str(e)[:80]}
                ok = False
                continue
            if not (res[name]["joined"] and res[name]["remote"] >= 1 and res[name]["remote_tracks"] >= 2):
                ok = False
        if ok:
            break
        time.sleep(2)
    for name, b, pg in pages:
        rep.check("%s joined conference %s and sees the other participant + remote media tracks" % (name, ROOM),
                  bool(res.get(name, {}).get("joined")) and res[name].get("remote", 0) >= 1 and res[name].get("remote_tracks", 0) >= 2, json.dumps(res.get(name)))
    # videobridge view (inside the machine): /debug lists live conferences and endpoints (P2P is off, so media must go via the JVB)
    out = subprocess.run(["sudo", "systemd-run", "-M", "ou-meet1", "--quiet", "--pipe", "--wait", "curl", "-s", "http://127.0.0.1:8080/debug?full=true"], capture_output=True, text=True).stdout
    try:
        st = json.loads(out)
        confs = st.get("conferences", {})
        eps = [len(c.get("endpoints", {})) if isinstance(c.get("endpoints"), (dict, list)) else 0 for c in confs.values()]
        rep.check("JVB /debug: a conference with 2 endpoints", any(e >= 2 for e in eps), "conferences=%d endpoints=%s" % (len(confs), eps))
        import re
        bps = [int(x) for x in re.findall(r'"bitrate_bps":(\d+)', out)]
        rep.check("JVB is forwarding video (allocator bitrate_bps > 0)", any(b > 0 for b in bps), "bitrate_bps=%s" % bps[:4])
    except Exception:  # noqa
        rep.check("JVB /debug readable", False, out[:100])
    pages[0][2].screenshot(path=os.environ.get("OU_SHOT", "/tmp/claude-1000/-home-administrator/a1d917f8-7438-424e-a57a-793b46deb95e/scratchpad/chat-r/jitsi-bob.png"))
    # bob leaves; carol sees him go
    pages[0][2].evaluate("APP.conference.hangup()")
    time.sleep(4)
    try:
        rem = pages[1][2].evaluate("APP.store.getState()['features/base/participants'].remote.size")
    except Exception:  # noqa
        rem = -1
    rep.check("bob hangs up; carol sees 0 remote participants", rem == 0, rem)
    for _, b, _ in pages:
        b.close()
rep.finish()
