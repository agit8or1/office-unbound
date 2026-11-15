#!/usr/bin/env python3
"""C01 Matrix chat via MAS -> Keycloak SSO: bob + alice log in (browser flow), room, messages, file up/download, leave.
Plain Client-Server API (requests); the only browser use is the OIDC login."""
import hashlib
import os
import sys
import time
import urllib.parse
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import collab_lib as L
import matrix_sso as M

rep = L.Report("C01 Matrix chat: SSO login, room, messages, file, leave (Synapse+MAS+Keycloak)")
q = urllib.parse.quote

# --- unauthenticated access and local login/registration closed
r = L.S.post(L.HS + "/_matrix/client/v3/createRoom", json={}, timeout=30)
rep.check("anonymous createRoom refused", r.status_code == 401, r.status_code)
r = L.S.get(L.HS + "/_matrix/client/v3/login", timeout=30)
flows = [f["type"] for f in r.json().get("flows", [])]
rep.check("homeserver login flows are SSO/token only (no m.login.password)", "m.login.password" not in flows, flows)
r = L.S.post(L.HS + "/_matrix/client/v3/login", json={"type": "m.login.password", "identifier": {"type": "m.id.user", "user": "bob"}, "password": "x"}, timeout=30)
rep.check("direct password login to homeserver refused", r.status_code in (400, 401, 403, 404, 405), r.status_code)
r = L.S.post(L.HS + "/_matrix/client/v3/register", json={}, timeout=30)
rep.check("open registration refused", r.status_code in (400, 401, 403, 404, 405), r.status_code)

# --- SSO login
users = {}
for u in ("bob", "alice"):
    t0 = time.time()
    c = M.login(u, L.password(u))
    users[u] = c
    rep.check("%s SSO login via MAS+Keycloak -> %s" % (u, c.mxid), c.mxid == "@%s:matrix.ou-lab.internal" % u, "%.1fs, access ttl %ss, refresh token %s" % (time.time() - t0, c.expires_in, bool(c.refresh)))
bob, alice = users["bob"], users["alice"]
dn = bob.api("GET", "/_matrix/client/v3/profile/" + q(bob.mxid)).json().get("displayname")
rep.check("display name imported from Keycloak claim", bool(dn), dn)

# --- room + messages
room = bob.api("POST", "/_matrix/client/v3/createRoom", json={"name": "collab-spike-" + uuid.uuid4().hex[:6], "preset": "private_chat", "invite": [alice.mxid]})
rep.check("bob creates room and invites alice", room.status_code == 200, room.text[:120])
rid = room.json()["room_id"]
j = alice.api("POST", "/_matrix/client/v3/join/" + q(rid), json={})
rep.check("alice joins", j.status_code == 200, j.status_code)


def send(c, body, txn):
    return c.api("PUT", "/_matrix/client/v3/rooms/%s/send/m.room.message/%s" % (q(rid), txn), json={"msgtype": "m.text", "body": body})


def messages(c):
    r = c.api("GET", "/_matrix/client/v3/rooms/%s/messages?dir=b&limit=20" % q(rid))
    return [(e["sender"], e["content"].get("body"), e["content"].get("msgtype")) for e in r.json().get("chunk", []) if e["type"] == "m.room.message"]


s1 = send(bob, "hello from bob " + uuid.uuid4().hex[:6], "t1")
rep.check("bob sends message", s1.status_code == 200, s1.status_code)
# real sync from alice's side (long-poll /sync, as a client would)
t0 = time.time()
seen = False
since = None
for _ in range(10):
    sy = alice.api("GET", "/_matrix/client/v3/sync?timeout=3000" + ("&since=" + since if since else "")).json()
    since = sy.get("next_batch")
    tl = sy.get("rooms", {}).get("join", {}).get(rid, {}).get("timeline", {}).get("events", [])
    if any(e["type"] == "m.room.message" and e["sender"] == bob.mxid for e in tl):
        seen = True
        break
rep.check("alice receives bob's message via /sync", seen, "%.1fs" % (time.time() - t0))
s2 = send(alice, "reply from alice", "t2")
rep.check("alice replies", s2.status_code == 200, s2.status_code)
m = messages(bob)
rep.check("bob sees both messages in order", [x[0] for x in reversed(m)] == [bob.mxid, alice.mxid], m)

# --- file upload / download (authenticated media)
blob = os.urandom(300 * 1024)
sha = hashlib.sha256(blob).hexdigest()
up = bob.api("POST", "/_matrix/media/v3/upload?filename=spike.bin", data=blob, headers={"Content-Type": "application/octet-stream"})
rep.check("bob uploads 300 KiB file", up.status_code == 200, up.text[:100])
mxc = up.json()["content_uri"]
ev = bob.api("PUT", "/_matrix/client/v3/rooms/%s/send/m.room.message/t3" % q(rid), json={"msgtype": "m.file", "body": "spike.bin", "url": mxc, "info": {"size": len(blob), "mimetype": "application/octet-stream"}})
rep.check("bob posts m.file event", ev.status_code == 200, ev.status_code)
srv, mid = mxc[len("mxc://"):].split("/", 1)
dl = alice.api("GET", "/_matrix/client/v1/media/download/%s/%s" % (srv, mid))
rep.check("alice downloads file byte-exact (sha256 match)", dl.status_code == 200 and hashlib.sha256(dl.content).hexdigest() == sha, "%s %d bytes" % (dl.status_code, len(dl.content)))
anon = L.S.get(L.HS + "/_matrix/client/v1/media/download/%s/%s" % (srv, mid), timeout=30)
rep.check("anonymous media download refused (authenticated media)", anon.status_code in (401, 403, 404), anon.status_code)

# --- refresh token, whoami after refresh
old = bob.access
rr = bob.do_refresh()
rep.check("bob access token refresh via MAS", rr.status_code == 200 and bob.access != old, rr.status_code)
rep.check("refreshed token works", bob.api("GET", "/_matrix/client/v3/account/whoami").status_code == 200)

# --- leave
lv = alice.api("POST", "/_matrix/client/v3/rooms/%s/leave" % q(rid), json={})
rep.check("alice leaves room", lv.status_code == 200, lv.status_code)
rep.check("alice (left) cannot send", send(alice, "ghost", "t9").status_code == 403)
send(bob, "after-alice-left", "t10")
bodies = [x[1] for x in messages(alice)] if alice.api("GET", "/_matrix/client/v3/rooms/%s/messages?dir=b&limit=20" % q(rid)).status_code == 200 else []
rep.check("alice (left) does not see messages sent after she left (history up to leave only)", "after-alice-left" not in bodies, bodies[:3])
lv = bob.api("POST", "/_matrix/client/v3/rooms/%s/leave" % q(rid), json={})
rep.check("bob leaves room", lv.status_code == 200, lv.status_code)
bob.api("POST", "/_matrix/client/v3/rooms/%s/forget" % q(rid), json={}); alice.api("POST", "/_matrix/client/v3/rooms/%s/forget" % q(rid), json={})
rep.finish()
