#!/usr/bin/env python3
"""ou-pbx-helper: the ONLY process that holds the asterisk group and write access to /etc/asterisk/ou (security review 4, M11).

The web-facing softphone app (`ou-phone`, user ou-phone) used to run ou_pbx in-process: any code execution in the app or one of its dependencies
gave the Asterisk control socket (default_perm=permit: `channel originate ... application System`, config rewrite + reload, pbx.key, every HA1).
Now the web app has NO asterisk group, NO write access, no LDAP bind password and no state dir. It can only ask this helper, over a unix socket,
for three fixed operations, each for exactly one validated uid:

  {"op": "me",     "uid": U}              -> {"extension": "1001" | null}           (LDAP: has an unlocked extension?)
  {"op": "issue",  "uid": U, "ttl": N}    -> web credential, expires in clamp(N, 60, 3600) s, rotation kicks the old registration
  {"op": "revoke", "uid": U}              -> removes the web credential, kicks its registration

One JSON line in, one JSON line out. Everything else (device kinds other than `web`, other users' credentials, config, raw asterisk commands) is not
expressible. The peer must be the configured web user (SO_PEERCRED), the socket is 0660 ou-pbx:ou-phone, issue is rate-limited per uid.
Socket activation (ou-pbx-helper.socket) is supported (LISTEN_FDS); without it the helper binds $OU_HELPER_SOCKET itself.
"""
import json
import os
import pwd
import socket
import socketserver
import struct
import sys
import threading
import time

sys.path.insert(0, os.environ.get("OU_PBX_LIB", "/opt/ou-pbx"))
import ou_pbx  # noqa: E402

SOCK = os.environ.get("OU_HELPER_SOCKET", "/run/ou-pbx/helper.sock")
PEER_USER = os.environ.get("OU_HELPER_PEER_USER", "ou-phone")
MAX_TTL, MIN_TTL = 3600, 60
MIN_ISSUE_INTERVAL = float(os.environ.get("OU_HELPER_MIN_ISSUE_INTERVAL", "5"))
_last_issue: dict = {}
_lock = threading.Lock()


def handle(req: dict) -> dict:
    op, uid = req.get("op"), req.get("uid", "")
    if not (isinstance(uid, str) and ou_pbx.UID_RE.match(uid)):
        return {"error": "bad request"}
    if op == "me":
        u = ou_pbx.ldap_users().get(uid)
        return {"extension": u["ext"] if u and not u["locked"] else None}
    if op == "issue":
        try:
            ttl = max(MIN_TTL, min(MAX_TTL, int(req.get("ttl", MAX_TTL))))
        except (TypeError, ValueError):
            return {"error": "bad request"}
        with _lock:
            now = time.monotonic()
            if now - _last_issue.get(uid, -1e9) < MIN_ISSUE_INTERVAL:
                return {"error": "rate limited"}
            _last_issue[uid] = now
            if len(_last_issue) > 5000:
                for k in [k for k, v in _last_issue.items() if now - v > 60]:
                    _last_issue.pop(k, None)
        try:
            return ou_pbx.issue(uid, "web", ttl)
        except PermissionError:
            return {"error": "no active extension"}
    if op == "revoke":
        ou_pbx.revoke(uid, "web")
        return {"ok": True}
    return {"error": "bad request"}


class H(socketserver.StreamRequestHandler):
    timeout = 20

    def handle(self):
        pid, uid, gid = struct.unpack("3i", self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        try:
            allowed = pwd.getpwnam(PEER_USER).pw_uid
        except KeyError:
            allowed = -1
        if uid != allowed:
            self.wfile.write(b'{"error": "forbidden"}\n')
            return
        try:
            req = json.loads(self.rfile.readline(4096) or b"{}")
            res = handle(req) if isinstance(req, dict) else {"error": "bad request"}
        except Exception as e:  # noqa: BLE001  (never leak internals / secrets to the caller)
            ou_pbx.log("helper error: %s" % type(e).__name__)
            res = {"error": "failed"}
        self.wfile.write(json.dumps(res).encode() + b"\n")


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True


def make_server():
    if os.environ.get("LISTEN_FDS") == "1" and os.environ.get("LISTEN_PID") == str(os.getpid()):
        srv = Server(SOCK, H, bind_and_activate=False)
        srv.socket.close()
        srv.socket = socket.fromfd(3, socket.AF_UNIX, socket.SOCK_STREAM)
        return srv
    try:
        os.unlink(SOCK)
    except FileNotFoundError:
        pass
    old = os.umask(0o117)
    try:
        return Server(SOCK, H)
    finally:
        os.umask(old)


if __name__ == "__main__":
    make_server().serve_forever()
