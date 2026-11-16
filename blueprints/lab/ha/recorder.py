#!/usr/bin/env python3
"""LAB ONLY. Central recorder for the HA partition proof (docs/status/ha-partition-results.md).

Runs on the node machine (ou-ha-node1) and is the ONE place where every class of controller side effect becomes observable, independent of
the controllers' own logs:
  :8006  fake Proxmox VE API (tests/pve_sim.py, a test double) over TLS; every request is recorded with the caller's source address and the
         X-OU-Controller / X-OU-Epoch headers the controller stamps on provider calls; mutating calls can be slowed (long-running jobs)
  :8007  webhook receiver (TLS, same certificate): every alert notification is recorded
  :8099  control API (plain HTTP, lab network only): GET /state, POST /reset, POST /config {"delay_ms": n}, GET /cert
and it reads two node-side evidence files: the agent's exec log (/var/lib/ou-agent/exec.log: every signed request, epoch, decision) and the
backup helper stub's log (/var/lib/ha-recorder/backup.jsonl: every backup.* run that was ADMITTED by the agent).
usage: recorder.py --src /root/src/ics --bind 192.168.186.27"""
import argparse
import http.server
import io
import json
import os
import socketserver
import ssl
import sys
import threading
import time

ap = argparse.ArgumentParser()
ap.add_argument("--src", default="/root/src/ics")
ap.add_argument("--bind", required=True)
ap.add_argument("--dir", default="/var/lib/ha-recorder")
A = ap.parse_args()
sys.path.insert(0, A.src)
from tests.pve_sim import PveSim, _Handler, SIM_MARKER  # noqa: E402  (test double, lab only)
from tests.pve_mock import make_cert  # noqa: E402

os.makedirs(A.dir, exist_ok=True)
LOCK = threading.Lock()
REC: list[dict] = []
CFG = {"delay_ms": 0}
AGENT_LOG = "/var/lib/ou-agent/exec.log"
BACKUP_LOG = os.path.join(A.dir, "backup.jsonl")


def rec(kind, **kw):
    with LOCK:
        REC.append({"seq": len(REC) + 1, "ts": round(time.time(), 3), "kind": kind, **kw})


def mk_sim():
    s = PveSim(task_delay=0.05)
    s.populate_owner_env()
    return s


SIM = mk_sim()


class PveHandler(_Handler):
    def _do(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        self.rfile = io.BytesIO(raw)
        mutating = self.command != "GET"
        body = raw.decode("utf-8", "replace") if raw and not self.path.endswith("/access/ticket") else ""
        # never keep a password / secret: only the identifying field values
        keep = {}
        for kv in body.split("&"):
            k, _, v = kv.partition("=")
            if k in ("userid", "tokenid", "roleid", "poolid", "path", "vmid", "newid", "name", "pool", "storage", "target", "roles", "users", "tokens"):
                keep[k] = v[:80]
        rec("pve", src=self.client_address[0], method=self.command, path=self.path.split("?")[0], mutating=mutating, fields=keep,
            controller=self.headers.get("X-OU-Controller"), epoch=self.headers.get("X-OU-Epoch"), job=self.headers.get("X-OU-Job"))
        if mutating and CFG["delay_ms"]:
            time.sleep(CFG["delay_ms"] / 1000.0)
        return super()._do()
    do_GET = do_POST = do_PUT = do_DELETE = _do


class HookHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        rec("webhook", src=self.client_address[0], path=self.path, event=self.headers.get("X-OU-Event"), controller=self.headers.get("X-OU-Controller"),
            epoch=self.headers.get("X-OU-Epoch"), job=self.headers.get("X-OU-Job"), bytes=len(raw))
        self.send_response(204)
        self.end_headers()


def tail_json(path):
    out = []
    try:
        for line in open(path):
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    except OSError:
        pass
    return out


class Control(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _j(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/cert":
            return self._j({"fingerprint_sha256": FP, "now": time.time(), "root_password": SIM.ROOT_PW})
        if self.path == "/state":
            with LOCK:
                recs = list(REC)
            return self._j({"now": time.time(), "records": recs, "agent": tail_json(AGENT_LOG), "backup": tail_json(BACKUP_LOG), "config": CFG})
        self._j({"error": "not_found"}, 404)

    def do_POST(self):
        global SIM
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}") if n else {}
        if self.path == "/reset":     # forget the records and rebuild the simulator (a fresh cluster); the node-side logs are cut by the driver (offsets)
            with LOCK:
                REC.clear()
            SIM = mk_sim()
            PVE_SRV.sim = SIM
            return self._j({"ok": True, "root_password": SIM.ROOT_PW})
        if self.path == "/probe":
            return self._j(probe(bool(body.get("open"))))
        if self.path == "/config":
            CFG.update({k: int(v) for k, v in body.items() if k in CFG})
            return self._j(CFG)
        self._j({"error": "not_found"}, 404)


class Quiet(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(204)
        self.end_headers()


PROBE = {"srv": None}


def probe(open_):
    """:8010 is the port the monitored check watches: open -> check ok, closed -> check fails (drives the monitor/alert loops from outside)"""
    if open_ and PROBE["srv"] is None:
        s = TS((A.bind, 8010), Quiet)
        s.socket = ctx.wrap_socket(s.socket, server_side=True)
        threading.Thread(target=s.serve_forever, daemon=True).start()
        PROBE["srv"] = s
    elif not open_ and PROBE["srv"] is not None:
        PROBE["srv"].shutdown()
        PROBE["srv"].server_close()
        PROBE["srv"] = None
    return {"probe_open": PROBE["srv"] is not None}


class TS(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


cert_pem, key_pem, FP = make_cert()
cf, kf = os.path.join(A.dir, "tls.crt"), os.path.join(A.dir, "tls.key")
open(cf, "w").write(cert_pem)
open(kf, "w").write(key_pem)
os.chmod(kf, 0o600)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cf, kf)
PVE_SRV = TS((A.bind, 8006), PveHandler)
PVE_SRV.sim = SIM
PVE_SRV.socket = ctx.wrap_socket(PVE_SRV.socket, server_side=True)
HOOK_SRV = TS((A.bind, 8007), HookHandler)
HOOK_SRV.socket = ctx.wrap_socket(HOOK_SRV.socket, server_side=True)
CTL_SRV = TS((A.bind, 8099), Control)
for s in (PVE_SRV, HOOK_SRV):
    threading.Thread(target=s.serve_forever, daemon=True).start()
print(f"recorder up: pve https://{A.bind}:8006 webhook https://{A.bind}:8007 control http://{A.bind}:8099 fp {FP} marker {SIM_MARKER}", flush=True)
CTL_SRV.serve_forever()
