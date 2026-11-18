"""`guest.probe`: health probes the node agent runs against ITS OWN services on the loopback address (agent >= 0.5.0).

The deployment's service ports are loopback-only or open to the deployment's own VMs, never to the ICS, so the ICS cannot probe them; and a TLS
service is verified against the deployment CA (/etc/ou/tls/ca.crt, written by cfg.tls) for the exact name its certificate must carry. Read-only:
one TCP connection (and at most one HTTP GET) per probe to 127.0.0.1, bounded time and size, run in the agent process (no helper, no privilege).
Results are booleans plus a short message; no response body is returned."""
import http.client
import re
import socket
import ssl
import time

from .guestspec import _exact, _int, _s
from .proto import Reject

PROBE_RUNBOOK = "guest.probe"
CA_FILE = "/etc/ou/tls/ca.crt"
KINDS = ("tcp", "tls", "http", "https")
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
PATH_RE = re.compile(r"^/[A-Za-z0-9._~/%?=&+-]{0,200}$")
HOST_RE = re.compile(r"^(?=.{4,200}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")
BODY_RE = re.compile(r'^[\x20-\x7e]{1,100}$')
MAX_PROBES, TIMEOUT, MAX_READ = 16, 5.0, 65536


def check(p, cfg=None):
    _exact(p, ("probes",))
    if not isinstance(p["probes"], list) or not 1 <= len(p["probes"]) <= MAX_PROBES:
        raise Reject("bad_params", "probes: 1..%d" % MAX_PROBES)
    out = []
    for x in p["probes"]:
        _exact(x, ("name", "kind", "port", "path", "expect_status", "body_contains", "server_name"), ("name", "kind", "port"))
        if x["kind"] not in KINDS:
            raise Reject("bad_params", "kind must be one of " + ", ".join(KINDS))
        q = {"name": _s(x["name"], NAME_RE, "probe name"), "kind": x["kind"], "port": _int(x["port"], 1, 65535, "port")}
        if x["kind"] in ("tls", "https"):
            q["server_name"] = _s(x.get("server_name"), HOST_RE, "server_name (required for tls/https)")
        elif "server_name" in x:
            raise Reject("bad_params", "server_name only for tls/https")
        if x["kind"] in ("http", "https"):
            q["path"] = _s(x.get("path", "/"), PATH_RE, "path")
            q["expect_status"] = _int(x.get("expect_status", 200), 100, 599, "expect_status")
            if x.get("body_contains") is not None:
                q["body_contains"] = _s(x["body_contains"], BODY_RE, "body_contains")
        elif any(k in x for k in ("path", "expect_status", "body_contains")):
            raise Reject("bad_params", "path/expect_status/body_contains only for http/https")
        out.append(q)
    return {"probes": out}


def _ctx():
    c = ssl.create_default_context(cafile=CA_FILE)   # ONLY the deployment CA: a system CA can never vouch for a deployment service
    c.minimum_version = ssl.TLSVersion.TLSv1_2
    return c


def one(q) -> dict:
    t0 = time.monotonic()
    try:
        if q["kind"] == "tcp":
            socket.create_connection(("127.0.0.1", q["port"]), timeout=TIMEOUT).close()
            return {"name": q["name"], "ok": True, "message": "port open"}
        if q["kind"] == "tls":
            with socket.create_connection(("127.0.0.1", q["port"]), timeout=TIMEOUT) as s:
                with _ctx().wrap_socket(s, server_hostname=q["server_name"]) as t:
                    return {"name": q["name"], "ok": True, "message": f"TLS ok ({t.version()}), certificate valid for {q['server_name']}"}
        conn = http.client.HTTPConnection("127.0.0.1", q["port"], timeout=TIMEOUT)
        if q["kind"] == "https":   # the socket goes to loopback; SNI and certificate verification are for the service's name
            conn.sock = _ctx().wrap_socket(socket.create_connection(("127.0.0.1", q["port"]), timeout=TIMEOUT), server_hostname=q["server_name"])
        host = q.get("server_name") or "127.0.0.1"
        conn.request("GET", q["path"], headers={"Host": host, "User-Agent": "ou-agent-probe", "X-Forwarded-Proto": "https", "X-Forwarded-Host": host})
        r = conn.getresponse()
        body = r.read(MAX_READ).decode("utf-8", "replace")
        conn.close()
        ok = r.status == q["expect_status"] and (q.get("body_contains") is None or q["body_contains"] in body)
        why = f"HTTP {r.status}" + ("" if ok or r.status != q["expect_status"] else " (expected text missing)")
        return {"name": q["name"], "ok": ok, "status": r.status, "message": why + f" in {int((time.monotonic() - t0) * 1000)} ms"}
    except ssl.SSLCertVerificationError as e:
        return {"name": q["name"], "ok": False, "message": f"TLS certificate not valid for {q.get('server_name')}: {e.verify_message}"[:200]}
    except (OSError, ssl.SSLError, http.client.HTTPException) as e:
        return {"name": q["name"], "ok": False, "message": f"{type(e).__name__}: {e}"[:200]}


def execute(params) -> dict:
    return {"probes": [one(q) for q in params["probes"]]}
