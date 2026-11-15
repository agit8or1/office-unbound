"""Helpers for the gw1 (source-built Gromox) lab tests. Names gw_*.py are owned by the groupware engineer.
Config: /etc/office-unbound/lab/gw1-users.env (OU_GW1_PW_<user>=...), CA at gw1-ca.crt; override with
OU_GW1_ENV / OU_GW1_CA. Host gw1.ou-lab.internal must resolve (we add it to /etc/hosts on the ICS).
Never prints passwords. TLS is always verified against the lab CA."""
import os, socket, sys, uuid
HOST = os.environ.get("OU_GW1_HOST", "gw1.ou-lab.internal")
DOMAIN = HOST
# OU_GW1_RESOLVE=<ip>: connect to that IP for HOST (and autodiscover.HOST) while keeping the real name for SNI, Host header and
# certificate verification (restore drills: test a restored node by IP without touching /etc/hosts; same effect as curl --resolve).
_RES = os.environ.get("OU_GW1_RESOLVE")
if _RES:
    _orig_gai = socket.getaddrinfo
    def _gai(host, *a, **k): return _orig_gai(_RES if host in (HOST, "autodiscover." + HOST) else host, *a, **k)
    socket.getaddrinfo = _gai
CA = os.environ.get("OU_GW1_CA", "/etc/office-unbound/lab/gw1-ca.crt")
ENV = os.environ.get("OU_GW1_ENV", "/etc/office-unbound/lab/gw1-users.env")
RUN = uuid.uuid4().hex[:10]
PW = {}
for line in open(ENV):
    if line.startswith("OU_GW1_PW_"):
        k, v = line.strip().split("=", 1); PW[k[len("OU_GW1_PW_"):]] = v
USERS = [u for u in PW if u != "support"]
def addr(u): return "%s@%s" % (u, DOMAIN)
class Rep:
    def __init__(s, t): s.t = t; s.n = {"PASS": 0, "FAIL": 0, "SKIP": 0}; print("== %s (run %s) ==" % (t, RUN))
    def _e(s, st, name, d): s.n[st] += 1; print("%s %s - %s" % (st, name, d)); sys.stdout.flush()
    def ok(s, name, d=""): s._e("PASS", name, d or "ok")
    def fail(s, name, d): s._e("FAIL", name, d)
    def skip(s, name, d): s._e("SKIP", name, d)
    def check(s, name, cond, okd, faild): (s.ok if cond else s.fail)(name, okd if cond else faild); return bool(cond)
    def done(s):
        print("-- %s: %d PASS, %d FAIL, %d SKIP" % (s.t, s.n["PASS"], s.n["FAIL"], s.n["SKIP"]))
        if s.n["FAIL"]: sys.exit(1)
        if s.n["SKIP"] and os.environ.get("OU_STRICT_SKIP") == "1": print("-- OU_STRICT_SKIP=1: SKIP treated as failure"); sys.exit(77)
        sys.exit(0)
