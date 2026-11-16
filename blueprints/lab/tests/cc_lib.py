"""Shared helpers for the desktop-client compatibility tests (cc_tb_*.py, cc_evo_*.py). They run INSIDE the lab desktop
machine ou-desk2 (see blueprints/lab/spike-desk/README.md) and read test-user passwords from /root/cc/users.env
(OU_PASSWORD_<UID>=...; created from ou-id1's test-users.env, never printed). TLS is always verified against the system store
(lab CA + gw1 CA installed there). Server-side verification uses plain IMAPS/EWS/DAV clients, independent from the client under test."""
import imaplib, json, os, re, sys, time, uuid, requests
sys.path.insert(0, "/root/cc")

HOST = "gw1.ou-lab.internal"
DOMAIN = "ou-lab.internal"
RUN = uuid.uuid4().hex[:6]
ENV = dict(l.strip().split("=", 1) for l in open("/root/cc/users.env") if "=" in l)


def pw(uid): return ENV["OU_PASSWORD_" + uid.upper()]
def addr(uid): return "%s@%s" % (uid, DOMAIN)


class Rep:
    def __init__(s, t): s.t = t; s.rows = []; print("== %s (run %s) ==" % (t, RUN))
    def _e(s, st, name, d, how):
        s.rows.append((st, name, d, how)); print("%s %s [%s] - %s" % (st, name, how, d)); sys.stdout.flush()
    def passed(s, name, d, how): s._e("PASS", name, d, how)
    def fail(s, name, d, how): s._e("FAIL", name, d, how)
    def partial(s, name, d, how): s._e("PARTIAL", name, d, how)
    def nosup(s, name, d, how): s._e("NOT SUPPORTED", name, d, how)
    def check(s, name, cond, okd, faild, how):
        (s.passed if cond else s.fail)(name, okd if cond else faild, how); return bool(cond)
    def done(s):
        n = {}
        for r in s.rows: n[r[0]] = n.get(r[0], 0) + 1
        print("-- %s: %s" % (s.t, ", ".join("%d %s" % (v, k) for k, v in n.items())))
        json.dump(s.rows, open("/root/cc/result-%s.json" % s.t.replace(" ", "_"), "w"), indent=1)


def imap(uid):
    M = imaplib.IMAP4_SSL(HOST, 993)
    M.login(addr(uid), pw(uid))
    return M


def imap_find(uid, subject, folder="INBOX", wait=40):
    """Server-side check: poll IMAP until a message with this Subject exists. Returns (uid, flags, raw) or None."""
    end = time.time() + wait
    while time.time() < end:
        M = imap(uid)
        try:
            typ, _ = M.select('"%s"' % folder, readonly=True)
            if typ == "OK":
                typ, d = M.search(None, "SUBJECT", '"%s"' % subject)
                ids = d[0].split()
                if ids:
                    typ, f = M.fetch(ids[-1], "(FLAGS BODY.PEEK[])")
                    flags = re.findall(rb"FLAGS \(([^)]*)\)", f[0][0])
                    return ids[-1], (flags[0].decode() if flags else ""), f[0][1]
        finally:
            try: M.logout()
            except Exception: pass
        time.sleep(2)
    return None


def imap_flags(uid, subject, folder="INBOX"):
    M = imap(uid)
    try:
        M.select('"%s"' % folder, readonly=True)
        typ, d = M.search(None, "SUBJECT", '"%s"' % subject)
        ids = d[0].split()
        if not ids: return None
        typ, f = M.fetch(ids[-1], "(FLAGS)")
        return re.findall(rb"FLAGS \(([^)]*)\)", f[0])[0].decode()
    finally:
        M.logout()


def imap_folders(uid):
    M = imap(uid)
    try:
        typ, d = M.list()
        return [re.findall(rb'"/" "?(.*?)"?$', x)[0].decode() for x in d]
    finally:
        M.logout()


def imap_append(uid, folder, raw):
    M = imap(uid)
    try:
        M.append('"%s"' % folder, None, None, raw)
    finally:
        M.logout()


def imap_store(uid, subject, op, flag, folder="INBOX"):
    M = imap(uid)
    try:
        M.select('"%s"' % folder)
        typ, d = M.search(None, "SUBJECT", '"%s"' % subject)
        for i in d[0].split():
            M.store(i, op, flag)
    finally:
        M.logout()


DAV = "https://%s/dav" % HOST


def dav(uid, method, path, **kw):
    return requests.request(method, DAV + path, auth=(addr(uid), pw(uid)), timeout=60, **kw)


def ews(uid, body):
    env = ('<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
           'xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" '
           'xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"><soap:Body>%s</soap:Body></soap:Envelope>' % body)
    return requests.post("https://%s/EWS/Exchange.asmx" % HOST, data=env, auth=(addr(uid), pw(uid)),
                         headers={"Content-Type": "text/xml"}, timeout=60)
