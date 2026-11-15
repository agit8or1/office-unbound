"""Shared helpers for gw_ldap_*.py (Gromox authenticating against the authoritative OpenLDAP; single user store).
Lab wiring (all defaults work from the ICS host with passwordless sudo; override by env):
  OU_GW1_CA            gw1 lab CA (default /etc/office-unbound/lab/gw1-ca.crt) - used for IMAPS/EWS/EAS
  OU_CA_FILE           lab CA of the identity machines (Keycloak/OpenCloud); if unset the Keycloak/OpenCloud steps SKIP
  OU_GW_MACHINE        nspawn machine of gromox            (default ou-gw1)
  OU_ID_MACHINE        nspawn machine of the directory     (default ou-id1)
  OU_KC_ADMIN_PASSWORD Keycloak admin password (optional: enables the Keycloak revoke step)
SKIP semantics: SKIP never hides a failure; with OU_STRICT_SKIP=1 any SKIP makes the run exit 77.
Passwords are read at run time and never printed. TLS is always verified."""
import imaplib, os, re, shlex, smtplib, email.message, ssl, struct, subprocess, sys, time, uuid
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

RUN = uuid.uuid4().hex[:8]
GW_HOST = os.environ.get("OU_GW1_HOST", "gw1.ou-lab.internal")
GW_CA = os.environ.get("OU_GW1_CA", "/etc/office-unbound/lab/gw1-ca.crt")
KC_CA = os.environ.get("OU_CA_FILE")
GW_M = os.environ.get("OU_GW_MACHINE", "ou-gw1")
ID_M = os.environ.get("OU_ID_MACHINE", "ou-id1")
KC_HOST = os.environ.get("OU_HOST_KC", "auth.ou-lab.internal")
OC_HOST = os.environ.get("OU_HOST_FILES", "cloud.ou-lab.internal")
MAIL_DOMAIN = os.environ.get("OU_MAIL_DOMAIN", "ou-lab.internal")
BASE_DN = "dc=" + MAIL_DOMAIN.replace(".", ",dc=")   # clean-room lab (cr.ou-lab.internal) support: no hard-coded names
LDAP_HOST = "ldap." + MAIL_DOMAIN
DIRSH = "/root/lab/spike-identity-files/kc/ldap-user.sh"
SYNC = "/usr/local/sbin/gw-ldap-sync.py"


class Rep:
    def __init__(s, t): s.t = t; s.n = {"PASS": 0, "FAIL": 0, "SKIP": 0}; print("== %s (run %s) ==" % (t, RUN))
    def _e(s, st, name, d): s.n[st] += 1; print("%s %s - %s" % (st, name, d)); sys.stdout.flush()
    def ok(s, name, d=""): s._e("PASS", name, d or "ok")
    def fail(s, name, d): s._e("FAIL", name, d)
    def skip(s, name, d): s._e("SKIP", name, d)
    def info(s, msg): print("INFO %s" % msg); sys.stdout.flush()
    def check(s, name, cond, okd, faild): (s.ok if cond else s.fail)(name, okd if cond else faild); return bool(cond)
    def done(s):
        print("-- %s: %d PASS, %d FAIL, %d SKIP" % (s.t, s.n["PASS"], s.n["FAIL"], s.n["SKIP"]))
        if s.n["FAIL"]: sys.exit(1)
        if s.n["SKIP"] and os.environ.get("OU_STRICT_SKIP") == "1":
            print("-- OU_STRICT_SKIP=1: SKIP treated as failure"); sys.exit(77)
        sys.exit(0)


def sh(machine, cmd, timeout=180):
    """Run a command inside an nspawn machine (as root) from the ICS host. Returns (rc, stdout+stderr)."""
    p = subprocess.run(["sudo", "-n", "systemd-run", "-M", machine, "--quiet", "--pipe", "--wait", "/bin/bash", "-c", cmd],
                       capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr)


def lab_access():
    try:
        rc, out = sh(ID_M, "true"); rc2, _ = sh(GW_M, "true")
        return rc == 0 and rc2 == 0
    except Exception:
        return False


def dir_cmd(action, user, extra=""):
    return sh(ID_M, "%s %s %s %s" % (DIRSH, action, shlex.quote(user), shlex.quote(extra) if extra else ""))


def dir_pw(user):
    rc, out = sh(ID_M, "grep ^OU_PASSWORD_%s= /root/ou-lab-secrets/test-users.env | tail -1" % user.upper())
    if rc != 0 or "=" not in out: raise RuntimeError("no password for %s" % user)
    return out.strip().split("=", 1)[1]


def gw_sync(args=""):
    rc, out = sh(GW_M, "%s %s" % (SYNC, args))
    return rc, out


def gw_sql(q):
    rc, out = sh(GW_M, "mysql -N email -e %s" % shlex.quote(q))
    return out.strip()


def imap_active():
    p = subprocess.run(["sudo", "-n", "systemctl", "-M", GW_M, "is-active", "gromox-imap"], capture_output=True, text=True)
    return p.stdout.strip() == "active"


def wait_imap_active(rep, timeout=300):
    """Coordination rule: never touch gromox units while another operator has gromox-imap down."""
    t = time.time()
    while not imap_active():
        if time.time() - t > timeout: return False
        rep.info("gromox-imap inactive (another operator?), waiting"); time.sleep(15)
    return True


def addr(u): return "%s@%s" % (u, MAIL_DOMAIN)
def new_user(prefix="gwl"): return "%s%s" % (prefix, uuid.uuid4().hex[:6])


# ---- protocol probes: each returns True when the credentials are ACCEPTED
_ctx = None
def ctx():
    global _ctx
    if _ctx is None: _ctx = ssl.create_default_context(cafile=GW_CA)
    return _ctx

def imap_login(mail, pw):
    try:
        im = imaplib.IMAP4_SSL(GW_HOST, 993, ssl_context=ctx(), timeout=20); im.login(mail, pw); im.logout(); return True
    except imaplib.IMAP4.error: return False

def imap_open(mail, pw):
    im = imaplib.IMAP4_SSL(GW_HOST, 993, ssl_context=ctx(), timeout=20); im.login(mail, pw); im.select("INBOX"); return im

def imap_alive(im):
    try: return im.noop()[0] == "OK" and im.select("INBOX")[0] == "OK"
    except Exception: return False

def _req():
    import requests
    return requests

def ews(mail, pw, session=None):
    """EWS GetFolder inbox -> (http status, ok)"""
    rq = session or _req()
    body = ('<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
            'xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">'
            '<soap:Header><t:RequestServerVersion Version="Exchange2013"/></soap:Header><soap:Body><m:GetFolder><m:FolderShape><t:BaseShape>Default</t:BaseShape></m:FolderShape>'
            '<m:FolderIds><t:DistinguishedFolderId Id="inbox"/></m:FolderIds></m:GetFolder></soap:Body></soap:Envelope>')
    r = rq.post("https://%s/EWS/Exchange.asmx" % GW_HOST, data=body.encode(), auth=(mail, pw), verify=GW_CA, timeout=30,
                headers={"Content-Type": "text/xml; charset=utf-8", "Connection": "keep-alive" if session else "close"})
    return r.status_code, (r.status_code == 200 and 'ResponseClass="Success"' in r.text)

def eas_options(mail, pw):
    r = _req().options("https://%s/Microsoft-Server-ActiveSync" % GW_HOST, auth=(mail, pw), verify=GW_CA, timeout=30)
    return r.status_code, r.status_code == 200

def mapi_status(mail, pw):
    """POST to the emsmdb endpoint: only the HTTP auth layer is probed (401 = refused). Not a full Connect."""
    r = _req().post("https://%s/mapi/emsmdb/" % GW_HOST, data=b"", auth=(mail, pw), verify=GW_CA, timeout=30,
                    headers={"Content-Type": "application/mapi-http", "X-RequestType": "PING", "X-RequestId": "%s:1" % uuid.uuid4(), "X-ClientInfo": "{%s}:1" % uuid.uuid4()})
    return r.status_code, r.status_code != 401

def mapi_connect(mail, pw):
    """Real MAPI/HTTP Connect via Autodiscover-advertised URL. Returns (X-ResponseCode, StatusCode/ErrorCode) or None."""
    import re
    rq = _req()
    ad = ('<?xml version="1.0" encoding="utf-8"?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006"><Request>'
          '<EMailAddress>%s</EMailAddress><AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>' % mail)
    r = rq.post("https://%s/autodiscover/autodiscover.xml" % GW_HOST, data=ad.encode(), auth=(mail, pw), verify=GW_CA, timeout=30,
                headers={"Content-Type": "text/xml", "User-Agent": "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17126; Pro)"})
    m1 = re.search(r'Type="mapiHttp".*?<MailStore><InternalUrl>([^<]+)</InternalUrl>', r.text, re.S)
    ldn = re.search(r"<LegacyDN>([^<]+)</LegacyDN>", r.text)
    if not (m1 and ldn): return None
    body = ldn.group(1).encode() + b"\0" + struct.pack("<IIIIII", 0, 1252, 0x409, 0x409, 0, 0)
    r = rq.post(m1.group(1), data=body, auth=(mail, pw), verify=GW_CA, timeout=60,
                headers={"Content-Type": "application/mapi-http", "X-RequestType": "Connect", "X-RequestId": "%s:1" % uuid.uuid4(), "X-ClientInfo": "{%s}:1" % uuid.uuid4()})
    if r.status_code != 200: return (r.status_code, None)
    return (r.headers.get("X-ResponseCode"), struct.unpack("<II", r.content[r.content.find(b"\r\n\r\n") + 4:][:8]) if b"\r\n\r\n" in r.content else None)

def kc_login(user, pw):
    r = _req().post("https://%s/realms/ou-lab/protocol/openid-connect/token" % KC_HOST, verify=KC_CA, timeout=30,
                    data={"grant_type": "password", "client_id": "ou-lab-test", "username": user, "password": pw, "scope": "openid profile email"})
    return r

def send_mail(frm, to, subj):
    m = email.message.EmailMessage(); m["From"], m["To"], m["Subject"] = frm, to, subj; m.set_content("lab token\n")
    with smtplib.SMTP(GW_HOST, 25, timeout=30) as s: return s.send_message(m)

def imap_fetch_subject(mail, pw, subj, wait=40):
    end = time.time() + wait
    while time.time() < end:
        try:
            im = imap_open(mail, pw); t, d = im.search(None, "SUBJECT", '"%s"' % subj); im.logout()
            if t == "OK" and d[0].split(): return True
        except Exception: pass
        time.sleep(2)
    return False
