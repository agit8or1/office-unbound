#!/usr/bin/env python3
"""GW09: groupware restore drill (acceptance 17, groupware tier).
  gw_09_restore_drill.py seed     against the ORIGINAL node, BEFORE gw-backup.sh: sends one canary mail (unique token + random body) to a SQL lab user
                                  (grace), an LDAP user (alice@ou-lab.internal) and the shared mailbox (support), creates a CalDAV event for
                                  the LDAP user and for a SQL user (bob). Writes the state file (tokens, body sha256, Message-IDs).
  gw_09_restore_drill.py verify   against the RESTORED node (OU_GW1_RESOLVE=<ip of restore>; never touches /etc/hosts): IMAP INBOX count ==
                                  backup MANIFEST, canary present with byte-identical body, EWS FindItem finds it, shared-mailbox ACL restored
                                  (alice reads support via EWS), CalDAV event present, LDAP user logs in (restored gromox -> OpenLDAP),
                                  ActiveSync FolderSync for an LDAP user, then the unmodified gw_02 (MAPI/HTTP Connect) + gw_03 (EAS) tests.
Env: OU_DRILL_STATE (default $PWD/gw09-state.json), OU_DRILL_MANIFEST (verify), OU_GW1_RESOLVE, OU_GW1_HOST/CA/ENV (see gw_lab.py),
     OU_ID_MACHINE (default ou-id1; LDAP test password is read from there, never printed).
PROVES (lab, one run): logical backup content restored to a fresh machine is served over IMAP/EWS/DAV/EAS/MAPI-HTTP.
DOES NOT PROVE: ActiveSync device state, search index, free/busy, rules, anything not in IPM_SUBTREE (see restore-drill-results.md)."""
import email, email.policy, hashlib, imaplib, json, os, re, smtplib, ssl, subprocess, sys, time, email.message
import requests
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gw_lab as L
MODE = sys.argv[1] if len(sys.argv) > 1 else "verify"
STATE = os.environ.get("OU_DRILL_STATE", os.path.join(os.getcwd(), "gw09-state.json"))
IDM = os.environ.get("OU_ID_MACHINE", "ou-id1")
LDAP_DOM = "ou-lab.internal"
rep = L.Rep("GW09 restore drill (%s)" % MODE)
ctx = ssl.create_default_context(cafile=L.CA)
S = requests.Session(); S.verify = L.CA
B = "https://" + L.HOST

def ldap_pw(uid):
    p = subprocess.run(["sudo", "-n", "systemd-run", "-M", IDM, "--quiet", "--pipe", "--wait", "/bin/bash", "-c",
                        "grep ^OU_PASSWORD_%s= /root/ou-lab-secrets/test-users.env | tail -1" % uid.upper()], capture_output=True, text=True)
    return p.stdout.strip().split("=", 1)[1]
ACC = {  # label -> (address, password)
    "sql:grace": ("grace@" + L.HOST, L.PW["grace"]),
    "sql:bob": ("bob@" + L.HOST, L.PW["bob"]),
    "sql:alice": ("alice@" + L.HOST, L.PW["alice"]),
    "ldap:alice": ("alice@" + LDAP_DOM, ldap_pw("alice")),
}
SHARED = "support@" + L.HOST

def body_of(raw):
    m = email.message_from_bytes(raw, policy=email.policy.default)
    part = m.get_body(preferencelist=("plain",))
    txt = part.get_content() if part else ""
    return m, hashlib.sha256(txt.replace("\r\n", "\n").strip().encode()).hexdigest()
def imap_open(label):
    a, pw = ACC[label]; im = imaplib.IMAP4_SSL(L.HOST, 993, ssl_context=ctx, timeout=60); im.login(a, pw); return im
def imap_find(label, subj):
    im = imap_open(label); im.select("INBOX", readonly=True)
    t, d = im.search(None, "SUBJECT", '"%s"' % subj); ids = d[0].split(); out = []
    for i in ids:
        t, dd = im.fetch(i, "(BODY.PEEK[])"); out.append(dd[0][1])
    n = int(im.select("INBOX", readonly=True)[1][0]); im.logout(); return out, n
def soap(addr_pw, body):
    env = ('<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" '
           'xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"><soap:Header><t:RequestServerVersion Version="Exchange2013"/></soap:Header><soap:Body>%s</soap:Body></soap:Envelope>' % body)
    return S.post(B + "/EWS/Exchange.asmx", data=env.encode(), auth=addr_pw, headers={"Content-Type": "text/xml; charset=utf-8"}, timeout=90)
def folder_xml(mailbox=None):
    mb = "<t:Mailbox><t:EmailAddress>%s</t:EmailAddress></t:Mailbox>" % mailbox if mailbox else ""
    return '<t:DistinguishedFolderId Id="inbox">%s</t:DistinguishedFolderId>' % mb
def ews_find(label, subj, mailbox=None):
    r = soap(ACC[label], '<m:FindItem Traversal="Shallow"><m:ItemShape><t:BaseShape>Default</t:BaseShape></m:ItemShape><m:ParentFolderIds>%s</m:ParentFolderIds></m:FindItem>' % folder_xml(mailbox))
    return r.status_code == 200 and subj in r.text, r
def dav(label, uid): return "%s/dav/calendars/%s/Calendar/%s.ics" % (B, ACC[label][0], uid)

if MODE == "seed":
    st = {"run": L.RUN, "mail": {}, "cal": {}}
    rnd = os.urandom(24).hex()
    targets = [("sql:grace", "grace@" + L.HOST), ("ldap:alice", "alice@" + LDAP_DOM), ("shared:support", SHARED)]
    for label, to in targets:
        subj = "OU-DRILL-%s-%s" % (L.RUN, label.split(":")[1])
        text = "restore drill canary for %s\n%s\n%s\n" % (to, rnd, hashlib.sha256((rnd + label).encode()).hexdigest())
        m = email.message.EmailMessage(); m["From"], m["To"], m["Subject"] = "bob@" + L.HOST, to, subj
        m["Message-ID"] = "<drill-%s-%s@oulab.invalid>" % (L.RUN, label.split(":")[1]); m.set_content(text)
        r = smtplib.SMTP(L.HOST, 25, timeout=30).send_message(m); rep.check("SMTP canary to %s" % to, not r, "accepted", str(r))
        st["mail"][label] = {"to": to, "subject": subj, "message_id": m["Message-ID"], "body_sha256": hashlib.sha256(text.replace("\r\n", "\n").strip().encode()).hexdigest()}
    time.sleep(6)
    for label in ("sql:grace", "ldap:alice"):
        raws, n = imap_find(label, st["mail"][label]["subject"])
        ok = len(raws) == 1 and body_of(raws[0])[1] == st["mail"][label]["body_sha256"]
        rep.check("canary delivered %s" % label, ok, "1 message, body sha256 matches what was sent (INBOX now %d)" % n, "found %d" % len(raws))
    ok, r = ews_find("sql:alice", st["mail"]["shared:support"]["subject"], SHARED); rep.check("canary delivered shared:support (EWS as alice)", ok, "visible", "HTTP %s" % r.status_code)
    for label in ("ldap:alice", "sql:bob"):
        uid = "drill-%s-%s" % (L.RUN, label.replace(":", "-")); sub = "DRILL event %s" % uid
        ics = ("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//OU Lab//EN\r\nBEGIN:VEVENT\r\nUID:%s\r\nDTSTAMP:20261115T120000Z\r\nDTSTART:20261202T100000Z\r\nDTEND:20261202T110000Z\r\nSUMMARY:%s\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n" % (uid, sub))
        r = S.put(dav(label, uid), data=ics, headers={"Content-Type": "text/calendar"}, auth=ACC[label], timeout=60)
        rep.check("CalDAV PUT event %s" % label, r.status_code in (201, 204), "HTTP %s" % r.status_code, "HTTP %s %s" % (r.status_code, r.text[:200]))
        st["cal"][label] = {"uid": uid, "summary": sub}
    json.dump(st, open(STATE, "w"), indent=1); os.chmod(STATE, 0o600)
    print("state written: %s" % STATE)
    rep.done()

# ---------------------------------------------------------------- verify
st = json.load(open(STATE)); MF = os.environ["OU_DRILL_MANIFEST"]
mbx = {}
for ln in open(MF):
    if ln.startswith(("mbx|", "mbxraw|")):
        f = ln.rstrip("\n").split("|"); mbx[f[1]] = {"status": f[2], "total": int(f[3]), "inbox": int(f[4]), "cal": int(f[5])}
print("INFO restore target resolves %s -> %s" % (L.HOST, os.environ.get("OU_GW1_RESOLVE", "(normal DNS: THIS IS NOT A RESTORE TEST)")))
for label in ("sql:grace", "ldap:alice", "sql:bob"):
    addr = ACC[label][0]; exp = mbx[addr]["inbox"]
    try:
        raws, n = imap_find(label, "OU-DRILL-%s-" % st["run"]) if label in st["mail"] else ([], int(imap_open(label).select("INBOX", readonly=True)[1][0]))
    except Exception as e:
        rep.fail("IMAP login/select %s" % label, repr(e)[:200]); continue
    rep.check("IMAP INBOX count == manifest (%s)" % label, n == exp, "%d == %d (manifest, taken at backup time)" % (n, exp), "%d != manifest %d" % (n, exp))
    if label in st["mail"]:
        c = st["mail"][label]
        good = [r for r in raws if body_of(r)[1] == c["body_sha256"] and body_of(r)[0]["Subject"] == c["subject"]]
        rep.check("canary body identical (%s)" % label, len(raws) == 1 and len(good) == 1, "1 message, subject + body sha256 == pre-backup value, Message-ID %s" % (body_of(raws[0])[0]["Message-ID"] if raws else "?"), "found=%d identical=%d" % (len(raws), len(good)))
        ok, r = ews_find(label, c["subject"]); rep.check("EWS FindItem finds canary (%s)" % label, ok, "subject returned by FindItem", "HTTP %s" % r.status_code)
# shared mailbox: no direct login; ACL restored => alice reads it over EWS; counts via GetFolder
c = st["mail"]["shared:support"]
ok, r = ews_find("sql:alice", c["subject"], SHARED); rep.check("shared mailbox canary via EWS as alice (ACL restored)", ok, "visible", "HTTP %s %s" % (r.status_code, re.sub(r"\s+", " ", r.text[:200])))
r = soap(ACC["sql:alice"], '<m:GetFolder><m:FolderShape><t:BaseShape>Default</t:BaseShape></m:FolderShape><m:FolderIds>%s</m:FolderIds></m:GetFolder>' % folder_xml(SHARED))
tc = re.search(r"<t:TotalCount>(\d+)", r.text); exp = mbx[SHARED]["inbox"]
rep.check("shared inbox TotalCount == manifest", bool(tc) and int(tc.group(1)) == exp, "%s == %d" % (tc.group(1) if tc else "?", exp), "EWS %s vs manifest %d" % (tc.group(1) if tc else r.status_code, exp))
okc = True
for label in ("sql:carol",):
    pass
r = soap(("carol@" + L.HOST, L.PW["carol"]), '<m:FindItem Traversal="Shallow"><m:ItemShape><t:BaseShape>Default</t:BaseShape></m:ItemShape><m:ParentFolderIds>%s</m:ParentFolderIds></m:FindItem>' % folder_xml(SHARED))
rep.check("shared mailbox still denies carol (no ACL)", c["subject"] not in r.text, "ErrorAccessDenied / not visible", "LEAK")
for label, e in st["cal"].items():
    r = S.get(dav(label, e["uid"]), auth=ACC[label], timeout=60)
    rep.check("CalDAV event present (%s)" % label, r.status_code == 200 and e["summary"] in r.text, "GET 200, SUMMARY '%s'" % e["summary"], "HTTP %s" % r.status_code)
# ActiveSync FolderSync as the LDAP user (WBXML, SyncKey 0), same request bytes as gw_03
H = {"MS-ASProtocolVersion": "14.1", "Content-Type": "application/vnd.ms-sync.wbxml", "User-Agent": "OULab-EAS-drill/1.0"}
fs = bytes([0x03, 0x01, 0x6A, 0x00, 0x00, 0x07, 0x56, 0x52, 0x03]) + b"0\0" + bytes([0x01, 0x01])
r = S.post(B + "/Microsoft-Server-ActiveSync", params={"Cmd": "FolderSync", "User": ACC["ldap:alice"][0], "DeviceId": "oulabdrill01", "DeviceType": "OULab"}, data=fs, headers=H, auth=ACC["ldap:alice"], timeout=120)
rep.check("ActiveSync FolderSync (LDAP user)", r.status_code == 200 and b"Inbox" in r.content, "HTTP 200, %d bytes WBXML, Inbox listed" % len(r.content), "HTTP %s %r" % (r.status_code, r.content[:100]))
rc = 0
for t in ("gw_02_ews_mapi_autodiscover", "gw_03_activesync", "gw_04_dav", "gw_05_shared_mailbox"):
    p = subprocess.run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), t + ".py")], capture_output=True, text=True)
    lines = [l for l in p.stdout.splitlines() if l.startswith(("PASS", "FAIL", "--"))]
    print("\n".join("  [%s] %s" % (t[:5], l) for l in lines))
    rep.check("unmodified %s against the restore" % t, p.returncode == 0, "rc=0", "rc=%s %s" % (p.returncode, (p.stdout + p.stderr)[-300:]))
rep.done()
