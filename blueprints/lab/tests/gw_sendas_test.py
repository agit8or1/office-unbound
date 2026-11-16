#!/usr/bin/env python3
"""EWS send-as / send-on-behalf behaviour of Gromox (patch 0004). Lab test, prints PASS/FAIL per case, exit 1 on any FAIL.

Env (never printed): OU_PASSWORD_ALICE, OU_PASSWORD_BOB (lab directory users alice/bob), OU_CA_FILE (lab CA bundle, TLS is verified),
OU_GW_HOST (default gw1.ou-lab.internal), OU_LAB_DOMAIN (default ou-lab.internal), OU_GW_EXEC (command prefix that runs a shell string
on the groupware node, default `sudo systemd-run -M ou-gw1 --quiet --pipe --wait /bin/sh -c`). OU_STRICT_SKIP=1 turns a SKIP into a FAIL.
Cases: bob sends through EWS CreateItem with From=carol, to alice, with each grant on carol's store; the DELIVERED headers are read over IMAP.
Expected: none -> denied; sendas.txt -> From only; delegates.txt or ACL Send bit -> From + Sender (on behalf); sendas.txt + ACL -> From only.
Grants are removed again at the end."""
import imaplib, os, re, shlex, ssl, subprocess, sys, time
import requests

HOST = os.environ.get("OU_GW_HOST", "gw1.ou-lab.internal")
DOM = os.environ.get("OU_LAB_DOMAIN", "ou-lab.internal")
CA = os.environ.get("OU_CA_FILE")
EXEC = shlex.split(os.environ.get("OU_GW_EXEC", "sudo systemd-run -M ou-gw1 --quiet --pipe --wait /bin/sh -c"))
PWB, PWA = os.environ.get("OU_PASSWORD_BOB"), os.environ.get("OU_PASSWORD_ALICE")
if not (CA and PWB and PWA):
    print("SKIP gw_sendas: need OU_CA_FILE, OU_PASSWORD_ALICE, OU_PASSWORD_BOB")
    sys.exit(1 if os.environ.get("OU_STRICT_SKIP") else 0)

BOB, CAROL, ALICE = ("%s@%s" % (u, DOM) for u in ("bob", "carol", "alice"))
CAROL_DIR = "/var/lib/gromox/user/" + CAROL
DB = CAROL_DIR + "/exmdb/exchange.sqlite3"
ctx = ssl.create_default_context(cafile=CA)
fails = 0


def node(cmd):
    return subprocess.run(EXEC + [cmd], capture_output=True, text=True, timeout=60).stdout.strip()


def ews(body):
    env = ('<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
           'xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" '
           'xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"><soap:Header>'
           '<t:RequestServerVersion Version="Exchange2013"/></soap:Header><soap:Body>%s</soap:Body></soap:Envelope>' % body)
    return requests.post("https://%s/EWS/Exchange.asmx" % HOST, data=env, auth=(BOB, PWB), headers={"Content-Type": "text/xml"},
                         verify=CA, timeout=60).text


def reset():
    node("rm -f %s/config/sendas.txt %s/config/delegates.txt; sqlite3 %s \"DELETE FROM permissions WHERE username='%s'\"" % (CAROL_DIR, CAROL_DIR, DB, BOB))


SENDAS = "printf '%s\\r\\n' > {d}/config/sendas.txt; chown gromox:gromox {d}/config/sendas.txt".format(d=CAROL_DIR) % BOB
DELEG = "printf '%s\\r\\n' > {d}/config/delegates.txt; chown gromox:gromox {d}/config/delegates.txt".format(d=CAROL_DIR) % BOB
ACL = "sqlite3 %s \"INSERT OR REPLACE INTO permissions (folder_id,username,permission) VALUES (9,'%s',4)\"" % (DB, BOB)

CASES = [  # name, setup, expect_delivered, expect_sender_header
    ("no grant", "", False, None),
    ("sendas.txt only (send-as)", SENDAS, True, False),
    ("delegates.txt only (on behalf)", DELEG, True, True),
    ("folder ACL Send bit only (on behalf)", ACL, True, True),
    ("sendas.txt + ACL bit (send-as wins)", SENDAS + "; " + ACL, True, False),
]


def run_case(name, setup, deliver, sender):
    global fails
    reset()
    if setup:
        node(setup)
    subj = "sendas-%d-%d" % (abs(hash(name)) % 10**6, int(time.time()))
    frm = "<t:From><t:Mailbox><t:EmailAddress>%s</t:EmailAddress><t:RoutingType>SMTP</t:RoutingType></t:Mailbox></t:From>" % CAROL
    r = ews('<m:CreateItem MessageDisposition="SendAndSaveCopy"><m:SavedItemFolderId><t:DistinguishedFolderId Id="sentitems"/></m:SavedItemFolderId>'
            '<m:Items><t:Message><t:Subject>%s</t:Subject><t:Body BodyType="Text">x</t:Body><t:ToRecipients><t:Mailbox>'
            '<t:EmailAddress>%s</t:EmailAddress></t:Mailbox></t:ToRecipients>%s</t:Message></m:Items></m:CreateItem>' % (subj, ALICE, frm))
    rc = (re.search(r"<m:ResponseCode>(\w+)</m:ResponseCode>", r) or [None, "?"])[1]
    time.sleep(4)
    M = imaplib.IMAP4_SSL(HOST, 993, ssl_context=ctx)
    M.login(ALICE, PWA)
    M.select("INBOX")
    _, d = M.search(None, "SUBJECT", subj)
    hdr = ""
    if d[0]:
        n = d[0].split()[-1]
        _, dd = M.fetch(n, "(BODY.PEEK[HEADER.FIELDS (FROM SENDER)])")
        hdr = dd[0][1].decode()
        M.store(n, "+FLAGS", "\\Deleted")
        M.expunge()
    M.logout()
    got = bool(hdr)
    ok = got == deliver
    if deliver and ok:
        ok = (CAROL in re.search(r"(?im)^From:.*$", hdr).group(0)) and (bool(re.search(r"(?im)^Sender:.*%s" % re.escape(BOB), hdr)) == sender)
    print("%s %s: CreateItem=%s delivered=%s headers=%s" % ("PASS" if ok else "FAIL", name, rc, got, hdr.strip().replace("\r\n", " | ")))
    fails += not ok


try:
    for c in CASES:
        run_case(*c)
finally:
    reset()
print("gw_sendas: %d case(s), %d FAIL" % (len(CASES), fails))
sys.exit(1 if fails else 0)
