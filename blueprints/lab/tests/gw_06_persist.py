#!/usr/bin/env python3
"""GW06: persistence across restart. `seed` delivers a unique token to alice+bob, stores it in /tmp/gw1-persist.tok;
`verify` (run after machine restart) finds it again via IMAP (alice) and EWS (bob) and via EAS-independent DAV event read.
Usage: gw_06_persist.py seed|verify"""
import os, sys, time, imaplib, ssl, smtplib, email.message, requests
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gw_lab as L
TF = os.environ.get("GW_PERSIST_FILE", os.path.expanduser("~/.gw1-persist.tok"))
mode = sys.argv[1] if len(sys.argv) > 1 else "verify"
rep = L.Rep("GW06 persist (%s)" % mode)
ctx = ssl.create_default_context(cafile=L.CA)
if mode == "seed":
    tok = "OU-PERSIST-%s" % L.RUN
    for to in ("alice", "bob"):
        m = email.message.EmailMessage(); m["From"], m["To"], m["Subject"] = L.addr("grace"), L.addr(to), "persist " + tok; m.set_content("x")
        rep.check("seed->%s" % to, not smtplib.SMTP(L.HOST, 25, timeout=30).send_message(m), "queued", "refused")
    uid = "persist-%s" % L.RUN
    ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//OU//EN\r\nBEGIN:VEVENT\r\nUID:%s\r\nDTSTAMP:20261115T120000Z\r\nDTSTART:20261202T100000Z\r\nDTEND:20261202T110000Z\r\nSUMMARY:%s\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n" % (uid, tok)
    r = requests.put("https://%s/dav/calendars/%s/Calendar/%s.ics" % (L.HOST, L.addr("alice"), uid), data=ics, headers={"Content-Type": "text/calendar"}, auth=(L.addr("alice"), L.PW["alice"]), verify=L.CA)
    rep.check("seed DAV event", r.status_code in (201, 204), "HTTP %s" % r.status_code, "HTTP %s" % r.status_code)
    time.sleep(4); open(TF, "w").write("%s %s\n" % (tok, uid)); os.chmod(TF, 0o600)
else:
    tok, uid = open(TF).read().split()
    for u in ("alice", "bob"):
        im = imaplib.IMAP4_SSL(L.HOST, 993, ssl_context=ctx); im.login(L.addr(u), L.PW[u]); im.select("INBOX")
        t, d = im.search(None, "SUBJECT", '"%s"' % tok)
        rep.check("IMAP %s has token after restart" % u, t == "OK" and bool(d[0].split()), "found", "missing"); im.logout()
    r = requests.get("https://%s/dav/calendars/%s/Calendar/%s.ics" % (L.HOST, L.addr("alice"), uid), auth=(L.addr("alice"), L.PW["alice"]), verify=L.CA)
    rep.check("DAV event after restart", r.status_code == 200 and tok in r.text, "event intact", "HTTP %s" % r.status_code)
rep.done()
