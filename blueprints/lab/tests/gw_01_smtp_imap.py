#!/usr/bin/env python3
"""GW01: SMTP (postfix :25 -> LMTP -> gromox-delivery) + IMAPS fetch of a unique token across users;
IMAP login for every provisioned user (>5: no user cap); external recipient must not leave the lab.
PROVES: postfix virtual_mailbox_maps(SQL) -> gromox LDA -> mailbox; IMAPS TLS chain; SQL-created users can authenticate.
DOES NOT PROVE: SMTP AUTH submission (587 not configured in the lab), DKIM/SPF, antispam, MAPI visibility."""
import email.message, imaplib, smtplib, ssl, time, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gw_lab as L
rep = L.Rep("GW01 smtp+imap")
ctx = ssl.create_default_context(cafile=L.CA)
tok = "OU-GW-%s" % L.RUN
def send(frm, to, subj):
    m = email.message.EmailMessage(); m["From"], m["To"], m["Subject"] = L.addr(frm), to, subj
    m.set_content("lab token %s\n" % tok)
    with smtplib.SMTP(L.HOST, 25, timeout=30) as s: return s.send_message(m)
def fetch(user, subj):
    end = time.time() + 60; last = ""
    while time.time() < end:
        try:
            im = imaplib.IMAP4_SSL(L.HOST, 993, ssl_context=ctx, timeout=30); im.login(L.addr(user), L.PW[user]); im.select("INBOX")
            t, d = im.search(None, "SUBJECT", '"%s"' % subj)
            if t == "OK" and d[0].split():
                t, m = im.fetch(d[0].split()[-1], "(RFC822)"); im.logout(); return m[0][1]
            im.logout()
        except Exception as e: last = str(e)[:150]
        time.sleep(2)
    return last or None
for a, b in (("alice", "bob"), ("carol", "dave")):
    try:
        r = send(a, L.addr(b), "gw %s>%s %s" % (a, b, tok))
        rep.check("SMTP %s->%s" % (a, b), not r, "accepted on :25", "refused %s" % r)
    except Exception as e: rep.fail("SMTP %s->%s" % (a, b), str(e)[:200]); continue
    got = fetch(b, "gw %s>%s %s" % (a, b, tok))
    rep.check("IMAPS fetch %s" % b, isinstance(got, bytes) and tok.encode() in got, "token in %s INBOX" % b, "not found: %r" % (got,))
for u in L.USERS:
    try:
        im = imaplib.IMAP4_SSL(L.HOST, 993, ssl_context=ctx, timeout=30); im.login(L.addr(u), L.PW[u]); im.logout(); rep.ok("IMAP login %s" % u)
    except Exception as e: rep.fail("IMAP login %s" % u, str(e)[:150])
rep.check("user count >5", len(L.USERS) > 5, "%d users logged in via IMAP" % len(L.USERS), "only %d users" % len(L.USERS))
try:
    smtplib.SMTP(L.HOST, 25, timeout=30).sendmail(L.addr("alice"), ["x@external-test.invalid"], "Subject: no\r\n\r\nx")
    rep.fail("external recipient", "accepted by postfix (relay open?)")
except smtplib.SMTPRecipientsRefused as e: rep.ok("external recipient", "refused: %s" % str(e)[:100])
except Exception as e: rep.fail("external recipient", str(e)[:150])
rep.done()
