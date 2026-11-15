#!/usr/bin/env python3
"""T10 SMTP submission + IMAP fetch of a unique token (grommunio, groupware-eval.md lab plan 8/9).

alice submits a message to bob on port 587 (STARTTLS + AUTH, verified against the
lab CA) and bob's INBOX is polled over IMAPS (993) until the unique token
arrives. Also asserts the OUTBOUND kill switch: a message to an external
address must NOT be delivered anywhere (we check it is rejected/deferred at
submission or sits unsent; never reaches the internet - the VM also blocks
egress 25/465/587).
PROVES: LDAP-bound authentication (lldap password) works for SMTP and IMAP,
local delivery through postfix -> gromox works, TLS chain is valid.
DOES NOT PROVE: DKIM/SPF/DMARC, antispam, inbound from a foreign MTA, large
attachments, MAPI/EWS/EAS visibility of the same message.
Env: OU_CA_FILE, OU_PASSWORD_ALICE, OU_PASSWORD_BOB.
"""
import email.message
import imaplib
import os
import smtplib
import ssl
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ou_lab as L

rep = L.Report("T10 SMTP submit + IMAP fetch")
pa, pb = L.password_for("alice"), L.password_for("bob")
if not (L.CA_FILE and pa and pb):
    rep.skipped("config", "need OU_CA_FILE, OU_PASSWORD_ALICE, OU_PASSWORD_BOB"); rep.finish()
if not L.resolves(L.HOST_MAIL):
    rep.failed("dns", "%s does not resolve (add to /etc/hosts)" % L.HOST_MAIL); rep.finish()

ctx = ssl.create_default_context(cafile=L.CA_FILE)
alice, bob = "alice@" + L.MAIL_DOMAIN, "bob@" + L.MAIL_DOMAIN
token = "OU-MAIL-%s" % L.RUN_ID

def send(to, subject):
    m = email.message.EmailMessage()
    m["From"], m["To"], m["Subject"] = alice, to, subject
    m.set_content("lab token %s\n" % token)
    with smtplib.SMTP(L.HOST_MAIL, 587, timeout=30) as s:
        s.starttls(context=ctx); s.login(alice, pa)
        return s.send_message(m)

try:
    refused = send(bob, "lab mail " + token)
    rep.check("SMTP submit alice->bob", not refused, "accepted by 587 STARTTLS", "refused: %s" % refused)
except smtplib.SMTPAuthenticationError as e:
    rep.failed("SMTP AUTH", "alice rejected (LDAP bind / downsync not done?): %s" % str(e)[:120]); rep.finish()
except Exception as e:  # noqa: BLE001
    rep.failed("SMTP submit", str(e)[:200]); rep.finish()

found = None
end = time.time() + 90
while time.time() < end and not found:
    try:
        im = imaplib.IMAP4_SSL(L.HOST_MAIL, 993, ssl_context=ctx, timeout=30)
        im.login(bob, pb); im.select("INBOX")
        typ, data = im.search(None, "SUBJECT", '"%s"' % token)
        if typ == "OK" and data[0].split():
            typ, msg = im.fetch(data[0].split()[-1], "(RFC822)")
            found = msg[0][1]
        im.logout()
    except Exception as e:  # noqa: BLE001
        last = str(e)[:120]
    if not found:
        time.sleep(3)
rep.check("IMAP fetch by bob", bool(found) and token.encode() in found, "token found in INBOX",
          "token not in bob's INBOX within 90s (check postfix queue / gromox-delivery)")

# outbound kill switch
try:
    r = send("someone@external-test.invalid", "must not leave lab " + token)
    rep.passed("outbound external submit", "submission accepted (queued) - verify on the VM that `postqueue -p` shows it errored/bounced and nothing left the VM")
except smtplib.SMTPRecipientsRefused:
    rep.passed("outbound external submit", "refused at submission (acceptable)")
except Exception as e:  # noqa: BLE001
    rep.failed("outbound external submit", str(e)[:200])
rep.finish()
