#!/usr/bin/env python3
"""P03: bob (web softphone) calls carol (registered, does not answer) -> after the ring timeout the call falls into carol's voicemail,
bob's browser (fake microphone) records a message, hangs up -> Asterisk mails it (mailcmd -> gw1 SMTP :25, STARTTLS verified) to
carol's address from LDAP; verified by IMAPS login as carol (LDAP password) on the lab groupware, attachment present."""
import email
import imaplib
import os
import re
import ssl
import sys
import time

from playwright.sync_api import sync_playwright

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pbx_lib as L

rep = L.Report("P03 voicemail -> e-mail in carol's lab mailbox")
ctx_tls = ssl.create_default_context(cafile="/etc/office-unbound/lab/gw1-ca.crt")


def imap():
    im = imaplib.IMAP4_SSL("gw1.ou-lab.internal", 993, ssl_context=ctx_tls, timeout=30)
    im.login("carol@ou-lab.internal", L.password("carol"))
    im.select("INBOX")
    return im


def vm_ids(im):
    im.noop()
    t, d = im.search(None, "SUBJECT", '"[Voicemail]"')
    return set(d[0].split())


before = vm_ids(imap())
rep.check("baseline: voicemail mails already in carol's INBOX", True, len(before))
with sync_playwright() as p:
    b = L.browser(p)
    try:
        cb, pb = L.open_phone(b, "bob")
        cc, pc = L.open_phone(b, "carol")
        rep.check("both softphones registered", L.wait_state(pb, "#status", "registered", 30) is not None and L.wait_state(pc, "#status", "registered", 30) is not None)
        t0 = time.time()
        pb.fill("#number", "1003")
        pb.click("#call")
        pc.wait_for_selector("#answer", state="visible", timeout=15000)
        rep.check("carol's phone rings and she does NOT answer", True)
        # wait until bob's channel is inside VoiceMail()
        in_vm = False
        for _ in range(60):
            ch = L.ast("core show channels concise")
            if "!VoiceMail!" in ch:
                in_vm = True
                break
            time.sleep(1)
        rep.check("after the ring timeout bob's call is in VoiceMail()", in_vm, "%.0fs after dialling" % (time.time() - t0))
        time.sleep(22)  # bob "speaks" (Chromium fake microphone: periodic beep) while the greeting + beep play and the recording runs
        rep.check("bob's call state before hanging up: %s" % pb.get_attribute("#callstate", "data-state"), True)
        if not pb.is_disabled("#hangup"):
            pb.click("#hangup")
        L.wait_state(pb, "#callstate", "ended", 10)
        L.wait_state(pc, "#callstate", "ended", 10)
    finally:
        b.close()
files = L.pbx("find /var/spool/asterisk/voicemail/ou/1003/INBOX -type f -printf '%f %s\\n' | sort")
rep.check("voice message stored on the PBX (msg0000.* with audio data)", re.search(r"msg\d+\.(wav|WAV|gsm)\s+\d{3,}", files) is not None, files.strip().replace("\n", " | "))
new = set()
for _ in range(30):
    new = vm_ids(imap()) - before
    if new:
        break
    time.sleep(1)
rep.check("e-mail delivered to carol@ou-lab.internal (IMAPS on the lab groupware)", bool(new), "%d new" % len(new))
if new:
    im = imap()
    t, d = im.fetch(sorted(new)[-1], "(RFC822)")
    m = email.message_from_bytes(d[0][1])
    atts = [(pt.get_filename(), len(pt.get_payload(decode=True) or b"")) for pt in m.walk() if pt.get_filename()]
    print("   | From: %s | To: %s | Subject: %s" % (m["From"], m["To"], m["Subject"]))
    rep.check("subject names the caller (1002) and From is the PBX", "1002" in (m["Subject"] or "") and ("voicemail@" + L.PBX) in (m["From"] or ""), m["Subject"])
    rep.check("audio attachment present with data", bool(atts) and atts[0][1] > 500, atts)
    body = [pt.get_payload(decode=True).decode(errors="replace") for pt in m.walk() if pt.get_content_type() == "text/plain"]
    rep.check("body mentions caller name from LDAP (Lab Bob)", bool(body) and "Lab Bob" in body[0], (body[0].strip()[:120] if body else ""))
rep.finish()
