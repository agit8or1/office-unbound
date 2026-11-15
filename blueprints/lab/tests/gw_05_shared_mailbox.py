#!/usr/bin/env python3
"""GW05: shared mailbox 'support@' (address_status=4, not directly loginable): mail is delivered to it, direct login is
refused, and alice (granted via folder ACL) reads it over EWS using Mailbox/SmtpAddress addressing while carol (no ACL) cannot.
PROVES: shared-mailbox delivery + ACL enforcement in EWS. Lab ACLs were inserted into the store's sqlite (no admin-api).
DOES NOT PROVE: Outlook auto-mapping of shared mailboxes, send-as/send-on-behalf, IMAP shared folders."""
import os, re, sys, time, smtplib, imaplib, ssl, email.message, requests
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gw_lab as L
rep = L.Rep("GW05 shared mailbox")
tok = "OU-SHR-%s" % L.RUN; sh = L.addr("support")
m = email.message.EmailMessage(); m["From"], m["To"], m["Subject"] = L.addr("erin"), sh, "shared probe " + tok; m.set_content("x")
r = smtplib.SMTP(L.HOST, 25, timeout=30).send_message(m); rep.check("SMTP to shared mailbox", not r, "accepted", str(r)); time.sleep(4)
S = requests.Session(); S.verify = L.CA
def find(user):
    env = ('<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"><soap:Body>'
           '<m:FindItem Traversal="Shallow"><m:ItemShape><t:BaseShape>Default</t:BaseShape></m:ItemShape><m:ParentFolderIds><t:DistinguishedFolderId Id="inbox"><t:Mailbox><t:EmailAddress>%s</t:EmailAddress></t:Mailbox></t:DistinguishedFolderId></m:ParentFolderIds></m:FindItem></soap:Body></soap:Envelope>' % sh)
    return S.post("https://%s/EWS/Exchange.asmx" % L.HOST, data=env, auth=(L.addr(user), L.PW[user]), headers={"Content-Type": "text/xml"}, timeout=60)
r = find("alice")
rep.check("alice reads shared inbox via EWS", tok in r.text, "token visible in support@ inbox", "HTTP %s %s" % (r.status_code, re.sub(r"\s+", " ", r.text[:300])))
r = find("carol")
rep.check("carol (no ACL) denied", tok not in r.text, "not visible (HTTP %s, %s)" % (r.status_code, ",".join(re.findall(r"ResponseCode>([^<]+)", r.text))[:60]), "LEAK")
try:
    im = imaplib.IMAP4_SSL(L.HOST, 993, ssl_context=ssl.create_default_context(cafile=L.CA)); t = im.login(sh, L.PW["support"]); rep.fail("direct login support@", "login unexpectedly worked: %s" % (t,))
except imaplib.IMAP4.error as e: rep.ok("direct login support@ refused", str(e)[:80])
rep.done()
