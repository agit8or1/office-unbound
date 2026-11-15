#!/usr/bin/env python3
"""T15 Autodiscover POX request (Outlook-style) for alice.

POSTs the classic Autodiscover XML (2006 request schema, 2006a response
schema) to https://autodiscover.<domain>/autodiscover/autodiscover.xml and
https://<mail host>/autodiscover/autodiscover.xml with Basic auth, then lists
the protocols returned (EXCH/EXPR/WEB, MapiHttp, EWS URLs, LegacyDN).
PROVES: Autodiscover is served for the lab domain, returns a non-error
account section and which protocol endpoints grommunio advertises.
DOES NOT PROVE: that Outlook accepts the response (cert trust on the client,
SCP/DNS lookup order, modern-auth redirect, profile creation): MANUAL-CHECKLIST.md B1.
Also prints LegacyDN to the log for T16.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ou_lab as L

rep = L.Report("T15 Autodiscover POX")
if not L.need_requests(rep):
    rep.finish()
import requests
pw = L.password_for("alice")
if not (L.CA_FILE and pw):
    rep.skipped("config", "need OU_CA_FILE, OU_PASSWORD_ALICE"); rep.finish()
V = L.verify()
user = "alice@" + L.MAIL_DOMAIN
BODY = ('<?xml version="1.0" encoding="utf-8"?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">'
        "<Request><EMailAddress>%s</EMailAddress><AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>"
        "</Request></Autodiscover>") % user

def autodiscover(host):
    return requests.post("https://%s/autodiscover/autodiscover.xml" % host, data=BODY.encode(), auth=(user, pw), verify=V, timeout=30,
                         headers={"Content-Type": "text/xml"})

seen = False
for host in (L.HOST_AUTODISCOVER, L.HOST_MAIL):
    if not L.resolves(host):
        rep.skipped("autodiscover @ %s" % host, "name does not resolve (add to /etc/hosts)"); continue
    try:
        r = autodiscover(host)
    except Exception as e:  # noqa: BLE001
        rep.failed("autodiscover @ %s" % host, str(e)[:150]); continue
    txt = r.text
    ok = r.status_code == 200 and "<Account>" in txt and "<Error" not in txt
    rep.check("autodiscover @ %s" % host, ok, "Account section returned", "HTTP %s %s" % (r.status_code, re.sub(r"\s+", " ", txt)[:200]))
    if ok:
        seen = True
        types = re.findall(r"<Type>([^<]+)</Type>", txt)
        print("  info: protocol types: %s" % ", ".join(types))
        print("  info: MapiHttp present: %s" % ("MapiHttp" in txt))
        print("  info: EwsUrl: %s" % (re.findall(r"<EwsUrl>([^<]+)</EwsUrl>", txt) or ["-"])[0])
        ldn = re.findall(r"<LegacyDN>([^<]+)</LegacyDN>", txt)
        print("  info: LegacyDN: %s" % (ldn[0] if ldn else "-"))
        rep.check("MAPI/HTTP advertised", "MapiHttp" in txt or "mapi/emsmdb" in txt, "MapiHttp endpoint advertised",
                  "no MapiHttp/emsmdb in response: classic Outlook will not use MAPI/HTTP")
if not seen:
    rep.failed("autodiscover", "no host returned a valid Account response")
rep.finish()
