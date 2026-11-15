#!/usr/bin/env python3
"""T13 EWS SOAP: GetFolder(inbox) + FindItem.

POSTs real EWS SOAP requests to /EWS/Exchange.asmx with Basic auth (grommunio
accepts password auth for EWS; NTLM/Kerberos are not used). First sends an
unauthenticated request to confirm the endpoint challenges (401), then
GetFolder for the distinguished inbox and FindItem (shallow, first 5).
PROVES: the EWS endpoint is served, authenticates LDAP-backed users, and
returns ResponseClass="Success" for two core operations.
DOES NOT PROVE: operation coverage vs Exchange (CreateItem, Sync*, GetUserAvailability,
streaming notifications, delegation), nor that Outlook for Mac / Apple Mail work:
those need the real clients (MANUAL-CHECKLIST.md B3, B5).
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ou_lab as L

rep = L.Report("T13 EWS")
if not L.need_requests(rep):
    rep.finish()
import requests
pw = L.password_for("alice")
if not (L.CA_FILE and pw):
    rep.skipped("config", "need OU_CA_FILE, OU_PASSWORD_ALICE"); rep.finish()
V = L.verify()
url = "https://%s/EWS/Exchange.asmx" % L.HOST_MAIL
auth = ("alice@" + L.MAIL_DOMAIN, pw)
HDR = {"Content-Type": "text/xml; charset=utf-8"}
ENV = ('<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
       'xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" '
       'xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">'
       '<soap:Header><t:RequestServerVersion Version="Exchange2013_SP1"/></soap:Header><soap:Body>%s</soap:Body></soap:Envelope>')
GETFOLDER = ('<m:GetFolder><m:FolderShape><t:BaseShape>Default</t:BaseShape></m:FolderShape>'
             '<m:FolderIds><t:DistinguishedFolderId Id="inbox"/></m:FolderIds></m:GetFolder>')
FINDITEM = ('<m:FindItem Traversal="Shallow"><m:ItemShape><t:BaseShape>IdOnly</t:BaseShape></m:ItemShape>'
            '<m:IndexedPageItemView MaxEntriesReturned="5" Offset="0" BasePoint="Beginning"/>'
            '<m:ParentFolderIds><t:DistinguishedFolderId Id="inbox"/></m:ParentFolderIds></m:FindItem>')

try:
    r0 = requests.post(url, data=(ENV % GETFOLDER).encode(), headers=HDR, verify=V, timeout=30)
except Exception as e:  # noqa: BLE001
    rep.failed("endpoint", "%s: %s" % (url, str(e)[:150])); rep.finish()
rep.check("unauthenticated challenge", r0.status_code == 401, "401 with %s" % r0.headers.get("WWW-Authenticate", "?")[:60],
          "HTTP %s (expected 401; EWS not exposed or auth not enforced)" % r0.status_code)
for name, body, marker in (("GetFolder inbox", GETFOLDER, "GetFolderResponse"), ("FindItem inbox", FINDITEM, "FindItemResponse")):
    r = requests.post(url, data=(ENV % body).encode(), headers=HDR, auth=auth, verify=V, timeout=60)
    ok = r.status_code == 200 and marker in r.text and re.search(r'ResponseClass="Success"', r.text) is not None
    detail = "ResponseClass=Success" if ok else "HTTP %s ; %s" % (r.status_code, re.sub(r"\s+", " ", r.text)[:200])
    rep.check("EWS " + name, ok, detail, detail)
    if ok and name.startswith("FindItem"):
        n = len(re.findall(r"<t:Message>|<t:Message ", r.text))
        print("  info: %d message(s) in first page" % n)
rep.finish()
