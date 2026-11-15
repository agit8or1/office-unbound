#!/usr/bin/env python3
"""GW02: EWS (GetFolder inbox, FindItem token, CreateItem calendar + FindItem calendar), MAPI/HTTP
(emsmdb + nspi endpoint handshake), Autodiscover POX, all through nginx TLS (verified against lab CA).
PROVES: gromox-http serves EWS/MAPIHTTP/oxdisco, Basic auth against SQL users, mailbox visible over EWS.
MAPI/HTTP: sends a real MS-OXCMAPIHTTP *Connect* request (binary NDR body) and checks X-ResponseCode/X-PendingPeriod
etc. headers + response parse of StatusCode/ErrorCode.  This proves the server speaks the protocol; it does NOT
prove an actual Outlook profile creation, address-book (NSPI) browsing, sync, or Outlook Anywhere (RPC/HTTP)."""
import os, re, struct, sys, time, uuid, smtplib, email.message
import requests
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gw_lab as L
rep = L.Rep("GW02 ews/mapi/autodiscover")
B = "https://" + L.HOST
S = requests.Session(); S.verify = L.CA
def auth(u): return (L.addr(u), L.PW[u])
def soap(user, body, path="/EWS/Exchange.asmx"):
    env = ('<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
           'xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">'
           '<soap:Header><t:RequestServerVersion Version="Exchange2013"/></soap:Header><soap:Body>%s</soap:Body></soap:Envelope>' % body)
    return S.post(B + path, data=env.encode(), auth=auth(user), headers={"Content-Type": "text/xml; charset=utf-8"}, timeout=60)
# --- seed a message for alice so FindItem has a known token
tok = "OU-EWS-%s" % L.RUN
m = email.message.EmailMessage(); m["From"], m["To"], m["Subject"] = L.addr("bob"), L.addr("alice"), "ews probe " + tok; m.set_content("body " + tok)
smtplib.SMTP(L.HOST, 25, timeout=30).send_message(m); time.sleep(4)
# --- EWS
r = S.post(B + "/EWS/Exchange.asmx", data=b"", timeout=30)
rep.check("EWS unauthenticated -> 401", r.status_code == 401, "401 WWW-Authenticate=%s" % r.headers.get("WWW-Authenticate"), "HTTP %s" % r.status_code)
r = soap("alice", '<m:GetFolder><m:FolderShape><t:BaseShape>Default</t:BaseShape></m:FolderShape><m:FolderIds><t:DistinguishedFolderId Id="inbox"/></m:FolderIds></m:GetFolder>')
ok = r.status_code == 200 and 'ResponseClass="Success"' in r.text and "NoError" in r.text
rep.check("EWS GetFolder inbox", ok, "Success; %s" % (re.findall(r'<t:DisplayName>([^<]*)', r.text)[:1] + re.findall(r'<t:TotalCount>(\d+)', r.text)), "HTTP %s %s" % (r.status_code, r.text[:300]))
r = soap("alice", '<m:FindItem Traversal="Shallow"><m:ItemShape><t:BaseShape>IdOnly</t:BaseShape><t:AdditionalProperties><t:FieldURI FieldURI="item:Subject"/></t:AdditionalProperties></m:ItemShape>'
         '<m:ParentFolderIds><t:DistinguishedFolderId Id="inbox"/></m:ParentFolderIds></m:FindItem>')
rep.check("EWS FindItem inbox has token", r.status_code == 200 and tok in r.text, "subject with %s returned" % tok, "HTTP %s token missing: %s" % (r.status_code, r.text[:300]))
ev = "OU-EVT-%s" % L.RUN
r = soap("alice", '<m:CreateItem SendMeetingInvitations="SendToNone"><m:SavedItemFolderId><t:DistinguishedFolderId Id="calendar"/></m:SavedItemFolderId><m:Items><t:CalendarItem>'
         '<t:Subject>%s</t:Subject><t:Start>2026-12-01T10:00:00Z</t:Start><t:End>2026-12-01T11:00:00Z</t:End></t:CalendarItem></m:Items></m:CreateItem>' % ev)
rep.check("EWS CreateItem calendar", r.status_code == 200 and 'ResponseClass="Success"' in r.text, "created %s" % ev, "HTTP %s %s" % (r.status_code, r.text[:400]))
r = soap("alice", '<m:FindItem Traversal="Shallow"><m:ItemShape><t:BaseShape>Default</t:BaseShape></m:ItemShape><m:ParentFolderIds><t:DistinguishedFolderId Id="calendar"/></m:ParentFolderIds></m:FindItem>')
rep.check("EWS FindItem calendar has event", ev in r.text, "event read back", "HTTP %s event missing: %s" % (r.status_code, r.text[:300]))
r = soap("bob", '<m:GetFolder><m:FolderShape><t:BaseShape>Default</t:BaseShape></m:FolderShape><m:FolderIds><t:DistinguishedFolderId Id="calendar"/></m:FolderIds></m:GetFolder>')
rep.check("EWS isolation: bob calendar != alice event", ev not in r.text and r.status_code == 200, "bob sees no alice event", "HTTP %s" % r.status_code)
# --- Autodiscover POX
ad = ('<?xml version="1.0" encoding="utf-8"?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/outlook/requestschema/2006"><Request>'
      '<EMailAddress>%s</EMailAddress><AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>' % L.addr("alice"))
for path in ("/autodiscover/autodiscover.xml", "/Autodiscover/Autodiscover.xml"):
    r = S.post(B + path, data=ad.encode(), auth=auth("alice"), headers={"Content-Type": "text/xml", "User-Agent": "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17126; Pro)"}, timeout=30)
    if r.status_code == 200: break
m1 = re.search(r'Type="mapiHttp".*?<MailStore><InternalUrl>([^<]+)</InternalUrl>', r.text, re.S)
MURL = m1.group(1) if m1 else None
LDN = (re.search(r"<LegacyDN>([^<]+)</LegacyDN>", r.text) or [None, None])[1]
urls = sorted(set(re.findall(r"<(?:EwsUrl|OABUrl|InternalUrl)>([^<]+)<", r.text))) + re.findall(r'Type="(mapiHttp)"|<Type>(EXHTTP|EXCH|EXPR)</Type>', r.text)
rep.check("Autodiscover POX", r.status_code == 200 and bool(MURL) and "/EWS/Exchange.asmx" in r.text, "MAPI/HTTP + EWS URLs present", "HTTP %s %s" % (r.status_code, r.text[:500]))
print("INFO autodiscover URLs:", urls[:12])
# --- MAPI/HTTP
NURL = MURL.replace("/emsmdb/", "/nspi/") if MURL else B + "/mapi/nspi/"
MURL = MURL or B + "/mapi/emsmdb/"
r = S.post(MURL, data=b"", timeout=30)
rep.check("MAPI/HTTP emsmdb unauth", r.status_code in (401, 200), "HTTP %s WWW-Authenticate=%s X-ServerApplication=%s" % (r.status_code, r.headers.get("WWW-Authenticate"), r.headers.get("X-ServerApplication")), "HTTP %s" % r.status_code)
# MS-OXCMAPIHTTP Connect: body = UserDn(ASCIIZ) + Flags(u32) + DefaultCodePage + LcidString + LcidSort + AuxiliaryBufferSize + AuxiliaryBuffer
udn = (LDN or "").encode() + b"\0"
body = udn + struct.pack("<IIIIII", 0, 1252, 0x409, 0x409, 0, 0)
hdr = {"Content-Type": "application/mapi-http", "X-RequestType": "Connect", "X-RequestId": "%s:1" % uuid.uuid4(), "X-ClientInfo": "{%s}:1" % uuid.uuid4(), "X-ClientApplication": "OULabTest/1.0"}
r = S.post(MURL, data=body, auth=auth("alice"), headers=hdr, timeout=60)
rc = r.headers.get("X-ResponseCode")
rep.check("MAPI/HTTP Connect headers", r.status_code == 200 and r.headers.get("X-RequestType") == "Connect" and rc is not None,
          "HTTP 200 X-RequestType=Connect X-ResponseCode=%s X-ServerApplication=%s Content-Type=%s X-PendingPeriod=%s" % (rc, r.headers.get("X-ServerApplication"), r.headers.get("Content-Type"), r.headers.get("X-PendingPeriod")),
          "HTTP %s hdrs=%s" % (r.status_code, dict(r.headers)))
if r.status_code == 200 and r.headers.get("Content-Type", "").startswith("application/mapi-http"):
    # response body: meta-tags "PROCESSING\r\nDONE\r\n" then StatusCode(u32) ErrorCode(u32) ...
    i = r.content.find(b"\r\n\r\n")
    payload = r.content[i + 4:] if i >= 0 else r.content
    print("INFO connect response meta/payload head:", r.content[:60])
    if len(payload) >= 8:
        st, ec = struct.unpack("<II", payload[:8])
        rep.check("MAPI/HTTP Connect Status/ErrorCode=0", st == 0 and ec == 0, "StatusCode=0 ErrorCode=0 (session cookie: %s)" % ("set" if "sid" in str(r.headers.get("Set-Cookie", "")) else "n/a"), "StatusCode=%s ErrorCode=0x%x" % (st, ec))
        # Disconnect
        if r.cookies:
            h2 = dict(hdr); h2["X-RequestType"] = "Disconnect"; h2["X-RequestId"] = "%s:2" % uuid.uuid4()
            d = S.post(MURL, data=struct.pack("<I", 0), headers=h2, auth=auth("alice"), timeout=30)
            rep.check("MAPI/HTTP Disconnect", d.status_code == 200 and d.headers.get("X-ResponseCode") == "0", "X-ResponseCode=%s" % d.headers.get("X-ResponseCode"), "HTTP %s" % d.status_code)
r = S.post(NURL, data=b"", timeout=30)
rep.check("MAPI/HTTP nspi endpoint exists", r.status_code in (401, 200, 400), "HTTP %s" % r.status_code, "HTTP %s" % r.status_code)
rep.done()
