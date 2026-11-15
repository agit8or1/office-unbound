#!/usr/bin/env python3
"""T16 MAPI/HTTP endpoint handshake: PING + EMSMDB Connect.

1. Unauthenticated POST /mapi/emsmdb/ must challenge (401).
2. Authenticated PING (X-RequestType: PING) on /mapi/emsmdb/ and /mapi/nspi/
   must answer 200 with X-ResponseCode: 0.
3. Best effort: EMSMDB Connect with the user's LegacyDN (from Autodiscover)
   must return X-ResponseCode 0 and StatusCode 0 in the body.
PROVES: gromox-http serves MAPI/HTTP behind nginx, authenticates, and speaks the
transport framing (MS-OXCMAPIHTTP).
DOES NOT PROVE: that Outlook can build a profile, sync a mailbox in cached
mode, or survive a long session; no ROP execution (Execute) is attempted.
Real classic Outlook is REQUIRED for that: MANUAL-CHECKLIST.md B1.
Framing and Connect layout per MS-OXCMAPIHTTP; UNVERIFIED by observation.
"""
import os
import re
import struct
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ou_lab as L

rep = L.Report("T16 MAPI/HTTP handshake")
if not L.need_requests(rep):
    rep.finish()
import requests
pw = L.password_for("alice")
if not (L.CA_FILE and pw):
    rep.skipped("config", "need OU_CA_FILE, OU_PASSWORD_ALICE"); rep.finish()
V = L.verify()
user = "alice@" + L.MAIL_DOMAIN
auth = (user, pw)
base = "https://%s/mapi" % L.HOST_MAIL

def hdrs(kind):
    return {"X-RequestType": kind, "X-RequestId": "%s:1" % uuid.uuid4(), "X-ClientInfo": "{%s}-1" % uuid.uuid4(),
            "X-ClientApplication": "OuLabTest/0.1", "Content-Type": "application/mapi-http"}

try:
    r0 = requests.post(base + "/emsmdb/", data=b"", headers=hdrs("PING"), verify=V, timeout=30)
except Exception as e:  # noqa: BLE001
    rep.failed("endpoint", str(e)[:200]); rep.finish()
rep.check("unauthenticated challenge", r0.status_code == 401, "401", "HTTP %s (expected 401)" % r0.status_code)
for ep in ("emsmdb", "nspi"):
    r = requests.post("%s/%s/" % (base, ep), data=b"", headers=hdrs("PING"), auth=auth, verify=V, timeout=30)
    rc = r.headers.get("X-ResponseCode")
    rep.check("PING /mapi/%s/" % ep, r.status_code == 200 and rc == "0", "HTTP 200 X-ResponseCode 0",
              "HTTP %s X-ResponseCode=%s" % (r.status_code, rc))

# best-effort Connect
ldn = None
try:
    ad = requests.post("https://%s/autodiscover/autodiscover.xml" % L.HOST_MAIL, auth=auth, verify=V, timeout=30,
                       headers={"Content-Type": "text/xml"},
                       data=('<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006"><Request>'
                             "<EMailAddress>%s</EMailAddress><AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>"
                             "</Request></Autodiscover>" % user).encode())
    m = re.search(r"<LegacyDN>([^<]+)</LegacyDN>", ad.text)
    ldn = m.group(1) if m else None
except Exception:  # noqa: BLE001
    pass
if not ldn:
    rep.skipped("EMSMDB Connect", "no LegacyDN from Autodiscover (run T15 and inspect)")
else:
    body = (ldn.encode("ascii") + b"\x00" + struct.pack("<IIIII", 0, 1252, 0x409, 0x409, 0) + struct.pack("<I", 0))
    r = requests.post(base + "/emsmdb/?MailboxId=%s" % user, data=body, headers=hdrs("Connect"), auth=auth, verify=V, timeout=60)
    rc = r.headers.get("X-ResponseCode")
    payload = r.content
    # Responses may be prefixed by PROCESSING/DONE meta lines before the binary part.
    if b"\r\n\r\n" in payload[:200] and payload.lstrip().startswith((b"PROCESSING", b"PENDING", b"DONE")):
        payload = payload.split(b"\r\n\r\n", 1)[1]
    status = struct.unpack("<I", payload[:4])[0] if len(payload) >= 4 else None
    rep.check("EMSMDB Connect", r.status_code == 200 and rc == "0" and status == 0,
              "X-ResponseCode 0, StatusCode 0 (%d bytes)" % len(r.content),
              "HTTP %s X-ResponseCode=%s StatusCode=%s (framing assumptions UNVERIFIED; compare with Outlook trace)" % (r.status_code, rc, status))
rep.finish()
