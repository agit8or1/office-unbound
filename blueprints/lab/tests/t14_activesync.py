#!/usr/bin/env python3
"""T14 ActiveSync: OPTIONS discovery + FolderSync (SyncKey 0).

OPTIONS /Microsoft-Server-ActiveSync with Basic auth must advertise
MS-Server-ActiveSync / MS-ASProtocolVersions / MS-ASProtocolCommands.
FolderSync is sent as hand-encoded WBXML (version 1.3, UTF-8,
FolderHierarchy code page 7: <FolderSync><SyncKey>0</SyncKey></FolderSync>)
and the reply is checked for HTTP 200 + <Status>1</Status>.
PROVES: grommunio-sync is reachable, authenticates the user and answers the
first protocol round (folder hierarchy).
DOES NOT PROVE: item sync (Sync cmd), Ping/push, Provision policy
enforcement (HTTP 449 is reported as SKIP), attachment handling, real
phone behaviour. Needs a real device/client: MANUAL-CHECKLIST.md B6.
WBXML byte layout is from MS-ASWBXML; UNVERIFIED by observation.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ou_lab as L

rep = L.Report("T14 ActiveSync")
if not L.need_requests(rep):
    rep.finish()
import requests
pw = L.password_for("alice")
if not (L.CA_FILE and pw):
    rep.skipped("config", "need OU_CA_FILE, OU_PASSWORD_ALICE"); rep.finish()
V = L.verify()
user = "alice@" + L.MAIL_DOMAIN
auth = (user, pw)
base = "https://%s/Microsoft-Server-ActiveSync" % L.HOST_MAIL

try:
    o = requests.options(base, auth=auth, verify=V, timeout=30)
except Exception as e:  # noqa: BLE001
    rep.failed("OPTIONS", str(e)[:200]); rep.finish()
hdr = {k.lower(): v for k, v in o.headers.items()}
rep.check("OPTIONS status", o.status_code == 200, "HTTP 200", "HTTP %s (401 => credentials not accepted via LDAP bind?)" % o.status_code)
vers = hdr.get("ms-asprotocolversions", "")
rep.check("protocol versions advertised", bool(vers), "MS-ASProtocolVersions: %s" % vers, "header missing")
rep.check("FolderSync command advertised", "FolderSync" in hdr.get("ms-asprotocolcommands", ""), "FolderSync in MS-ASProtocolCommands",
          "MS-ASProtocolCommands=%r" % hdr.get("ms-asprotocolcommands"))
rep.check("server header", "ms-server-activesync" in hdr, "MS-Server-ActiveSync: %s" % hdr.get("ms-server-activesync"), "missing")

version = "14.1" if "14.1" in vers else (vers.split(",")[-1] if vers else "14.1")
WBXML = bytes([0x03, 0x01, 0x6A, 0x00,  # wbxml 1.3, unknown public id, utf-8, no string table
               0x00, 0x07,              # switch to code page 7 (FolderHierarchy)
               0x56,                    # FolderSync (with content)
               0x52, 0x03, 0x30, 0x00, 0x01,  # SyncKey "0"
               0x01])                   # end FolderSync
q = "?Cmd=FolderSync&User=%s&DeviceId=oulab%s&DeviceType=OuLabTest" % (user, L.RUN_ID)
r = requests.post(base + q, data=WBXML, auth=auth, verify=V, timeout=60, headers={
    "Content-Type": "application/vnd.ms-sync.wbxml", "MS-ASProtocolVersion": version})
if r.status_code == 449:
    rep.skipped("FolderSync", "HTTP 449: device provisioning required; Provision handshake not implemented in this test")
else:
    ok = r.status_code == 200 and b"\x4c\x03\x31\x00" in r.content  # <Status>1</Status>
    rep.check("FolderSync", ok, "HTTP 200, Status 1 (%d bytes WBXML)" % len(r.content),
              "HTTP %s, %d bytes, Status!=1 or body not WBXML: %r" % (r.status_code, len(r.content), r.content[:40]))
rep.finish()
