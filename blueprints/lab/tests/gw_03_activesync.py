#!/usr/bin/env python3
"""GW03: ActiveSync via grommunio-sync: OPTIONS (no auth + auth), FolderSync (WBXML, SyncKey 0), then Sync of Inbox
must list the unique-token message (subject decoded from WBXML strings). Provisioning is OFF in the lab (no admin-api).
PROVES: nginx->php-fpm->php-mapi->gromox-zcore path works for EAS, WBXML protocol 14.1, redis state store.
DOES NOT PROVE: a real phone/Outlook EAS client (device-specific quirks), provisioning/remote wipe, push (Ping) over time."""
import os, re, sys, time, smtplib, email.message, requests
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gw_lab as L
rep = L.Rep("GW03 activesync")
B = "https://" + L.HOST + "/Microsoft-Server-ActiveSync"
S = requests.Session(); S.verify = L.CA
u = "carol"
auth = (L.addr(u), L.PW[u])
r = S.options(B, timeout=30)
rep.check("OPTIONS unauthenticated", r.status_code in (200, 401), "HTTP %s MS-Server-ActiveSync=%s" % (r.status_code, r.headers.get("MS-Server-ActiveSync")), "HTTP %s" % r.status_code)
r = S.options(B, auth=auth, timeout=30)
rep.check("OPTIONS auth: versions+commands", r.status_code == 200 and "14.1" in r.headers.get("MS-ASProtocolVersions", "") and "FolderSync" in r.headers.get("MS-ASProtocolCommands", ""),
          "versions=%s" % r.headers.get("MS-ASProtocolVersions"), "HTTP %s hdrs=%s" % (r.status_code, dict(r.headers)))
r = S.post(B, params={"Cmd": "FolderSync", "User": L.addr(u), "DeviceId": "oulabdev01", "DeviceType": "OULab"}, timeout=30)
rep.check("FolderSync unauth -> 401", r.status_code == 401, "401", "HTTP %s" % r.status_code)
H = {"MS-ASProtocolVersion": "14.1", "Content-Type": "application/vnd.ms-sync.wbxml", "User-Agent": "OULab-EAS-test/1.0"}
P = {"Cmd": "FolderSync", "User": L.addr(u), "DeviceId": "oulabdev01", "DeviceType": "OULab"}
fs = bytes([0x03, 0x01, 0x6A, 0x00, 0x00, 0x07, 0x56, 0x52, 0x03]) + b"0\0" + bytes([0x01, 0x01])
r = S.post(B, params=P, data=fs, headers=H, auth=auth, timeout=120)
rep.check("FolderSync", r.status_code == 200 and len(r.content) > 20 and b"Inbox" in r.content, "HTTP 200, %d bytes WBXML" % len(r.content),
          "HTTP %s len=%d body=%r hdr=%s" % (r.status_code, len(r.content), r.content[:200], r.headers.get("MS-Server-ActiveSync")))
# find inbox ServerId + SyncKey from response
sk = re.search(rb"\x52\x03([^\x00]+)\x00", r.content)
synckey = sk.group(1).decode() if sk else None
rep.check("FolderSync SyncKey", bool(synckey) and synckey != "0", "SyncKey=%s" % synckey, "no new SyncKey in response")
# deliver a token message to carol, then EAS Sync on inbox
tok = "OU-EAS-%s" % L.RUN
m = email.message.EmailMessage(); m["From"], m["To"], m["Subject"] = L.addr("alice"), L.addr(u), "eas probe " + tok; m.set_content("x")
smtplib.SMTP(L.HOST, 25, timeout=30).send_message(m); time.sleep(4)
folders = [(m.group(1).decode(), m.group(2).decode()) for m in re.finditer(rb"OH\x03(.*?)\x00\x01I\x03.*?\x00\x01G\x03(.*?)\x00\x01J\x03(\d+)", r.content)]
ids = [sid for sid, name in folders if name == "Inbox"]
rep.check("FolderSync parsed folders", len(folders) >= 4 and ids, "folders=%s" % [n for _, n in folders], "no Inbox in %r" % r.content[:200])
r2 = None
found = False
for sid in ids:
    # Sync request: AirSync(cp0): Sync(0x05) Collections(0x1C) Collection(0x0F) SyncKey(0x0B) CollectionId(0x12) GetChanges(0x13) ; WindowSize 0x15
    body = (bytes([0x03, 0x01, 0x6A, 0x00, 0x45, 0x5C, 0x4F, 0x4B, 0x03]) + b"0\0" + bytes([0x01, 0x52, 0x03]) + sid.encode() + b"\0" + bytes([0x01, 0x01, 0x01, 0x01]))
    r1 = S.post(B, params=dict(P, Cmd="Sync"), data=body, headers=H, auth=auth, timeout=120)
    k = re.search(rb"\x4B\x03([^\x00]+)\x00", r1.content)
    if r1.status_code != 200 or not k: continue
    body2 = (bytes([0x03, 0x01, 0x6A, 0x00, 0x45, 0x5C, 0x4F, 0x4B, 0x03]) + k.group(1) + b"\0" + bytes([0x01, 0x52, 0x03]) + sid.encode() + b"\0" + bytes([0x01, 0x13, 0x01, 0x01, 0x01]))
    r2 = S.post(B, params=dict(P, Cmd="Sync"), data=body2, headers=H, auth=auth, timeout=120)
    if tok.encode() in r2.content: found = True; break
rep.check("EAS Sync inbox contains token", found, "subject with %s found in Sync response (tried %d folders)" % (tok, len(ids)), "token not seen (ids tried=%s) - last status %s" % (ids[:8], (r2.status_code if r2 is not None else None) if ids else "n/a"))
rep.done()
