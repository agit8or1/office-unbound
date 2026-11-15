#!/usr/bin/env python3
"""T04 WOPI / Collabora: OpenCloud collaboration service <-> real Collabora session, including an edit + save.

VERIFIED against OpenCloud 9.1.0 + Collabora CODE 26.04.6.1 (vendor .deb) in the nspawn lab.
PROVES: discovery up; OpenCloud's app registry lists CollaboraOnline; /app/open mints a WOPI token; a request WITHOUT
Collabora's proof-key headers is refused (so a WOPI-less client cannot read files with a leaked token alone);
a real Collabora websocket session loads the document (Collabora -> OpenCloud CheckFileInfo + GetFile over lab-CA TLS,
proof-key verified by OpenCloud); typing text and sending `save` makes Collabora PutFile the document back, the stored
DOCX then contains the typed text and OpenCloud lists a new version.
DOES NOT PROVE: rendering/UX in a browser, co-editing with two sessions, MS-authored file fidelity, tile rendering.
Needs: requests, python-docx, websocket-client.
"""
import io
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ou_lab as L

rep = L.Report("T04 WOPI / Collabora session")
if not L.need_requests(rep):
    rep.finish()
import requests
try:
    import docx
    import websocket
except ImportError:
    rep.skipped("dependencies", "python-docx / websocket-client missing"); rep.finish()

user, pw = "bob", L.password_for("bob")
if not (L.CA_FILE and pw):
    rep.skipped("config", "need OU_CA_FILE and OU_PASSWORD_BOB"); rep.finish()
V = L.verify()

r = requests.get("https://%s/hosting/discovery" % L.HOST_OFFICE, verify=V, timeout=30)
rep.check("collabora discovery", r.status_code == 200 and b"wopi-discovery" in r.content and b"docx" in r.content,
          "discovery XML lists docx", "HTTP %s %s" % (r.status_code, r.text[:100]))
r = requests.get("https://%s/hosting/capabilities" % L.HOST_OFFICE, verify=V, timeout=30)
rep.check("collabora capabilities", r.status_code == 200 and "productVersion" in r.text,
          "capabilities JSON: %s" % r.text[:80], "HTTP %s" % r.status_code)

tok = L.get_token(requests, user, pw)["access_token"]
dav = L.OcDav(requests, user, tok)
if not dav.discover():
    rep.failed("webdav", "no base path"); rep.finish()
# the collaboration service may still be re-registering after a restart: wait for the app registry
end = time.time() + 90
while True:
    apps = requests.get("https://%s/app/list" % L.HOST_FILES, headers={"Authorization": "Bearer " + tok}, verify=V, timeout=30)
    if apps.status_code == 200 and "CollaboraOnline" in apps.text or time.time() > end:
        break
    time.sleep(3)
rep.check("app registry lists Collabora", apps.status_code == 200 and "CollaboraOnline" in apps.text,
          "CollaboraOnline registered", "HTTP %s %s (collaboration service not registered? journalctl -u opencloud-collaboration)"
          % (apps.status_code, apps.text[:150]))

d = docx.Document(); d.add_paragraph("WOPI check %s" % L.RUN_ID)
b = io.BytesIO(); d.save(b); content = b.getvalue()
name = "wopi-%s.docx" % L.RUN_ID
rep.check("upload", dav.put(name, content).status_code in (201, 204), "uploaded %s" % name, "upload failed")
fid = dav.fileid(name)
if not rep.check("file id", bool(fid), "oc:fileid=%s" % fid, "no oc:fileid returned"):
    rep.finish()

S = L.CollaboraSession(requests, websocket, tok, fid)
if not rep.check("app/open", S.ok_open, "app_url + WOPI token returned", "HTTP %s %s" % (S.open_status, S.open_text[:200])):
    dav.delete(name); rep.finish()
bare = requests.get(S.wopi_src, params={"access_token": S.wopi_token}, verify=V, timeout=30)
rep.check("CheckFileInfo without proof-key refused", bare.status_code != 200,
          "HTTP %s (token alone is not enough; Collabora proof headers required)" % bare.status_code,
          "HTTP 200: WOPI token alone returned file info")
bad = requests.get(S.wopi_src, params={"access_token": S.wopi_token + "x"}, verify=V, timeout=30)
rep.check("tampered token refused", bad.status_code in (401, 403, 500), "HTTP %s" % bad.status_code, "HTTP %s" % bad.status_code)

try:
    loaded = S.connect_and_load()
    wopi_msg = next((m for m in S.messages if m.startswith("wopi:")), "")
    rep.check("Collabora loads document via WOPI", loaded and '"BaseFileName":"%s"' % name in wopi_msg,
              "session got status; CheckFileInfo BaseFileName=%s UserCanWrite visible" % name,
              "no status frame; messages=%s" % S.messages[-4:])
    rep.check("session is editable", "perm: edit" in S.messages, "perm: edit", "messages=%s" % S.messages[:6])
    saved = S.insert_text_and_save("EDITEDBYCOLLABORA")
    rep.check("Collabora save (PutFile)", saved, ".uno:Save success=true", "no save result; messages=%s" % S.messages[-4:])
except Exception as e:  # noqa: BLE001
    rep.failed("collabora session", str(e)[:200])
finally:
    S.close()
time.sleep(2)
g = dav.get(name)
try:
    paras = [p.text for p in docx.Document(io.BytesIO(g.content)).paragraphs]
except Exception as e:  # noqa: BLE001
    paras = ["<unparsable %s>" % e]
rep.check("stored DOCX contains Collabora edit", g.status_code == 200 and any("EDITEDBYCOLLABORA" in p for p in paras)
          and any("WOPI check %s" % L.RUN_ID in p for p in paras),
          "paragraphs=%s (bytes changed %d -> %d)" % (paras, len(content), len(g.content)), "paragraphs=%s" % paras)
import urllib.parse as up
vr = dav.s.request("PROPFIND", "https://%s/remote.php/dav/meta/%s/v" % (L.HOST_FILES, up.quote(fid, safe="$!")),
                   headers={"Depth": "1"}, timeout=30)
rep.check("Collabora save created a version", vr.status_code == 207 and ".REV." in vr.text,
          "version listed after save", "HTTP %s, no .REV. entries" % vr.status_code)
dav.delete(name)
rep.finish()
