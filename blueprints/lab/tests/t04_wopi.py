#!/usr/bin/env python3
"""T04 WOPI reachability: OpenCloud collaboration service <-> Collabora, with content check.

PROVES: Collabora discovery lists OOXML actions; OpenCloud's app registry
offers CollaboraOnline for docx; /app/open mints a WOPI access token; the
WOPI host answers CheckFileInfo and GetFile over the lab-CA TLS with the
expected file name, size and bytes.
DOES NOT PROVE: that Collabora itself can reach OpenCloud (Collabora ->
WOPI host TLS/allow-list), loads the document, renders it, or saves it back
(PutFile). That needs a browser session: MANUAL-CHECKLIST.md A1-A3.
Endpoints /app/list and /app/open and the JSON shape follow OpenCloud/oCIS
app-provider docs and are UNVERIFIED for 9.1.0.
"""
import os
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ou_lab as L

rep = L.Report("T04 WOPI / Collabora reachability")
if not L.need_requests(rep):
    rep.finish()
import requests
try:
    import docx
except ImportError as e:
    rep.skipped("dependencies", "python-docx missing"); rep.finish()
import io

user, pw = "bob", L.password_for("bob")
if not (L.CA_FILE and pw):
    rep.skipped("config", "need OU_CA_FILE and OU_PASSWORD_BOB"); rep.finish()
V = L.verify()

r = requests.get("https://%s/hosting/discovery" % L.HOST_OFFICE, verify=V, timeout=30)
rep.check("collabora discovery", r.status_code == 200 and b"wopi-discovery" in r.content and b"docx" in r.content,
          "discovery XML lists docx", "HTTP %s %s" % (r.status_code, r.text[:100]))
r = requests.get("https://%s/hosting/capabilities" % L.HOST_OFFICE, verify=V, timeout=30)
rep.check("collabora capabilities", r.status_code == 200 and "productVersion" in r.text, "capabilities JSON: %s" % r.text[:80],
          "HTTP %s" % r.status_code)

tok = L.get_token(requests, user, pw)["access_token"]
H = {"Authorization": "Bearer " + tok}
dav = L.OcDav(requests, user, tok)
if not dav.discover():
    rep.failed("webdav", "no base path"); rep.finish()

apps = requests.get("https://%s/app/list" % L.HOST_FILES, headers=H, verify=V, timeout=30)
rep.check("app registry lists Collabora", apps.status_code == 200 and "Collabora" in apps.text,
          "CollaboraOnline registered", "HTTP %s %s (collaboration service not registered? check journalctl -u opencloud)" % (apps.status_code, apps.text[:150]))

d = docx.Document(); d.add_paragraph("WOPI check %s" % L.RUN_ID)
b = io.BytesIO(); d.save(b); content = b.getvalue()
name = "wopi-%s.docx" % L.RUN_ID
rep.check("upload", dav.put(name, content).status_code in (201, 204), "uploaded %s" % name, "upload failed")
fid = dav.fileid(name)
if not rep.check("file id", bool(fid), "oc:fileid=%s" % fid, "no oc:fileid returned"):
    rep.finish()

op = requests.post("https://%s/app/open?file_id=%s&app_name=CollaboraOnline" % (L.HOST_FILES, urllib.parse.quote(fid, safe="")),
                   headers=H, verify=V, timeout=60)
if not rep.check("app/open", op.status_code == 200 and "app_url" in op.text, "app_url returned",
                 "HTTP %s %s" % (op.status_code, op.text[:200])):
    dav.delete(name); rep.finish()
j = op.json()
wopi_token = (j.get("form_parameters") or {}).get("access_token")
q = urllib.parse.parse_qs(urllib.parse.urlparse(j["app_url"]).query)
wopi_src = (q.get("WOPISrc") or [None])[0]
rep.check("WOPISrc + token", bool(wopi_src and wopi_token), "WOPISrc=%s" % wopi_src,
          "missing (app_url=%s form=%s)" % (j.get("app_url"), j.get("form_parameters")))
if wopi_src and wopi_token:
    ci = requests.get(wopi_src, params={"access_token": wopi_token}, verify=V, timeout=30)
    if rep.check("CheckFileInfo", ci.status_code == 200, "HTTP 200", "HTTP %s %s" % (ci.status_code, ci.text[:150])):
        info = ci.json()
        rep.check("CheckFileInfo content", info.get("BaseFileName") == name and info.get("Size") == len(content),
                  "BaseFileName/Size match (UserCanWrite=%s)" % info.get("UserCanWrite"),
                  "got BaseFileName=%r Size=%r expected %r/%d" % (info.get("BaseFileName"), info.get("Size"), name, len(content)))
    gf = requests.get(wopi_src + "/contents", params={"access_token": wopi_token}, verify=V, timeout=30)
    rep.check("GetFile bytes", gf.status_code == 200 and gf.content == content, "identical bytes",
              "HTTP %s, %s" % (gf.status_code, "differs" if gf.status_code == 200 else gf.text[:100]))
    bad = requests.get(wopi_src, params={"access_token": wopi_token + "x"}, verify=V, timeout=30)
    rep.check("bad token rejected", bad.status_code in (401, 403), "HTTP %s" % bad.status_code, "HTTP %s: tampered token accepted" % bad.status_code)
dav.delete(name)
rep.finish()
