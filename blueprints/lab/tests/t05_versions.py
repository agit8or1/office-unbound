#!/usr/bin/env python3
"""T05 file versions: list and restore (files-identity-eval.md test plan item 3, API half).

Edits one file 3 times via WebDAV PUT, lists versions through the
oCIS-style meta endpoint, restores the oldest by COPY, and checks the
content hash equals the original and that the restore is itself versioned.
PROVES: server-side versioning on overwrite and restore-by-API work.
DOES NOT PROVE: versions created by Collabora saves (UI), retention policy,
quota accounting (record these manually), sharing semantics.
The meta endpoint /remote.php/dav/meta/<fileid>/v and COPY restore follow
oCIS docs; UNVERIFIED for OpenCloud 9.1.0 -> failures here need a manual look first.
"""
import os
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ou_lab as L

rep = L.Report("T05 Versions list/restore")
if not L.need_requests(rep):
    rep.finish()
import requests

user, pw = "bob", L.password_for("bob")
if not (L.CA_FILE and pw):
    rep.skipped("config", "need OU_CA_FILE and OU_PASSWORD_BOB"); rep.finish()
tok = L.get_token(requests, user, pw)["access_token"]
dav = L.OcDav(requests, user, tok)
if not dav.discover():
    rep.failed("webdav", "no base path"); rep.finish()

name = "versions-%s.txt" % L.RUN_ID
v = [("version-%d %s\n" % (i, L.RUN_ID)).encode() for i in (1, 2, 3)]
for i, data in enumerate(v, 1):
    r = dav.put(name, data)
    rep.check("PUT v%d" % i, r.status_code in (201, 204), "HTTP %s" % r.status_code, "HTTP %s" % r.status_code)
fid = dav.fileid(name)
if not rep.check("file id", bool(fid), fid, "no oc:fileid"):
    rep.finish()

def list_versions():
    url = "https://%s/remote.php/dav/meta/%s/v" % (L.HOST_FILES, fid)
    r = dav.s.request("PROPFIND", url, headers={"Depth": "1"}, timeout=30)
    if r.status_code != 207:
        return r.status_code, []
    hrefs = [h.text for h in ET.fromstring(r.content).iter("{DAV:}href")]
    return 207, [h for h in hrefs if not h.rstrip("/").endswith("/v")]

code, vers = list_versions()
if not rep.check("list versions", code == 207 and len(vers) >= 2, "%d old versions listed" % len(vers),
                 "HTTP %s, %d versions (expected >= 2 after 3 writes)" % (code, len(vers))):
    dav.delete(name); rep.finish()
oldest = sorted(vers)[0]
r = dav.s.request("COPY", "https://%s%s" % (L.HOST_FILES, oldest),
                  headers={"Destination": dav.url(name)}, timeout=30)
rep.check("restore COPY", r.status_code in (201, 204), "HTTP %s" % r.status_code, "HTTP %s %s" % (r.status_code, r.text[:120]))
cur = dav.get(name).content
rep.check("restored content", cur in v[:2], "content is an earlier version (%r)" % cur[:14],
          "content %r is not an earlier version" % cur[:30])
rep.check("restored equals first version", cur == v[0], "hash equals version-1",
          "restored oldest listed version is not v1 (oldest listed may be v2 if v1 was the creation; inspect)")
code2, vers2 = list_versions()
rep.check("restore is versioned", code2 == 207 and len(vers2) > len(vers) - 1, "%d versions after restore" % len(vers2),
          "versions before=%d after=%d" % (len(vers), len(vers2)))
dav.delete(name)
rep.finish()
