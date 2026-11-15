#!/usr/bin/env python3
"""T05 file versions: list and restore (files-identity-eval.md test plan item 3, API half).

Edits one file 3 times via WebDAV PUT, lists versions through the
oCIS-style meta endpoint, restores the oldest by COPY, and checks the
content hash equals the original and that the restore is itself versioned.
PROVES: server-side versioning on overwrite and restore-by-API work.
DOES NOT PROVE: versions created by Collabora saves (UI), retention policy,
quota accounting (record these manually), sharing semantics.
VERIFIED against OpenCloud 9.1.0 in the lab run: PROPFIND /remote.php/dav/meta/<fileid>/v lists the collection
itself + one .../v/<id>.REV.<ts> per old version; restore = COPY of that href with a FULL-URL Destination
header (a path-only Destination gave HTTP 500).
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
    # first href is the meta collection itself (".../<fileid>/"); versions live under ".../v/<id>.REV.<utc-ts>"
    vs = [h for h in hrefs if "/v/" in h and ".REV." in h]
    def key(h):  # timestamps have 1-9 fractional digits: pad, else string sort misorders them
        ts = h.rsplit(".REV.", 1)[1].rstrip("Z")
        base, _, frac = ts.partition(".")
        return base + "." + frac.ljust(9, "0")
    return 207, sorted(vs, key=key)

code, vers = list_versions()
if not rep.check("list versions", code == 207 and len(vers) == 2, "%d old versions listed (3 writes => 2 old)" % len(vers),
                 "HTTP %s, %d versions (expected >= 2 after 3 writes)" % (code, len(vers))):
    dav.delete(name); rep.finish()
oldest = vers[0]  # list_versions() returns oldest first
r = dav.s.request("COPY", "https://%s%s" % (L.HOST_FILES, oldest),
                  headers={"Destination": dav.url(name)}, timeout=30)
rep.check("restore COPY", r.status_code in (201, 204), "HTTP %s" % r.status_code, "HTTP %s %s" % (r.status_code, r.text[:120]))
cur = dav.get(name).content
rep.check("restored content", cur in v[:2], "content is an earlier version (%r)" % cur[:14],
          "content %r is not an earlier version" % cur[:30])
rep.check("restored equals first version", cur == v[0], "hash equals version-1",
          "restored oldest listed version is not v1")
code2, vers2 = list_versions()
# Observed (9.1.0): restore CONSUMES the restored version and the replaced current content (v3) becomes a new
# version, so the count stays the same; prove versioning of the restore by content, not by count.
bodies = [dav.s.get("https://%s%s" % (L.HOST_FILES, h), timeout=30).content for h in vers2]
rep.check("restore is versioned", code2 == 207 and v[2] in bodies and v[0] not in bodies,
          "pre-restore content (v3) kept as a version; restored v1 is now current; versions=%d" % len(vers2),
          "versions after restore=%s (v3 present=%s)" % (len(vers2), v[2] in bodies))
dav.delete(name)
rep.finish()
