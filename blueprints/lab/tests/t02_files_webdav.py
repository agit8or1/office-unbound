#!/usr/bin/env python3
"""T02 WebDAV upload/download/rename/delete + restart persistence (OpenCloud).

Implements files-identity-eval.md test plan items 2 (storage half) and 4 (restart).
Auth: Keycloak bearer token for bob (OpenCloud basic auth is disabled by design).
PROVES: bytes written through WebDAV come back identical (sha256), also after an
OpenCloud service restart. DOES NOT PROVE: desktop-client sync/conflict
behaviour, full VM reboot, snapshot restore (manual).
Env: OU_CA_FILE, OU_PASSWORD_BOB, optional OU_SSH_FILES for the restart step.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ou_lab as L

rep = L.Report("T02 WebDAV round-trip")
if not L.need_requests(rep):
    rep.finish()
import requests

user, pw = "bob", L.password_for("bob")
if not (L.CA_FILE and pw):
    rep.skipped("config", "need OU_CA_FILE and OU_PASSWORD_BOB")
    rep.finish()
try:
    tok = L.get_token(requests, user, pw)["access_token"]
except Exception as e:  # noqa: BLE001
    rep.failed("token", str(e)[:200])
    rep.finish()

dav = L.OcDav(requests, user, tok)
base = dav.discover()
if not rep.check("webdav base path", bool(base), "using %s" % base,
                 "PROPFIND 207 on none of %s (path UNVERIFIED for 9.1.0 or auth rejected)" % L.OcDav.CANDIDATES):
    rep.finish()

d = "ou-lab-tests-%s" % L.RUN_ID
rep.check("MKCOL", dav.mkcol(d).status_code in (201, 405), "created %s" % d, "MKCOL failed")
small = ("hello office-unbound %s\n" % L.RUN_ID).encode()
big = os.urandom(3 * 1024 * 1024)
for name, data in (("small.txt", small), ("big.bin", big)):
    r = dav.put("%s/%s" % (d, name), data)
    rep.check("PUT %s" % name, r.status_code in (201, 204), "HTTP %s" % r.status_code,
              "HTTP %s %s" % (r.status_code, r.text[:100]))
    g = dav.get("%s/%s" % (d, name))
    rep.check("GET %s identical" % name, g.status_code == 200 and L.sha256(g.content) == L.sha256(data),
              "sha256 %s" % L.sha256(data)[:12], "HTTP %s, hash mismatch" % g.status_code)

pf = dav.propfind(d)
rep.check("PROPFIND lists files", pf.status_code == 207 and b"small.txt" in pf.content and b"big.bin" in pf.content,
          "both files listed", "HTTP %s" % pf.status_code)
mv = dav.s.request("MOVE", dav.url(d + "/small.txt"), headers={"Destination": dav.url(d + "/renamed.txt")}, timeout=30)
rep.check("MOVE (rename)", mv.status_code in (201, 204), "HTTP %s" % mv.status_code, "HTTP %s" % mv.status_code)
rep.check("renamed content intact", L.sha256(dav.get(d + "/renamed.txt").content) == L.sha256(small),
          "hash ok", "hash mismatch after MOVE")

ok, detail = L.ssh_restart("files", "opencloud")
if ok is None:
    rep.skipped("restart persistence", detail)
elif not ok:
    rep.failed("restart persistence", detail)
else:
    try:
        L.wait_http(requests, "https://%s/.well-known/openid-configuration" % L.HOST_FILES, 120)
        tok = L.get_token(requests, user, pw)["access_token"]
        dav = L.OcDav(requests, user, tok)
        dav.discover()
        g = dav.get(d + "/big.bin")
        rep.check("data after opencloud restart", g.status_code == 200 and L.sha256(g.content) == L.sha256(big),
                  "big.bin identical after restart", "HTTP %s / mismatch" % g.status_code)
    except Exception as e:  # noqa: BLE001
        rep.failed("data after opencloud restart", str(e)[:200])

dav.delete(d)
rep.check("cleanup", dav.get(d + "/big.bin").status_code == 404, "deleted", "folder still readable (trashbin is fine; check manually)")
rep.finish()
