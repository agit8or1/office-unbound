#!/usr/bin/env python3
"""T07 Desktop sync with the real OpenCloud desktop sync engine (opencloudcmd 4.0.0, same
libsync as the GUI client) running in lab machine OU_MACHINE_DESK (default ou-desk1).

Proves: upload, download, offline local edits + remote edits merged on reconnect, conflict
detection (both versions preserved), delete propagation. Does NOT prove: GUI client UX, the
virtual-files (on-demand) mode, Windows/macOS clients, desktop notifications.
Needs: OU_CA_FILE, OU_PASSWORD_BOB, sudo for systemd-run into the desk machine.
"""
import os, shlex, subprocess, sys, time, uuid
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ou_lab as L

rep = L.Report("T07 Desktop sync (opencloudcmd)")
try:
    import requests
except ImportError:
    rep.skipped("dependencies", "requests missing"); sys.exit(rep.finish())
pw = os.environ.get("OU_PASSWORD_BOB")
if not (os.environ.get("OU_CA_FILE") and pw):
    rep.skipped("config", "need OU_CA_FILE and OU_PASSWORD_BOB"); sys.exit(rep.finish())

M = os.environ.get("OU_MACHINE_DESK", "ou-desk1")
CMD = "/opt/opencloud-desktop/usr/bin/opencloudcmd"
run_id = uuid.uuid4().hex[:8]
rdir = "ou-t07-%s" % run_id            # remote sub folder in the Personal space
ldir = "/root/sync-%s" % run_id         # local sync root inside the desk machine
user = "bob"

def tok():  # OIDC access token (WebDAV checks from the ICS host)
    return L.get_token(requests, user, pw)["access_token"]

M_FILES = os.environ.get("OU_MACHINE_FILES", "ou-files1")
def app_token():
    """opencloudcmd authenticates with Basic user:app-token (OpenCloud auth-app, needs
    OC_ADD_RUN_SERVICES=auth-app + PROXY_ENABLE_APP_AUTH=true). Short-lived; never printed."""
    p = subprocess.run(["sudo", "systemd-run", "-M", M_FILES, "--wait", "-q", "-P", "--pipe",
                        "/usr/local/bin/opencloud", "auth-app", "create", "--user-name", user, "--expiration", "15m"],
                       capture_output=True, text=True, timeout=60)
    for line in p.stdout.splitlines():
        if line.strip().startswith("token:"):
            return line.split("token:", 1)[1].strip()
    raise RuntimeError("auth-app create failed rc=%s" % p.returncode)

def desk(script, token=None, timeout=300):
    args = ["sudo", "systemd-run", "-M", M, "--wait", "-q", "-P", "--pipe",
            "--setenv=LD_LIBRARY_PATH=/opt/opencloud-desktop/usr/lib", "--setenv=QT_QPA_PLATFORM=offscreen"]
    if token:
        args.append("--setenv=OPENCLOUD_TOKEN=" + token)   # never echoed
    p = subprocess.run(args + ["/bin/bash", "-c", script], capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr)

def sync():
    rc, out = desk('%s --non-interactive -u %s --remote-folder /%s https://%s Personal %s'
                   % (CMD, user, rdir, L.HOST_FILES, ldir), token=APP_TOKEN)
    return rc, out

def local_read(name):
    rc, out = desk("cat %s" % shlex.quote("%s/%s" % (ldir, name)))
    return out if rc == 0 else None

dav = L.OcDav(requests, user, tok()); dav.discover()
try:
    APP_TOKEN = app_token()
except Exception as e:  # noqa: BLE001
    rep.failed("app token", str(e)); sys.exit(rep.finish())
r = dav.s.request("MKCOL", dav.url(rdir), timeout=30)
rep.check("remote folder created", r.status_code in (201, 405), "MKCOL %s" % r.status_code, "MKCOL %s" % r.status_code)
desk("mkdir -p %s" % ldir)

# 1 upload
desk("echo 'local-%s' > %s/up.txt" % (run_id, ldir))
rc, out = sync()
rep.check("initial sync exit 0", rc == 0, "rc=0", "rc=%s %s" % (rc, out[-300:]))
g = dav.get("%s/up.txt" % rdir)
rep.check("upload: local file on server", g.status_code == 200 and g.text.strip() == "local-%s" % run_id,
          "content ok", "HTTP %s %r" % (g.status_code, g.text[:60]))

# 2 download
dav.put("%s/down.txt" % rdir, ("remote-%s\n" % run_id).encode())
rc, out = sync()
rep.check("download: server file appears locally", (local_read("down.txt") or "").strip() == "remote-%s" % run_id,
          "content ok", "rc=%s local=%r" % (rc, local_read("down.txt")))

# 3 offline: changes on both sides while no sync runs, then reconnect
desk("echo 'offline-local-%s' > %s/offline-new.txt; echo 'edited-offline' >> %s/up.txt" % (run_id, ldir, ldir))
dav.put("%s/remote-while-offline.txt" % rdir, b"remote-offline\n")
time.sleep(2)
rc, out = sync()
g1 = dav.get("%s/offline-new.txt" % rdir); g2 = dav.get("%s/up.txt" % rdir)
rep.check("offline: new local file uploaded on reconnect", g1.status_code == 200 and "offline-local" in g1.text,
          "ok", "HTTP %s" % g1.status_code)
rep.check("offline: local edit uploaded on reconnect", "edited-offline" in g2.text, "ok", repr(g2.text[:80]))
rep.check("offline: remote change downloaded on reconnect",
          (local_read("remote-while-offline.txt") or "").strip() == "remote-offline", "ok", "missing locally")

# 4 conflict: same file edited on both sides before the next sync
desk("echo 'LOCAL-VERSION' > %s/down.txt" % ldir)
time.sleep(1.5)
dav.put("%s/down.txt" % rdir, b"SERVER-VERSION\n")
rc, out = sync()
rc2, listing = desk("ls -1 %s" % ldir)
conflicts = [l for l in listing.splitlines() if "conflict" in l.lower() and l.startswith("down")]
local_main = (local_read("down.txt") or "").strip()
conflict_content = (local_read(conflicts[0]) or "").strip() if conflicts else ""
rep.check("conflict: conflict copy created locally", bool(conflicts), "files=%s" % conflicts, "listing=%r" % listing[-200:])
rep.check("conflict: both versions preserved",
          {local_main, conflict_content} == {"LOCAL-VERSION", "SERVER-VERSION"},
          "main=%r conflict=%r" % (local_main, conflict_content), "main=%r conflict=%r" % (local_main, conflict_content))
g = dav.get("%s/down.txt" % rdir)
rep.check("conflict: server copy not overwritten by the local edit", rc == 0 and bool(conflicts) and g.text.strip() == "SERVER-VERSION",
          "server keeps SERVER-VERSION", "server=%r" % g.text[:40])

# 5 delete propagation (local delete -> server); only meaningful if the file reached the server first
existed = dav.get("%s/offline-new.txt" % rdir).status_code == 200
desk("rm -f %s/offline-new.txt" % ldir)
rc, out = sync()
g = dav.get("%s/offline-new.txt" % rdir)
rep.check("delete: local delete propagated to server", existed and rc == 0 and g.status_code == 404, "HTTP 404 after it existed", "existed=%s rc=%s HTTP %s" % (existed, rc, g.status_code))

desk("rm -rf %s" % ldir)
dav.s.request("DELETE", dav.url(rdir), timeout=30)
sys.exit(rep.finish())
