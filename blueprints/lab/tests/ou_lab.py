"""Shared helpers for the Office Unbound lab acceptance tests.

STATUS: PREPARED, NOT EXECUTED against a real lab. Endpoint paths and response
shapes marked UNVERIFIED in individual tests come from upstream docs/source,
not from observation. A failing test may be a wrong assumption here, not a
product defect: read the detail text, then check the product.

Configuration is by environment variables only (no secrets in files):
  OU_LAB_DOMAIN        default ou-lab.internal
  OU_CA_FILE           path to the lab CA certificate (public), REQUIRED for TLS
  OU_REALM             default ou-lab
  OU_PASSWORD_<USER>   ALICE BOB CAROL DAVE ERIN (from kc:/root/ou-lab-secrets/test-users.env)
  OU_SSH_<ROLE>        optional ssh target (user@host) for FILES / OFFICE / MAIL,
                       used only to restart services; sudo must be passwordless
  OU_STRICT_SKIP=1     make SKIP count as failure (exit 77) - use for sign-off runs
Hostnames must resolve on the machine running the tests (/etc/hosts entries).
"""
import base64
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
import uuid

LAB_DOMAIN = os.environ.get("OU_LAB_DOMAIN", "ou-lab.internal")
REALM = os.environ.get("OU_REALM", "ou-lab")
HOST_KC = os.environ.get("OU_HOST_KC", "auth." + LAB_DOMAIN)
HOST_FILES = os.environ.get("OU_HOST_FILES", "cloud." + LAB_DOMAIN)
HOST_OFFICE = os.environ.get("OU_HOST_OFFICE", "office." + LAB_DOMAIN)
# OpenCloud's name of the office app (COLLABORATION_APP_NAME): "Documents" on ICS deployments (ics/ics/deploy/brand.py EDITOR_APP);
# the older lab spikes registered CollaboraOnline (set OU_EDITOR_APP=CollaboraOnline for them)
EDITOR_APP = os.environ.get("OU_EDITOR_APP", "Documents")
HOST_MAIL = os.environ.get("OU_HOST_MAIL", "mail." + LAB_DOMAIN)
HOST_AUTODISCOVER = os.environ.get("OU_HOST_AUTODISCOVER", "autodiscover." + LAB_DOMAIN)
MAIL_DOMAIN = os.environ.get("OU_MAIL_DOMAIN", LAB_DOMAIN)
CA_FILE = os.environ.get("OU_CA_FILE")
RUN_ID = uuid.uuid4().hex[:10]


class Report:
    """Collects PASS/FAIL/SKIP lines; exit code 1 on any FAIL."""

    def __init__(self, title):
        self.title = title
        self.counts = {"PASS": 0, "FAIL": 0, "SKIP": 0}
        print("== %s (run %s) ==" % (title, RUN_ID))

    def _emit(self, status, name, detail):
        self.counts[status] += 1
        print("%s %s - %s" % (status, name, detail))
        sys.stdout.flush()

    def passed(self, name, detail=""):
        self._emit("PASS", name, detail or "ok")

    def failed(self, name, detail):
        self._emit("FAIL", name, detail)

    def skipped(self, name, detail):
        self._emit("SKIP", name, detail)

    def check(self, name, ok, ok_detail, fail_detail):
        (self.passed if ok else self.failed)(name, ok_detail if ok else fail_detail)
        return bool(ok)

    def finish(self):
        c = self.counts
        print("-- %s: %d PASS, %d FAIL, %d SKIP" % (self.title, c["PASS"], c["FAIL"], c["SKIP"]))
        if c["FAIL"]:
            sys.exit(1)
        if c["SKIP"] and os.environ.get("OU_STRICT_SKIP") == "1":
            print("-- OU_STRICT_SKIP=1: SKIP treated as failure")
            sys.exit(77)
        sys.exit(0)


def need_requests(rep):
    try:
        import requests  # noqa: F401
        return True
    except ImportError:
        rep.skipped("dependencies", "python 'requests' not installed (pip install -r requirements.txt)")
        return False


def verify():
    """TLS verification target for requests: the lab CA, never False."""
    if not CA_FILE:
        raise RuntimeError("OU_CA_FILE not set (path to lab ca.crt); refusing to disable TLS verification")
    return CA_FILE


def resolves(host):
    try:
        socket.getaddrinfo(host, None)
        return True
    except OSError:
        return False


def password_for(user):
    return os.environ.get("OU_PASSWORD_" + user.upper())


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def jwt_claims(token):
    """Decode a JWT payload WITHOUT verifying the signature (diagnostics only)."""
    part = token.split(".")[1]
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))


def oidc_base():
    return "https://%s/realms/%s" % (HOST_KC, REALM)


def get_token(requests, user, password, client_id="ou-lab-test", scope="openid profile email"):
    """Resource-owner password grant against the lab realm (TEST CLIENT ONLY)."""
    r = requests.post(oidc_base() + "/protocol/openid-connect/token", verify=verify(), timeout=30, data={
        "grant_type": "password", "client_id": client_id, "username": user,
        "password": password, "scope": scope})
    if r.status_code != 200:
        raise RuntimeError("token request for %s failed: HTTP %s %s" % (user, r.status_code, r.text[:200]))
    return r.json()


def ssh_restart(role, unit):
    """Restart a systemd unit on a lab machine. Returns (ok, detail); ok is None when not configured (SKIP).

    Two ways (lab run used the second, from the ICS host against nspawn machines):
      OU_SSH_<ROLE>=user@host                      -> ssh user@host sudo systemctl restart <unit>
      OU_RESTART_CMD='sudo systemctl -M {machine} restart {unit}' + OU_MACHINE_<ROLE>=ou-files1
    """
    tmpl = os.environ.get("OU_RESTART_CMD")
    machine = os.environ.get("OU_MACHINE_" + role.upper())
    if tmpl and machine:
        cmd = tmpl.format(machine=machine, unit=unit).split()
        what = machine
    else:
        target = os.environ.get("OU_SSH_" + role.upper())
        if not target:
            return None, "neither OU_SSH_%s nor OU_RESTART_CMD+OU_MACHINE_%s set" % (role.upper(), role.upper())
        cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", target, "sudo", "systemctl", "restart", unit]
        what = target
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
    if p.returncode != 0:
        return False, "restart %s on %s failed: %s" % (unit, what, p.stderr.strip()[:200])
    return True, "restarted %s on %s" % (unit, what)


def wait_http(requests, url, timeout=120, **kw):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            r = requests.get(url, verify=verify(), timeout=10, **kw)
            if r.status_code < 500:
                return r
            last = "HTTP %s" % r.status_code
        except Exception as e:  # noqa: BLE001 - diagnostics
            last = str(e)[:120]
        time.sleep(3)
    raise RuntimeError("timeout waiting for %s (%s)" % (url, last))


def wait_app_ready(requests, app_name=EDITOR_APP, timeout=120):
    """KI-1: OpenCloud answers OIDC discovery ~5 s before the collaboration app is
    re-registered after a restart; /app/list is the accurate readiness signal."""
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            r = requests.get("https://%s/app/list" % HOST_FILES, verify=verify(), timeout=10)
            if r.status_code == 200 and app_name in r.text:
                return r
            last = "HTTP %s, %s listed=%s" % (r.status_code, app_name, app_name in r.text)
        except Exception as e:  # noqa: BLE001 - diagnostics
            last = str(e)[:120]
        time.sleep(1)
    raise RuntimeError("timeout waiting for app %s in /app/list (%s)" % (app_name, last))


# ---- WebDAV (OpenCloud) -------------------------------------------------
class OcDav:
    """Minimal WebDAV client with Bearer auth. Base path discovered at runtime."""
    CANDIDATES = ["/remote.php/dav/files/{user}", "/dav/files/{user}", "/remote.php/webdav"]

    def __init__(self, requests, user, token):
        self.rq = requests
        self.user = user
        self.s = requests.Session()
        self.s.headers["Authorization"] = "Bearer " + token
        self.s.verify = verify()
        self.base = None

    def url(self, path=""):
        return "https://%s%s/%s" % (HOST_FILES, self.base, path.lstrip("/"))

    def discover(self):
        for c in self.CANDIDATES:
            self.base = c.format(user=self.user)
            r = self.s.request("PROPFIND", self.url(""), headers={"Depth": "0"}, timeout=30)
            if r.status_code == 207:
                return self.base
        self.base = None
        return None

    def mkcol(self, path):
        return self.s.request("MKCOL", self.url(path), timeout=30)

    def put(self, path, data):
        return self.s.put(self.url(path), data=data, timeout=120)

    def get(self, path):
        return self.s.get(self.url(path), timeout=120)

    def delete(self, path):
        return self.s.delete(self.url(path), timeout=30)

    def propfind(self, path, body=None, depth="1"):
        return self.s.request("PROPFIND", self.url(path), data=body, timeout=30,
                              headers={"Depth": depth, "Content-Type": "application/xml"})

    def fileid(self, path):
        body = ('<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">'
                "<d:prop><oc:fileid/></d:prop></d:propfind>")
        r = self.propfind(path, body, "0")
        if r.status_code != 207:
            return None
        import xml.etree.ElementTree as ET
        for el in ET.fromstring(r.content).iter("{http://owncloud.org/ns}fileid"):
            return el.text
        return None


# ---- Collabora headless session (VERIFIED in the lab against coolwsd 26.04.6.1 + OpenCloud 9.1.0) ------------
class CollaboraSession:
    """Drives the same protocol the browser iframe uses: POST /app/open -> wss /cool/<docurl>/ws -> load -> edit -> save.

    Needs `websocket-client`. The Origin must be the Collabora host (the iframe origin); with the OpenCloud host as
    Origin coolwsd answers 403. Collabora itself calls CheckFileInfo/GetFile/PutFile on OpenCloud (with WOPI proof
    headers), so a successful load/save proves Collabora -> OpenCloud reachability, TLS trust and the WOPI allow-list.
    """

    def __init__(self, requests, websocket, token, file_id):
        import urllib.parse as up
        self.websocket, self.up = websocket, up
        r = requests.post("https://%s/app/open?file_id=%s&app_name=%s" % (HOST_FILES, up.quote(file_id, safe=""), EDITOR_APP),
                          headers={"Authorization": "Bearer " + token}, verify=verify(), timeout=60)
        self.open_status, self.open_text = r.status_code, r.text
        self.ok_open = r.status_code == 200 and "app_url" in r.text
        if self.ok_open:
            j = r.json()
            self.wopi_token = j["form_parameters"]["access_token"]
            self.wopi_src = up.parse_qs(up.urlparse(j["app_url"]).query)["WOPISrc"][0]
        self.ws = None
        self.messages = []

    def connect_and_load(self, timeout=40):
        up = self.up
        docurl = self.wopi_src + "?access_token=" + self.wopi_token
        self.ws = self.websocket.create_connection(
            "wss://%s/cool/%s/ws" % (HOST_OFFICE, up.quote(docurl, safe="")),
            sslopt={"ca_certs": CA_FILE}, origin="https://" + HOST_OFFICE, timeout=20)
        self.ws.send("coolclient 0.1")
        self.ws.send("load url=%s lang=en-US" % up.quote(docurl, safe=""))
        return self._until(lambda m: m.startswith("status:"), timeout)

    def _until(self, pred, timeout):
        end = time.time() + timeout
        while time.time() < end:
            try:
                m = self.ws.recv()
            except Exception as e:  # noqa: BLE001
                self.messages.append("ERR %s" % e)
                return False
            if isinstance(m, bytes):
                continue
            if m.startswith(("invalidatetiles", "tile", "cellcursor", "textselection", "statechanged", "progress")):
                continue
            self.messages.append(m[:200])
            if pred(m):
                return True
        return False

    def insert_text_and_save(self, text, timeout=40):
        self.ws.send("textinput id=0 text=%s" % text)
        time.sleep(1)
        self.ws.send("save dontTerminateEdit=1 dontSaveIfUnmodified=0")
        return self._until(lambda m: m.startswith("unocommandresult") and ".uno:Save" in m and '"success":true' in m, timeout)

    def save(self, timeout=40):
        self.ws.send("save dontTerminateEdit=1 dontSaveIfUnmodified=0")
        return self._until(lambda m: m.startswith("unocommandresult") and ".uno:Save" in m and '"success":true' in m, timeout)

    def close(self):
        try:
            if self.ws:
                self.ws.close()
        except Exception:  # noqa: BLE001
            pass
