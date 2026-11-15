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
    """Restart a systemd unit on a lab VM via ssh. Returns (ok, detail). SKIP-able."""
    target = os.environ.get("OU_SSH_" + role.upper())
    if not target:
        return None, "OU_SSH_%s not set" % role.upper()
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", target, "sudo", "systemctl", "restart", unit]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    if p.returncode != 0:
        return False, "ssh restart %s on %s failed: %s" % (unit, target, p.stderr.strip()[:200])
    return True, "restarted %s on %s" % (unit, target)


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
