"""Shared helpers for the collaboration spike tests (run from the ICS host).

Env (all optional, defaults = this lab):
  OU_CA_FILE            lab CA pem (default $COLLAB_CA or ../../../ou-lab-ca.crt in the scratchpad)
  COLLAB_HOME           HOME with an NSS db that trusts the lab CA, for headless Chromium (certutil -d sql:$HOME/.pki/nssdb)
  PLAYWRIGHT_BROWSERS_PATH
Passwords are read with `sudo systemd-run -M ou-id1 ... grep` from test-users.env and are never printed.
"""
import os
import subprocess
import sys
import time

import requests

CA = os.environ.get("OU_CA_FILE", "/tmp/claude-1000/-home-administrator/a1d917f8-7438-424e-a57a-793b46deb95e/scratchpad/ou-lab-ca.crt")
HOME = os.environ.get("COLLAB_HOME", "/tmp/claude-1000/-home-administrator/a1d917f8-7438-424e-a57a-793b46deb95e/scratchpad/chat-r/home")
os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", os.path.expanduser("~/.cache/ms-playwright"))
CHROME = os.environ.get("COLLAB_CHROME", os.path.expanduser("~/.cache/ms-playwright/chromium_headless_shell-1255/chrome-headless-shell-linux64/chrome-headless-shell"))
HS = "https://matrix.ou-lab.internal"
MAS = "https://mas.ou-lab.internal"
ELEMENT = "https://chat.ou-lab.internal"
KC = "https://auth.ou-lab.internal"
REALM = "ou-lab"
MEET = "https://meet.ou-lab.internal"
MEETAUTH = "https://meet-auth.ou-lab.internal"
S = requests.Session()
S.verify = CA


class Report:
    def __init__(self, title):
        self.title, self.fails, self.passes = title, 0, 0
        print("== " + title)

    def check(self, name, ok, detail=""):
        print("%s %s%s" % ("PASS" if ok else "FAIL", name, (" - " + str(detail)) if detail != "" else ""))
        if ok:
            self.passes += 1
        else:
            self.fails += 1
        sys.stdout.flush()
        return ok

    def finish(self):
        print("== %s: %d PASS / %d FAIL" % (self.title, self.passes, self.fails))
        sys.exit(1 if self.fails else 0)


def idm(*args):
    """Run a command inside ou-id1 (sudo systemd-run -M)."""
    p = subprocess.run(["sudo", "systemd-run", "-M", "ou-id1", "--quiet", "--pipe", "--wait", *args], capture_output=True, text=True, timeout=120)
    if p.returncode:
        raise RuntimeError("ou-id1 %s failed: %s" % (args[0], p.stderr[:200]))
    return p.stdout


def password(user):
    out = idm("/bin/grep", "^OU_PASSWORD_%s=" % user.upper(), "/root/ou-lab-secrets/test-users.env")
    return out.strip().split("=", 1)[1]


def kc_admin_headers():
    pw = idm("/bin/cat", "/root/ou-lab-secrets/keycloak-admin-password").strip()
    r = S.post(KC + "/realms/master/protocol/openid-connect/token", timeout=30,
               data={"grant_type": "password", "client_id": "admin-cli", "username": "kcadmin", "password": pw})
    r.raise_for_status()
    return {"Authorization": "Bearer " + r.json()["access_token"]}


def kc_user_id(H, user):
    return S.get("%s/admin/realms/%s/users" % (KC, REALM), params={"username": user, "exact": "true"}, headers=H, timeout=30).json()[0]["id"]


def browser(p, **kw):
    return p.chromium.launch(executable_path=CHROME, env={**os.environ, "HOME": HOME}, **kw)


def kc_login(page, user, pw):
    """Fill the Keycloak login form (present on the current page)."""
    page.wait_for_selector("input[name=username]", timeout=20000)
    page.fill("input[name=username]", user)
    page.fill("input[name=password]", pw)
    page.click("#kc-login, input[type=submit], button[type=submit]")
