"""Shared helpers for the telephony spike tests (run from the ICS host; machine ou-pbx1, lab IdP/LDAP on ou-id1).

Env (defaults = this lab):
  OU_CA_FILE           lab CA pem
  PBX_HOME             HOME with an NSS db trusting the lab CA (headless Chromium)
  PBX_CHROME           chrome-headless-shell binary
  LDAP_ICS_PW_FILE     svc-ics password file (used by ldap-phone.py / lock helpers)
Passwords of lab users are read with sudo systemd-run -M ou-id1 ... grep and never printed.
"""
import json
import os
import subprocess
import sys
import time

SP = "/tmp/claude-1000/-home-administrator/a1d917f8-7438-424e-a57a-793b46deb95e/scratchpad"
CA = os.environ.get("OU_CA_FILE", SP + "/ou-lab-ca.crt")
HOME = os.environ.get("PBX_HOME", SP + "/pbx-ad/home")
CHROME = os.environ.get("PBX_CHROME", os.path.expanduser("~/.cache/ms-playwright/chromium_headless_shell-1255/chrome-headless-shell-linux64/chrome-headless-shell"))
PBX = os.environ.get("PBX_HOST", "pbx.ou-lab.internal")
PBX_IP = os.environ.get("PBX_IP", "192.168.186.247")
PHONE = "https://" + os.environ.get("PHONE_HOST", "phone.ou-lab.internal")
MACHINE = os.environ.get("PBX_MACHINE", "ou-pbx1")   # ou-pbx2 = Asterisk 22 from the signed repo; ou-pbx1 = Ubuntu 20.6 reference
HERE = os.path.dirname(os.path.abspath(__file__))
LDAP_PHONE = os.path.join(HERE, "..", "..", "lab", "spike-pbx", "ldap-phone.py")


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


def sh(machine, script, stdin=None, timeout=120):
    """Run a bash script inside a lab machine."""
    p = subprocess.run(["sudo", "systemd-run", "-M", machine, "--quiet", "--pipe", "--wait", "bash", "-c", script],
                       input=stdin, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def pbx(script, **kw):
    rc, out, err = sh(MACHINE, script, **kw)
    return out


def ast(cmd):
    return pbx("asterisk -rx %s" % json.dumps(cmd))


def password(user):
    rc, out, err = sh("ou-id1", "grep '^OU_PASSWORD_%s=' /root/ou-lab-secrets/test-users.env" % user.upper())
    return out.strip().split("=", 1)[1]


def browser(p, **kw):
    return p.chromium.launch(
        executable_path=CHROME, env={**os.environ, "HOME": HOME},
        args=["--use-fake-device-for-media-stream", "--use-fake-ui-for-media-stream",
              "--disable-features=WebRtcHideLocalIpsWithMdns", "--autoplay-policy=no-user-gesture-required"], **kw)


def kc_login(page, user, pw):
    page.wait_for_selector("input[name=username]", timeout=20000)
    page.fill("input[name=username]", user)
    page.fill("input[name=password]", pw)
    page.click("#kc-login, input[type=submit], button[type=submit]")


def open_phone(browser_, user):
    """New context -> softphone -> Keycloak login -> returns page once the UI exists."""
    ctx = browser_.new_context(ignore_https_errors=False, permissions=["microphone"])
    pg = ctx.new_page()
    pg.goto(PHONE + "/")
    if "auth.ou-lab.internal" in pg.url:
        kc_login(pg, user, password(user))
    pg.wait_for_selector("#status", timeout=30000)
    return ctx, pg


def wait_state(pg, sel, value, timeout=20):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if pg.get_attribute(sel, "data-state") == value:
            return time.time() - t0
        time.sleep(0.2)
    return None


def ldap_phone(*args):
    env = {**os.environ, "LDAP_CA": CA, "LDAP_ICS_PW_FILE": SP + "/pbx-ad/icspw"}
    p = subprocess.run([SP + "/pvenv/bin/python", LDAP_PHONE, *args], env=env, capture_output=True, text=True)
    return p.stdout.strip() or p.stderr.strip()
