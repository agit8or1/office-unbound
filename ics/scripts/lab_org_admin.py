#!/usr/bin/env python3
"""Lab harness for the Organization Admin e2e (agent AX). Everything runs on THIS host; the production ICS service/DB are never touched.

  ics-up    create a throwaway database (default ics_test_axe), migrate it, start a dev ICS on 127.0.0.1:8124 (pid in the state dir)
  seed      operator accounts, the lab identity stack (LDAP + Keycloak real, NO agent nodes: enrolling nodes into a second ICS would
            reset the production ICS's agent trust), a customer, the tenant-admin binding, two org-admin users (role org-admin in Keycloak)
  portal-up self-signed https portal on 127.0.0.1:8447 using a throwaway Keycloak client (ou-portal-ax) and the binding's service key
  cleanup   disable/delete the ax* test users, revoke org-admin from the test admins
  down      stop what this script started (by recorded pid, never by pattern)

State (credentials of throwaway lab users, service key, pids) lives in $AX_DIR (0700) and is never printed.
Usage: lab_org_admin.py <cmd>     env: AX_DIR, AX_DB (ics_test_axe), AX_PORTAL_PY (python with the portal's deps), AX_PORTAL_SRC (portal dir)
"""
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import time

import httpx
import pyotp

HERE = os.path.dirname(os.path.abspath(__file__))
ICS_DIR = os.path.dirname(HERE)
sys.path.insert(0, ICS_DIR)
AX = os.environ.get("AX_DIR", os.path.expanduser("~/.cache/ou-org-admin-lab"))
DB = os.environ.get("AX_DB", "ics_test_axe")
PORT_ICS, PORT_PORTAL = 8124, 8447
STATE = os.path.join(AX, "state.json")
BASE = f"http://127.0.0.1:{PORT_ICS}/api/v1"
STACK, DOMAIN = "ax-lab", "ou-lab.internal"
TEST_ENV = "/etc/office-unbound/ics-test.env"


def log(m):
    print(time.strftime("%H:%M:%S"), m, flush=True)


def load():
    return json.load(open(STATE)) if os.path.exists(STATE) else {}


def save(s):
    os.makedirs(AX, mode=0o700, exist_ok=True)
    fd = os.open(STATE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, json.dumps(s, indent=1).encode())
    os.close(fd)


def sh(machine, cmd, timeout=120, stdin=None):
    p = subprocess.run(["sudo", "-n", "systemd-run", "-M", machine, "--quiet", "--pipe", "--wait", "/bin/bash", "-c", cmd], capture_output=True, text=True, timeout=timeout, input=stdin)
    return p.returncode, p.stdout + p.stderr


def secret_file(machine, path):
    rc, out = sh(machine, f"cat {path}")
    if rc != 0:
        raise SystemExit(f"cannot read {path} in {machine}")
    return out.strip()


def urls():
    env = dict(l.split("=", 1) for l in open(TEST_ENV).read().splitlines() if "=" in l and not l.startswith("#"))
    sub = lambda u: re.sub(r"/ics_test$", f"/{DB}", u)  # noqa: E731
    return sub(env["ICS_TEST_DATABASE_URL"]), sub(env["ICS_TEST_OWNER_DATABASE_URL"])


def dev_env():
    app, _ = urls()
    return {"ICS_DATABASE_URL": app, "ICS_VAULT_KEY_FILE": f"{AX}/vault.key", "ICS_AUDIT_KEY_FILE": f"{AX}/audit.key", "ICS_COOKIE_SECURE": "false",
            "ICS_MONITOR_ENABLED": "false", "ICS_ENV_FILE": f"{AX}/none.env", "ICS_ALLOW_LOOPBACK_ENDPOINTS": "false"}


def ics_up():
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, text
    os.makedirs(AX, mode=0o700, exist_ok=True)
    s = load()
    if s.get("ics_pid"):
        try:
            os.kill(s["ics_pid"], 0)
            log("dev ICS already running")
            return
        except OSError:
            pass
    rc = subprocess.run(["sudo", "-n", "-u", "postgres", "psql", "-Atc", f"select 1 from pg_database where datname='{DB}'"], capture_output=True, text=True).stdout.strip()
    if rc != "1":
        subprocess.run(["sudo", "-n", "-u", "postgres", "psql", "-c", f"create database {DB} owner ics_test_owner"], check=True, capture_output=True)
    act = subprocess.run(["sudo", "-n", "-u", "postgres", "psql", "-Atc", f"select count(*) from pg_stat_activity where datname='{DB}'"], capture_output=True, text=True).stdout.strip()
    log(f"database {DB}: {act} existing connection(s)")
    for n in ("vault.key", "audit.key"):
        p = f"{AX}/{n}"
        if not os.path.exists(p):
            fd = os.open(p, os.O_WRONLY | os.O_CREAT, 0o600)
            os.write(fd, os.urandom(32))
            os.close(fd)
    app_url, owner_url = urls()
    eng = create_engine(owner_url, isolation_level="AUTOCOMMIT")
    with eng.connect() as c:
        c.execute(text("DROP SCHEMA public CASCADE"))
        c.execute(text("CREATE SCHEMA public"))
    cfg = Config(os.path.join(ICS_DIR, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(ICS_DIR, "migrations"))
    cfg.attributes["url"], cfg.attributes["app_role"] = owner_url, "ics_test_app"
    command.upgrade(cfg, "head")
    env = {**os.environ, **dev_env()}
    out = open(f"{AX}/ics.log", "ab")
    p = subprocess.Popen([sys.executable, "-m", "uvicorn", "ics.main:create_app", "--factory", "--host", "127.0.0.1", "--port", str(PORT_ICS), "--log-level", "warning"],
                         cwd=ICS_DIR, env=env, stdout=out, stderr=out, start_new_session=True)
    s.update(ics_pid=p.pid)
    save(s)
    for _ in range(60):
        try:
            if httpx.get(f"http://127.0.0.1:{PORT_ICS}/readyz", timeout=2).status_code in (200, 503):
                break
        except httpx.HTTPError:
            time.sleep(0.5)
    log(f"dev ICS up on 127.0.0.1:{PORT_ICS} pid {p.pid}")


class Api:
    def __init__(self, name, pw, secret):
        self.c = httpx.Client(base_url=BASE, timeout=120)
        for step in (0, 1, -1, 2):
            r = self.c.post("/auth/login", json={"username": name, "password": pw, "totp_code": pyotp.TOTP(secret).at(time.time() + 30 * step)})
            if r.status_code == 200:
                break
            time.sleep(1)
        r.raise_for_status()
        self.h = {"X-CSRF-Token": r.json()["csrf_token"]}

    def get(self, p, **kw):
        r = self.c.get(p, headers=self.h, **kw)
        r.raise_for_status()
        return r.json()

    def post(self, p, body=None):
        r = self.c.post(p, headers=self.h, json=body or {})
        if r.status_code >= 400:
            raise SystemExit(f"{p}: {r.status_code} {r.text[:300]}")
        return r.json()


def runtime():
    from ics.config import Settings
    from ics.runtime import Runtime
    e = dev_env()
    return Runtime(Settings(database_url=e["ICS_DATABASE_URL"], vault_key_file=e["ICS_VAULT_KEY_FILE"], audit_key_file=e["ICS_AUDIT_KEY_FILE"], worker_enabled=False,
                            cookie_secure=False, monitor_enabled=False))


def mk_operator(rt, name, role):
    from sqlalchemy import text
    from ics import auth
    pw = secrets.token_urlsafe(18)
    with rt.session() as db:
        if db.execute(text("SELECT 1 FROM users WHERE username = :u"), {"u": name}).first():
            return None
        auth.create_invite(db, rt, name, role, actor="lab")
        tok = auth.issue_enrollment_token(db, rt, name, actor="lab")
        uri = auth.enroll_begin(db, rt, name, tok, pw, "127.0.0.1")
        sec = re.search(r"secret=([A-Z2-7]+)", uri).group(1)
        auth.enroll_confirm(db, rt, name, tok, pyotp.TOTP(sec).at(time.time()), "127.0.0.1")
    return {"password": pw, "secret": sec}


def run_plan(op, aps, action, params):
    r = op.post("/plans", {"action": action, "params": params})
    job = r["job_id"]
    if r["status"] == "pending_approval":
        for ap in aps[:r["approvals_required"]]:
            job = ap.post(f"/plans/{r['plan_id']}/approve").get("job_id") or job
    for _ in range(600):
        j = op.get(f"/jobs/{job}")
        if j["status"] in ("succeeded", "failed"):
            break
        time.sleep(0.5)
    log(f"plan {action:26s} risk={r['risk']:6s} -> {j['status']}" + ("" if j["status"] == "succeeded" else " :: " + json.dumps(j["error"])[:300]))
    if j["status"] != "succeeded":
        raise SystemExit(1)
    return r["plan_id"], j


def lab_login(uid, pw):
    """Direct-grant login with the lab test client: materialises the Keycloak shadow user and proves the credentials work."""
    ca = secret_file("ou-id1", "/etc/ou-lab/tls/ca.crt")
    import ssl
    ctx = ssl.create_default_context(cadata=ca)
    r = httpx.post("https://auth.ou-lab.internal/realms/ou-lab/protocol/openid-connect/token", verify=ctx,
                   data={"grant_type": "password", "client_id": "ou-lab-test", "username": uid, "password": pw, "scope": "openid"})
    return r.status_code == 200


def seed():
    from sqlalchemy import text
    rt = runtime()
    s = load()
    ops = s.setdefault("ops", {})
    for n, role in (("ax-admin", "admin"), ("ax-op", "operator"), ("ax-ap1", "approver"), ("ax-ap2", "approver")):
        c = mk_operator(rt, n, role)
        if c:
            ops[n] = c
    save(s)
    adm, op, a1, a2 = (Api(n, ops[n]["password"], ops[n]["secret"]) for n in ("ax-admin", "ax-op", "ax-ap1", "ax-ap2"))
    if not any(x["name"] == STACK for x in op.get("/identity/stacks")):
        base = "dc=ou-lab,dc=internal"
        run_plan(op, [a1, a2], "idm.stack.register", {
            "name": STACK, "ldap_url": "ldaps://ldap.ou-lab.internal", "ldap_bind_dn": f"cn=svc-ics,ou=system,{base}",
            "ldap_bind_password": secret_file("ou-id1", "/root/ou-lab-secrets/ldap-ics-password"),
            "ldap_people_dn": f"ou=people,{base}", "ldap_groups_dn": f"ou=groups,{base}", "mail_domain": DOMAIN, "entitlement_group": "mail-users",
            "allowed_groups": ["mail-users", "opencloudUser", "opencloudGuest", "opencloudSpaceAdmin", "opencloudAdmin"], "privileged_groups": ["opencloudAdmin"],
            "kc_url": "https://auth.ou-lab.internal", "kc_realm": "ou-lab", "kc_client_id": "ou-ics",
            "kc_client_secret": secret_file("ou-id1", "/root/ou-lab-secrets/kc-ics-client-secret"),
            "kc_offline_clients": ["web", "OpenCloudDesktop", "OpenCloudAndroid", "OpenCloudIOS", "ou-lab-test"],
            "identity_ca_pem": secret_file("ou-id1", "/etc/ou-lab/tls/ca.crt"), "files_url": "https://cloud.ou-lab.internal",
            "mail_host": "gw1.ou-lab.internal", "mail_ca_pem": open("/etc/office-unbound/lab/gw1-ca.crt").read(),
            "probe_client_id": "ou-lab-test", "reconcile_interval_seconds": 0})
    with rt.session() as db:
        cid = db.execute(text("SELECT id FROM customers WHERE name = 'Lab Organisation'")).scalar()
        if not cid:
            cid = db.execute(text("INSERT INTO customers (name, msp_owned, provisioning_mode) VALUES ('Lab Organisation', true, 'auto') RETURNING id")).scalar()
            db.commit()
    s["customer_id"] = str(cid)
    if not s.get("service_key"):
        r = adm.post(f"/customers/{cid}/tenant-admin", {"stack": STACK, "portal_client_id": "ou-portal-ax", "dkim_selector": "default",
                                                        "app_groups": {"mail": "mail-users", "files": "opencloudUser"}})
        s["service_key"] = r["service_key"]
        log("tenant-admin binding created (service key stored in the state dir)")
    save(s)
    users = s.setdefault("admins", {})
    for uid in ("axadmin1", "axadmin2"):
        if uid in users:
            continue
        pid, j = run_plan(op, [a1, a2], "idm.user.create", {"stack": STACK, "uid": uid, "display_name": f"AX Admin {uid[-1]}", "mail": f"{uid}@{DOMAIN}", "groups": ["mail-users", "opencloudUser"]})
        tok = op.post(f"/identity/enrollments/{pid}/reveal")["token"]
        pw = secrets.token_urlsafe(18) + "aA1"
        r = httpx.post(f"{BASE}/identity/enroll", json={"stack": STACK, "uid": uid, "token": tok, "password": pw})
        r.raise_for_status()
        users[uid] = {"password": pw}
        for _ in range(10):
            if lab_login(uid, pw):
                break
            time.sleep(2)
        save(s)
    rc, out = subprocess.run(["bash", os.environ["AX_KC_SETUP"], "role"], env={**os.environ, "ORG_ADMIN_USERS": ",".join(users)}, capture_output=True, text=True).returncode, ""
    log(f"org-admin role grant exit {rc}")
    save(s)
    log("seed done")


def portal_up():
    s = load()
    py = os.environ["AX_PORTAL_PY"]
    src = os.environ["AX_PORTAL_SRC"]
    cert, key = f"{AX}/portal.crt", f"{AX}/portal.key"
    if not os.path.exists(cert):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", key, "-out", cert, "-days", "7", "-subj", "/CN=127.0.0.1",
                        "-addext", "subjectAltName=IP:127.0.0.1"], check=True, capture_output=True)
    ca = secret_file("ou-id1", "/etc/ou-lab/tls/ca.crt") + "\n" + open("/etc/office-unbound/lab/gw1-ca.crt").read()
    for n, v in (("ca.pem", ca), ("client-secret", secret_file("ou-id1", "/root/ou-lab-secrets/kc-portal-ax-secret")), ("ics-key", s["service_key"])):
        fd = os.open(f"{AX}/{n}", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fd, v.encode())
        os.close(fd)
    env = {**os.environ, "PORTAL_BASE_URL": f"https://127.0.0.1:{PORT_PORTAL}", "PORTAL_OIDC_ISSUER": "https://auth.ou-lab.internal/realms/ou-lab",
           "PORTAL_OIDC_CLIENT_ID": "ou-portal-ax", "PORTAL_OIDC_CLIENT_SECRET_FILE": f"{AX}/client-secret", "PORTAL_FILES_URL": "https://cloud.ou-lab.internal",
           "PORTAL_MAIL_WEB_URL": "https://gw1.ou-lab.internal/web/", "PORTAL_MAIL_HOST": "gw1.ou-lab.internal", "PORTAL_MAIL_DOMAIN": DOMAIN,
           "PORTAL_ORG_NAME": "Lab Organisation", "PORTAL_CA_BUNDLE": f"{AX}/ca.pem", "PORTAL_ICS_URL": f"http://127.0.0.1:{PORT_ICS}", "PORTAL_ICS_KEY_FILE": f"{AX}/ics-key"}
    out = open(f"{AX}/portal.log", "ab")
    p = subprocess.Popen([py, "-m", "uvicorn", "app.main:create_app", "--factory", "--host", "127.0.0.1", "--port", str(PORT_PORTAL), "--ssl-keyfile", key, "--ssl-certfile", cert,
                          "--log-level", "warning"], cwd=src, env=env, stdout=out, stderr=out, start_new_session=True)
    s["portal_pid"] = p.pid
    save(s)
    time.sleep(2)
    log(f"portal up on https://127.0.0.1:{PORT_PORTAL} pid {p.pid}")


def cleanup():
    """Disable + delete every ax* user the harness or the e2e left behind, and take org-admin away from the test admins."""
    s = load()
    ops = s["ops"]
    op, a1, a2 = (Api(n, ops[n]["password"], ops[n]["secret"]) for n in ("ax-op", "ax-ap1", "ax-ap2"))
    users = [u for u in op.get("/identity/users", params={"stack": STACK}) if u["state"] != "deleted"]
    for u in users:
        if u["state"] == "active":
            run_plan(op, [a1, a2], "idm.user.disable", {"stack": STACK, "uid": u["uid"], "reason": "lab cleanup"})
        run_plan(op, [a1, a2], "idm.user.delete", {"stack": STACK, "uid": u["uid"], "reason": "lab cleanup"})
    rc = subprocess.run(["bash", os.environ["AX_KC_SETUP"], "role"], env={**os.environ, "ORG_ADMIN_REVOKE": ",".join(s.get("admins", {}))}, capture_output=True).returncode
    log(f"cleanup done, role revoke exit {rc}")


def down():
    s = load()
    for k in ("portal_pid", "ics_pid"):
        if s.get(k):
            try:
                os.killpg(s[k], signal.SIGTERM)
                log(f"stopped {k} {s[k]}")
            except OSError:
                pass
            s.pop(k)
    save(s)


if __name__ == "__main__":
    {"ics-up": ics_up, "seed": seed, "portal-up": portal_up, "cleanup": cleanup, "down": down}[sys.argv[1]]()
