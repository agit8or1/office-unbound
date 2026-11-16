#!/usr/bin/env python3
"""Throw-away SECOND ICS instance for lab runs of new identity code (never the production `ics` service or database).

  init   : (re)create the schema of the dedicated test database ics_test_<suffix>, throw-away vault/audit/signing keys, three accounts
           (lab-op operator, lab-ap1/lab-ap2 approvers) with TOTP; credentials -> $OU_INST_DIR/creds.json (0600)
  serve  : run the app (worker + monitor off except the worker) on 127.0.0.1:$OU_INST_PORT (default 8099) in the foreground

Environment: OU_INST_DIR (default ~/.cache/ou-ics-inst), OU_INST_SUFFIX (default aa; database ics_test_aa must exist, created by a DBA with the roles of
/etc/office-unbound/ics-test.env), OU_INST_PORT.  The DB credentials are taken from the test env file, with the database name swapped.
Run it with the ICS virtualenv from an ics/ checkout:  ics/.venv/bin/python ics/scripts/lab_ics_instance.py init
"""
import json
import os
import re
import secrets
import sys
import time

D = os.environ.get("OU_INST_DIR", os.path.expanduser("~/.cache/ou-ics-inst"))
SUF = os.environ.get("OU_INST_SUFFIX", "aa")
PORT = int(os.environ.get("OU_INST_PORT", "8099"))
ENVF = os.environ.get("ICS_TEST_ENV_FILE", "/etc/office-unbound/ics-test.env")


def urls():
    env = dict(l.strip().split("=", 1) for l in open(ENVF) if "=" in l and not l.startswith("#"))
    sw = lambda u: re.sub(r"/ics_test(_[a-z0-9]{1,12})?$", f"/ics_test_{SUF}", u)
    return sw(env["ICS_TEST_DATABASE_URL"]), sw(env["ICS_TEST_OWNER_DATABASE_URL"])


def setenv():
    app, _ = urls()
    os.makedirs(D, mode=0o700, exist_ok=True)
    for n in ("vault.key", "audit.key", "signing.key"):
        p = os.path.join(D, n)
        if not os.path.exists(p):
            fd = os.open(p, os.O_WRONLY | os.O_CREAT, 0o600)
            os.write(fd, os.urandom(32))
            os.close(fd)
    os.environ.update(ICS_DATABASE_URL=app, ICS_VAULT_KEY_FILE=os.path.join(D, "vault.key"), ICS_AUDIT_KEY_FILE=os.path.join(D, "audit.key"),
                      ICS_SIGNING_KEY_FILE=os.path.join(D, "signing.key"), ICS_COOKIE_SECURE="true", ICS_MONITOR_ENABLED="false", ICS_BACKUP_SCHEDULER_ENABLED=os.environ.get("ICS_BACKUP_SCHEDULER_ENABLED", "true"),
                      ICS_ENV_FILE="/nonexistent")


def init():
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, text
    setenv()
    _, owner = urls()
    eng = create_engine(owner, isolation_level="AUTOCOMMIT")
    with eng.connect() as c:
        c.execute(text("DROP SCHEMA public CASCADE"))
        c.execute(text("CREATE SCHEMA public"))
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    cfg = Config(os.path.join(root, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(root, "migrations"))
    cfg.attributes["url"] = owner
    cfg.attributes["app_role"] = "ics_test_app"
    command.upgrade(cfg, "head")
    from ics import auth
    from ics.runtime import Runtime
    import pyotp
    rt = Runtime()
    creds = {}
    for name, role in (("lab-op", "operator"), ("lab-ap1", "approver"), ("lab-ap2", "approver")):
        pw = secrets.token_urlsafe(18)
        with rt.session() as db:
            tok = auth.create_account_cli(db, rt, name, role)
            uri = auth.enroll_begin(db, rt, name, tok, pw, "127.0.0.1")
            secret = re.search(r"secret=([A-Z2-7]+)", uri).group(1)
            auth.enroll_confirm(db, rt, name, tok, pyotp.TOTP(secret).now(), "127.0.0.1")
        creds[name] = {"password": pw, "secret": secret}
        time.sleep(0.2)
    fd = os.open(os.path.join(D, "creds.json"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(creds, f)
    print("instance database + accounts ready; creds in", os.path.join(D, "creds.json"))


def serve():
    import uvicorn
    setenv()
    print(f"ICS lab instance on http://127.0.0.1:{PORT} (database ics_test_{SUF}); Ctrl-C to stop", flush=True)
    uvicorn.run("ics.main:create_app", factory=True, host="127.0.0.1", port=PORT, server_header=False)


if __name__ == "__main__":
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    {"init": init, "serve": serve}[sys.argv[1]]()
