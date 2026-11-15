#!/usr/bin/env python3
"""Lab driver for the backup product (ADR-0010): drives a THROWAWAY ICS (database ics_test_*, own temp keys under OU_BKPLAB_STATE) through the real
typed-action path: node.enroll -> backup.policy.create -> backup.run / verify / prune -> jobs on the backup lane -> the lab agent -> ou-backup -> restic
-> ou-bkp1 (rest-server). It never touches the production `ics` service or database.

  lab_backup_product.py init            reset the throwaway DB + keys, create accounts
  lab_backup_product.py enroll          enroll the lab runner agent (handshake from lab-agent-setup.sh) with a real 2-approver node.enroll plan
  lab_backup_product.py policies        create the three tier policies (files, identity, groupware) via plans
  lab_backup_product.py provision       per tier: fresh repository on ou-bkp1, vault password -> node (break-glass CLI path), init, offline recovery key
  lab_backup_product.py run [tier..]    backup.run for the tiers (default all)
  lab_backup_product.py verify [check|restore] [tier..]
  lab_backup_product.py prune [tier..]
  lab_backup_product.py checks          create + evaluate the monitoring checks (age, repo_check, restore, growth)
  lab_backup_product.py report          print policies / runs / verifications as the API returns them (JSON)
Needs: sudo -n for ou-backup/ou-bkp1 access, ICS_TEST_ENV_FILE (database), the lab agent running (lab-agent-setup.sh).
"""
import json
import os
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "agent"))
import pyotp  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402

from ics import auth, monitor, worker  # noqa: E402
from ics import actions  # noqa: E402
from ics.backups import ops  # noqa: E402
from ics.config import Settings, _load_env_file  # noqa: E402
from ics.runtime import Runtime  # noqa: E402

STATE = Path(os.environ.get("OU_BKPLAB_STATE", str(Path.home() / ".ou-backup-lab")))
HANDSHAKE = os.environ.get("OU_BKPLAB_HANDSHAKE", "/var/lib/ou-agent-bkplab/handshake.json")
SECRETS = "/etc/office-unbound/backup-lab"
BKP = "ou-bkp1"
TIERS = {"files": dict(rpo=86400, rto=900, sched={"every_hours": 12}), "identity": dict(rpo=86400, rto=900, sched={"every_hours": 12}),
         "groupware": dict(rpo=86400, rto=1800, sched={"every_hours": 12})}


def env() -> dict:
    e = _load_env_file(os.environ.get("ICS_TEST_ENV_FILE", "/etc/office-unbound/ics-test-d.env"))
    assert re.search(r"/ics_test(_[a-z0-9]{1,12})?$", e["ICS_TEST_DATABASE_URL"]), "refusing: not a test database"
    return e


def rt() -> Runtime:
    STATE.mkdir(mode=0o700, exist_ok=True)
    for n in ("vault.key", "audit.key", "signing.key"):
        p = STATE / n
        if not p.exists():
            p.write_bytes(os.urandom(32))
            p.chmod(0o600)
    s = Settings(database_url=env()["ICS_TEST_DATABASE_URL"], vault_key_file=str(STATE / "vault.key"), audit_key_file=str(STATE / "audit.key"),
                 signing_key_file=str(STATE / "signing.key"), worker_enabled=False, allow_loopback_endpoints=False, incident_renotify_seconds=0,
                 check_min_interval_seconds=5, check_min_interval_credentialed_seconds=5, remediation_min_backoff_seconds=0)
    return Runtime(s)


def sh(*argv, inp: str | None = None, check=True) -> str:
    r = subprocess.run(["sudo", "-n", *argv], input=inp, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise SystemExit(f"command failed ({argv[0]} {argv[1] if len(argv) > 1 else ''}): {r.stderr.strip()[-300:] or r.stdout.strip()[-300:]}")
    return r.stdout


def user(r: Runtime, name: str):
    with r.session() as d:
        return auth.User(d.execute(text("SELECT * FROM users WHERE username = :u"), {"u": name}).first())


def plan(r: Runtime, action: str, params: dict, who="bk-op", approvers=("bk-ap1", "bk-ap2")) -> dict:
    with r.session() as d:
        p = actions.create_plan(d, r, user(r, who), actions.ActionType(action), params, None)
        for a in approvers:
            if p["status"] != "approved":
                actions.decide_plan(d, r, user(r, a), uuid.UUID(p["plan_id"]), True, None)
        return p


def drain(r: Runtime, label: str = "") -> list[dict]:
    done = []
    while worker.run_once(r, beat=False) or worker.run_once(r, beat=False, backup_lane=True):
        pass
    with r.session() as d:
        for j in d.execute(text("SELECT j.id, p.action, p.params, j.status, j.result, j.error, extract(epoch from (j.finished_at - j.started_at)) AS secs "
                                "FROM jobs j JOIN plans p ON p.id = j.plan_id ORDER BY j.created_at DESC LIMIT 12")).all():
            done.append(dict(action=j.action, status=j.status, secs=float(j.secs or 0), error=j.error, params={k: v for k, v in j.params.items() if k != "repo"}))
    return done


def cmd_init() -> None:
    e = env()
    for f in ("vault.key", "audit.key", "signing.key"):
        (STATE / f).unlink(missing_ok=True)
    r = rt()
    eng = create_engine(e["ICS_TEST_OWNER_DATABASE_URL"], isolation_level="AUTOCOMMIT")
    with eng.connect() as c:
        c.execute(text("DROP SCHEMA public CASCADE"))
        c.execute(text("CREATE SCHEMA public"))
    cfg = Config(str(HERE.parent / "alembic.ini"))
    cfg.set_main_option("script_location", str(HERE.parent / "migrations"))
    cfg.attributes["url"] = e["ICS_TEST_OWNER_DATABASE_URL"]
    cfg.attributes["app_role"] = re.search(r"//([^:]+):", e["ICS_TEST_DATABASE_URL"]).group(1)
    command.upgrade(cfg, "head")
    r = rt()
    with r.session() as db:
        for name, role in (("bk-op", "operator"), ("bk-ap1", "approver"), ("bk-ap2", "approver")):
            auth.create_invite(db, r, name, role, created_by=None, actor="lab")
            tok = auth.issue_enrollment_token(db, r, name, actor="lab")
            uri = auth.enroll_begin(db, r, name, tok, "lab-throwaway-password-1", "127.0.0.1")
            auth.enroll_confirm(db, r, name, tok, pyotp.TOTP(re.search(r"secret=([A-Z2-7]+)", uri).group(1)).now(), "127.0.0.1")
    print("throwaway ICS database reset; accounts bk-op / bk-ap1 / bk-ap2 created")


def cmd_enroll() -> None:
    r = rt()
    h = json.load(open(HANDSHAKE))
    p = plan(r, "node.enroll", {"name": "bkp-runner", "address": h["address"], "port": h["port"], "tls_fingerprint_sha256": h["tls_fingerprint_sha256"],
                                "agent_key_fingerprint_sha256": h["agent_key_fingerprint_sha256"], "enrollment_token": h["token"]})
    print("node.enroll:", p["risk"], p["status"])
    print(drain(r)[0])
    with r.session() as d:
        n = d.execute(text("SELECT id, name, capabilities FROM nodes")).first()
        print("node", n.name, "capabilities", n.capabilities)


def cmd_policies() -> None:
    r = rt()
    with r.session() as d:
        node = str(d.execute(text("SELECT id FROM nodes WHERE name = 'bkp-runner'")).scalar())
    ca = subprocess.run(["openssl", "x509", "-in", f"{SECRETS}/bkp.crt", "-noout", "-fingerprint", "-sha256"], capture_output=True, text=True) if os.access(f"{SECRETS}/bkp.crt", os.R_OK) \
        else None
    fp = (ca.stdout.split("=")[1].strip().replace(":", "").lower() if ca else sh("openssl", "x509", "-in", f"{SECRETS}/bkp.crt", "-noout", "-fingerprint", "-sha256").split("=")[1].strip().replace(":", "").lower())
    ip = sh("systemd-run", "-M", BKP, "--wait", "-q", "-P", "--pipe", "/bin/bash", "-c", "ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1").strip()
    for tier, t in TIERS.items():
        p = plan(r, "backup.policy.create", {"name": f"lab-{tier}", "tier": tier, "deployment": "lab stack ou-lab.internal", "runner_node_id": node, "schedule": t["sched"],
                                              "retention": {"last": 2, "daily": 7, "weekly": 4, "monthly": 6}, "rpo_seconds": t["rpo"], "rto_seconds": t["rto"],
                                              "repo": {"url": f"https://{ip}:8000/{tier}", "ca_sha256": fp},
                                              "verify": {"check_every_seconds": 3600, "check_read_data_percent": 25, "restore_every_seconds": 86400}},
                 approvers=("bk-ap1",))
        print(tier, p["risk"], p["status"])
    for j in drain(r)[:3]:
        print(j["action"], j["status"], j["error"])


def cmd_provision() -> None:
    r = rt()
    for tier in TIERS:
        sh("systemd-run", "-M", BKP, "--wait", "-q", "-P", "--pipe", "/bin/bash", "-c", f"rm -rf /srv/restic/{tier}")   # a fresh repository per drill
        with r.session() as d:
            secret = ops.node_secret(r, d, f"lab-{tier}")          # break-glass: audited, value never printed
        sh("/usr/local/sbin/ou-backup", "--direct", "provision", tier, inp=json.dumps(secret))
        out = json.loads(sh("/usr/local/sbin/ou-backup", "--direct", "init", tier))
        rk = f"/var/lib/ou-backup/recovery-{tier}.txt"
        rec = json.loads(sh("/usr/local/sbin/ou-backup", "--direct", "recovery-key", tier, rk))
        sh("shred", "-u", rk)       # the owner would take the file offline first (docs/admin/backup-and-restore.md); the drill only needs the fingerprint
        with r.session() as d:
            ops.recovery_ack(d, f"lab-{tier}", rec["recovery_fp"])
        print(tier, "repo", out["repo_id"][:12], "recovery key fingerprint", rec["recovery_fp"])


def tiers_arg(a: list[str]) -> list[str]:
    return a or list(TIERS)


def cmd_run(a: list[str]) -> None:
    r = rt()
    for t in tiers_arg(a):
        t0 = time.time()
        p = plan(r, "backup.run", {"policy": f"lab-{t}"})
        j = drain(r)[0]
        print(t, j["status"], f"job {j['secs']:.1f}s wall {time.time() - t0:.1f}s", j["error"] or "")


def cmd_verify(a: list[str]) -> None:
    r = rt()
    level = a[0] if a and a[0] in ("check", "restore") else "check"
    for t in tiers_arg(a[1:] if a and a[0] in ("check", "restore") else a):
        plan(r, "backup.verify", {"policy": f"lab-{t}", "level": level})
        j = drain(r)[0]
        print(t, level, j["status"], f"job {j['secs']:.1f}s", j["error"] or "")


def cmd_prune(a: list[str]) -> None:
    r = rt()
    for t in tiers_arg(a):
        plan(r, "backup.prune", {"policy": f"lab-{t}"})
        j = drain(r)[0]
        print(t, "prune", j["status"], f"job {j['secs']:.1f}s", j["error"] or "")


def cmd_checks() -> None:
    r = rt()
    for t in TIERS:
        for aspect in ("age", "repo_check", "restore", "growth"):
            cfg = {"policy": f"lab-{t}", "aspect": aspect, **({"max_repo_bytes": 5 * 10**9} if aspect == "growth" else {})}
            plan(r, "check.create", {"name": f"bk-{t}-{aspect}", "kind": "backup", "config": cfg, "interval_seconds": 60})
    drain(r)
    with r.session() as d:
        ids = d.execute(text("SELECT id, name FROM checks ORDER BY name")).all()
    for c in ids:
        state, o = monitor.run_and_record(r, c.id)
        print(f"{c.name:28s} {state:9s} {o.message}")


def cmd_report() -> None:
    r = rt()
    with r.session() as d:
        print(json.dumps({"policies": ops.list_policies(d), "runs": ops.list_runs(d, limit=100), "verifications": ops.list_verifications(d, limit=100)}, indent=1, default=str))


if __name__ == "__main__":
    c, a = (sys.argv[1] if len(sys.argv) > 1 else "help"), sys.argv[2:]
    fn = {"init": cmd_init, "enroll": cmd_enroll, "policies": cmd_policies, "provision": cmd_provision, "checks": cmd_checks, "report": cmd_report}.get(c)
    if fn:
        fn()
    elif c in ("run", "verify", "prune"):
        {"run": cmd_run, "verify": cmd_verify, "prune": cmd_prune}[c](a)
    else:
        print(__doc__)
