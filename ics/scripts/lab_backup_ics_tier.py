#!/usr/bin/env python3
"""Lab drill: the ICS CONTROLLER tier of the backup product against a DEV ICS (database ics_test_<suffix>, throw-away keys; never the production
`ics` service or database). ADR-0010 tier "ics":

  policy ics-dev  ->  backup.run (pg_dump + roles + keys + env + units + release -> ENCRYPTED restic repository on ou-bkp1)
                  ->  offline recovery key (second restic key) proven to open the repository without the vault
                  ->  backup.verify check (100 % of the data read)
                  ->  backup.verify restore: passive-restore flow of docs/runbooks/ics-recovery.md into the scratch machine (default ou-ics-r1):
                      checksums, packages, ics-migrate, PASSIVE start, audit chain verifies and contains the backup-time head event,
                      alembic head, operator login (password + TOTP + vault key + audit key), controller reports not-ready (passive)
  negative: a wrong login canary makes the verification FAIL (a restore that cannot log in is never "verified");
            the repository holds no cleartext of the controller's secrets/DB credentials (control: the manifest decrypts).

Usage:  ICS_TEST_ENV_FILE=/etc/office-unbound/ics-test-aa.env ics/.venv/bin/python ics/scripts/lab_backup_ics_tier.py [--neg]
Needs sudo -n (lab host), the lab machines ou-bkp1 (backup target, started if stopped) and ou-ics-r1 (scratch image of an earlier ICS restore).
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
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "agent"))
SUF = os.environ.get("OU_INST_SUFFIX", "aa")
D = os.environ.get("OU_INST_DIR", str(Path.home() / ".cache" / "ou-ics-bk-dev"))
os.environ.update(OU_INST_SUFFIX=SUF, OU_INST_DIR=D, ICS_BACKUP_SCHEDULER_ENABLED="false")
import lab_ics_instance as li  # noqa: E402

li.D, li.SUF = D, SUF
li.ENVF = os.environ.get("ICS_TEST_ENV_FILE", li.ENVF)
assert re.search(r"ics-test(-[a-z0-9]{1,12})?\.env$", li.ENVF), "refusing: not a test env file"
SCRATCH = os.environ.get("OU_BK_ICS_SCRATCH", "ou-ics-r1")
BKP = "ou-bkp1"
SECRETS = "/etc/office-unbound/backup-lab"
LABBK = ROOT / "blueprints" / "lab" / "backup"
RESTIC = "/usr/local/bin/restic"
OK, BAD = [], []


def host(*argv, inp=None, timeout=1800, check=True, env=None):
    p = subprocess.run(["sudo", "-n", *argv], input=inp, capture_output=True, text=True, timeout=timeout, env=env)
    if check and p.returncode:
        raise SystemExit(f"command failed ({argv[0]}): {(p.stderr or p.stdout).strip()[-400:]}")
    return p


def inbkp(script: str) -> str:
    return host("systemd-run", "-M", BKP, "--wait", "-q", "-P", "--pipe", "/bin/bash", "-c", script).stdout


def check(name: str, ok: bool, detail: str = "") -> None:
    (OK if ok else BAD).append(name)
    print(("PASS " if ok else "FAIL ") + name + (" - " + detail if detail else ""), flush=True)


def main() -> int:
    neg = "--neg" in sys.argv
    avail = int([l for l in open("/proc/meminfo") if l.startswith("MemAvailable")][0].split()[1]) // 1024
    if avail < 2048:
        print(f"ABORT: only {avail} MiB available (<2 GiB)")
        return 2
    started = []
    if host("machinectl", "show", BKP, "-p", "State", "--value", check=False).stdout.strip() != "running":
        host("machinectl", "start", BKP)
        started.append(BKP)
        time.sleep(15)
    li.init()                                  # drops/recreates schema of ics_test_<suffix>: THE DEV ICS being protected
    creds = json.load(open(os.path.join(D, "creds.json")))
    os.environ["ICS_ALLOW_LOOPBACK_ENDPOINTS"] = "false"
    from ics.backups import ops  # noqa: E402
    from ics.runtime import Runtime  # noqa: E402
    import lab_backup_product as lbp  # noqa: E402
    r = Runtime()
    with r.session() as d:
        assert d.execute(lbp.text("SELECT current_database()")).scalar() == f"ics_test_{SUF}", "wrong database"
    canary = os.path.join(D, "login-canary.json")
    fd = os.open(canary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"username": "lab-op", "password": creds["lab-op"]["password"], "totp_secret": creds["lab-op"]["secret"]}, f)
    print(host("bash", str(LABBK / "lab-ics-tier-setup.sh"), str(ROOT), D, li.ENVF, SUF, SCRATCH, canary).stdout.strip())
    ip = inbkp("ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1").strip()
    bridge = host("bash", "-c", "ip -4 -o addr show vz-oulab | awk '{print $4}' | cut -d/ -f1 | grep -v '^169.254' | head -1").stdout.strip()
    fp = host("openssl", "x509", "-in", SECRETS + "/bkp.crt", "-noout", "-fingerprint", "-sha256").stdout.split("=")[1].strip().replace(":", "").lower()
    hs = os.path.join(D, "handshake.json")
    host("env", "OU_BKP_TIERS=ics", "bash", str(LABBK / "lab-agent-setup.sh"), str(ROOT), bridge, "18443", hs)
    h = json.load(open(hs))
    appr = ("lab-ap1", "lab-ap2")
    import socket
    for _ in range(30):                        # the agent was just (re)started
        try:
            socket.create_connection((h["address"], h["port"]), timeout=2).close()
            break
        except OSError:
            time.sleep(1)
    lbp.plan(r, "node.enroll", {"name": "bkp-runner-ics", "address": h["address"], "port": h["port"], "tls_fingerprint_sha256": h["tls_fingerprint_sha256"],
                                "agent_key_fingerprint_sha256": h["agent_key_fingerprint_sha256"], "enrollment_token": h["token"]}, who="lab-op", approvers=appr)
    j = lbp.drain(r)[0]
    check("I00 backup runner enrolled with the ICS tier only", j["status"] == "succeeded", str(j["error"] or ""))
    if j["status"] != "succeeded":
        return 1
    with r.session() as d:
        node = str(d.execute(lbp.text("SELECT id FROM nodes WHERE name = 'bkp-runner-ics'")).scalar())
    lbp.plan(r, "backup.policy.create", {"name": "ics-dev", "tier": "ics", "deployment": "dev ICS ics_test_%s" % SUF, "runner_node_id": node, "schedule": {"every_hours": 6},
                                         "retention": {"last": 2, "daily": 7, "weekly": 4, "monthly": 6}, "rpo_seconds": 21600, "rto_seconds": 1800,
                                         "repo": {"url": f"https://{ip}:8000/ics-dev", "ca_sha256": fp},
                                         "verify": {"check_every_seconds": 3600, "check_read_data_percent": 100, "restore_every_seconds": 86400}}, who="lab-op", approvers=appr[:1])
    j = lbp.drain(r)[0]
    check("I01 ICS-tier policy created through the typed action (plan -> approvals -> job)", j["status"] == "succeeded", str(j["error"] or ""))
    host("systemd-run", "-M", BKP, "--wait", "-q", "-P", "--pipe", "/bin/bash", "-c", "rm -rf /srv/restic/ics-dev")      # fresh repository
    with r.session() as d:
        pw = ops.node_secret(r, d, "ics-dev")["repo_password"]                 # break-glass export (audited), never printed
    host("/usr/local/sbin/ou-backup", "--direct", "provision", "ics", inp=json.dumps({"repo_password": pw}))
    out = json.loads(host("/usr/local/sbin/ou-backup", "--direct", "init", "ics").stdout)
    rk = "/var/lib/ou-backup/recovery-ics.txt"
    host("rm", "-f", rk)
    rec = json.loads(host("/usr/local/sbin/ou-backup", "--direct", "recovery-key", "ics", rk).stdout)
    with r.session() as d:
        ops.recovery_ack(d, "ics-dev", rec["recovery_fp"])
    check("I02 encrypted repository initialised, offline recovery key (second restic key) created", bool(out.get("repo_id")) and len(rec["recovery_fp"]) == 16, "repo %s key fingerprint %s" % (out["repo_id"][:12], rec["recovery_fp"]))

    t0 = time.time()
    lbp.plan(r, "backup.run", {"policy": "ics-dev"}, who="lab-op", approvers=appr)
    j = lbp.drain(r)[0]
    with r.session() as d:
        run = ops.list_runs(d, "ics-dev", "backup", 1)[0]
    check("I10 backup.run: dev ICS (pg_dump + roles + keys + env + units + release) -> encrypted repository", j["status"] == "succeeded" and run["repo_confirmed"] is True,
          "snapshot %s, %s bytes processed, %s added, %.1fs" % (str(run["snapshot"])[:8], run["bytes_processed"], run["bytes_added"], time.time() - t0) + (" " + str(j["error"]) if j["error"] else ""))
    # ---- offline recovery key: opens the repository with NO access to the vault
    recpw = host("sed", "-n", "s/^repository password: //p", rk).stdout.strip()
    renv = dict(os.environ, RESTIC_REPOSITORY=f"rest:https://{ip}:8001/ics-dev/", RESTIC_PASSWORD=recpw, RESTIC_CACERT="/etc/ou-backup/bkp-ca.crt",
                RESTIC_REST_USERNAME="maint", RESTIC_REST_PASSWORD=host("cat", SECRETS + "/rest-maint.pw").stdout.strip(),
                RESTIC_CACHE_DIR="/tmp/ou-bk-ics-cache")
    s = subprocess.run([RESTIC, "snapshots", "--json"], env=renv, capture_output=True, text=True, timeout=120)
    check("I11 the OFFLINE recovery key alone (no vault, no node credential file) opens the repository and lists the snapshot",
          s.returncode == 0 and len(json.loads(s.stdout or "[]")) >= 1, "%d snapshot(s)" % len(json.loads(s.stdout or "[]")) if s.returncode == 0 else s.stderr[-150:])
    s2 = subprocess.run([RESTIC, "dump", "latest", "/var/lib/ou-backup/stage/ics/current/MANIFEST", "--host", "ics-dev-controller"], env=renv, capture_output=True, text=True, timeout=120)
    check("I11 control: with that key the manifest of the backup is readable (db_name ics_test_%s, audit head recorded)" % SUF,
          f"db_name=ics_test_{SUF}" in s2.stdout and "audit_head_hash=" in s2.stdout, "manifest decrypted")
    host("shred", "-u", rk)
    hits = inbkp("grep -rIl --binary-files=text -e PRIVATE -e ics_test_app -e ICS_VAULT_KEY_FILE -e ics_test_aa /srv/restic/ics-dev 2>/dev/null | head -3").strip()
    check("I12 the repository holds no cleartext of the controller's configuration, DB credentials or keys (encrypted at rest)", hits == "", "no occurrence" if not hits else hits)
    lbp.plan(r, "backup.verify", {"policy": "ics-dev", "level": "check"}, who="lab-op", approvers=appr)
    j = lbp.drain(r)[0]
    check("I13 backup.verify level=check (100 % of the pack data read) passes", j["status"] == "succeeded", str(j["error"] or ""))
    # ---- restore verification: passive restore into the scratch machine
    t0 = time.time()
    lbp.plan(r, "backup.verify", {"policy": "ics-dev", "level": "restore"}, who="lab-op", approvers=appr)
    j = lbp.drain(r)[0]
    with r.session() as d:
        v = ops.list_verifications(d, "ics-dev", "restore", 1)[0]
    det = v.get("detail") or {}
    check("I20 restore verification (passive restore -> chain verify -> head event -> alembic head -> operator login) passes", j["status"] == "succeeded" and v["state"] == "passed",
          "RTO %ss (target %ss), wall %.0fs, chain checked %s events, passive=%s, operator_login=%s" % (v["rto_seconds"], v["rto_target_seconds"], time.time() - t0, det.get("chain_checked"), det.get("passive"), det.get("operator_login"))
          + ("" if v["state"] == "passed" else " | %s %s" % (v["error"], j["error"])))
    print("restore detail:", json.dumps({k: det.get(k) for k in ("seconds", "rto_seconds", "rto_seconds_incl_poweron", "canary_expected", "canary_observed", "problems")}, default=str))
    with r.session() as d:
        pv = [p for p in ops.list_policies(d) if p["name"] == "ics-dev"][0]
    check("I21 four states: backup ok, recovery ready (check + recovery key), restore verified", pv["states"]["backup_success"]["state"] == "ok" and pv["states"]["recovery_readiness"]["state"] == "ready"
          and pv["states"]["verified_restore"]["state"] == "verified", json.dumps({k: pv["states"][k]["state"] for k in pv["states"]}))
    for _ in range(30):
        if host("machinectl", "show", SCRATCH, "-p", "State", "--value", check=False).stdout.strip() != "running":
            break
        time.sleep(2)
    on = host("machinectl", "show", SCRATCH, "-p", "State", "--value", check=False).stdout.strip()
    check("I22 the scratch controller is powered off after the verification (a restored controller never stays up beside the original)", on != "running", on or "off")
    if neg:
        c2 = json.load(open(canary))
        c2["password"] = "definitely-not-the-password"
        host("tee", "/etc/ou-backup/creds/ics/login-canary.json", inp=json.dumps(c2))
        lbp.plan(r, "backup.verify", {"policy": "ics-dev", "level": "restore"}, who="lab-op", approvers=appr)
        j = lbp.drain(r)[0]
        with r.session() as d:
            v = ops.list_verifications(d, "ics-dev", "restore", 1)[0]
        check("I30 negative: a login canary that cannot log in on the restored controller makes the verification FAIL", v["state"] == "failed" and "login" in json.dumps(v["error"] or "") + json.dumps(v.get("detail") or ""),
              "state %s: %s" % (v["state"], str(v["error"])[:160]))
        host("install", "-m", "0600", canary, "/etc/ou-backup/creds/ics/login-canary.json")
    for m in started:
        host("machinectl", "poweroff", m, check=False)
    print(f"\n{len(OK)} passed, {len(BAD)} failed")
    return 1 if BAD else 0


if __name__ == "__main__":
    sys.exit(main())
