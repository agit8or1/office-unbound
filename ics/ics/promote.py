"""Fenced promotion of a warm standby (ADR-0012). Run as ROOT on the standby host:  python -m ics.cli promote ...

Order matters (single-writer guarantee):
  0. refuse unless this host is a standby and the old primary is not still streaming (or can be fenced right now);
  1. optionally FENCE the old primary through its database (controller_state.role='fenced') while it is reachable;
  2. promote PostgreSQL (pg_promote);
  3. in ONE transaction: bump the controller epoch + audit event `controller.promoted` (carries the replay position = data-loss bound);
  4. verify the audit chain end to end;
  5. flip the local role to primary and restart ics (worker/monitor start);
  6. announce the new epoch to every enrolled agent (the first signed request raises the agent's fence mark).
Whatever happens to the old primary afterwards, agents that have seen the new epoch refuse it.
"""
import os
import socket
import subprocess
import sys
import time

from sqlalchemy import create_engine, text

from . import agentclient, audit, epoch as epochmod
from .runtime import Runtime

ENV_FILE = os.environ.get("ICS_ENV_FILE", "/etc/office-unbound/ics.env")


def _pg(sql: str, as_user: str = "postgres") -> str:
    r = subprocess.run(["runuser", "-u", as_user, "--", "psql", "-X", "-Atq", "-v", "ON_ERROR_STOP=1", "-c", sql], capture_output=True, text=True, timeout=120)
    if r.returncode:
        raise RuntimeError(f"psql failed: {r.stderr.strip()[:200]}")
    return r.stdout.strip()


def set_env(path: str, updates: dict[str, str]) -> None:
    lines = open(path).read().splitlines()
    for k, v in updates.items():
        idx = [i for i, l in enumerate(lines) if l.strip().partition("=")[0].strip() == k]
        if idx:
            lines[idx[0]] = f"{k}={v}"
        else:
            lines.append(f"{k}={v}")
    st = os.stat(path)
    tmp = path + ".new"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, ("\n".join(lines) + "\n").encode())
    os.fchown(fd, st.st_uid, st.st_gid)
    os.fchmod(fd, st.st_mode & 0o7777)
    os.close(fd)
    os.replace(tmp, path)


def fence_old_primary(dsn: str, new_epoch_hint: str) -> None:
    """Best effort while the old primary is reachable: its own database says 'fenced', so its ics refuses to sign anything."""
    eng = create_engine(dsn)
    with eng.begin() as c:
        c.execute(text("UPDATE controller_state SET role = 'fenced', note = :n WHERE id = 1"), {"n": new_epoch_hint})
    eng.dispose()


def announce(rt: Runtime) -> list[dict]:
    """One harmless read-only runbook per enrolled node so every agent learns the new epoch now rather than at the next monitor pass."""
    out = []
    priv = agentclient.load_signing_key(rt.settings.signing_key_file)
    with rt.session() as db:
        nodes = db.execute(text("SELECT * FROM nodes WHERE status <> 'decommissioned'")).all()
    for n in nodes:
        caps = n.capabilities or {}
        if "disk.usage" in caps and caps["disk.usage"].get("paths"):
            action, params = "disk.usage", {"path": caps["disk.usage"]["paths"][0]}
        elif "service.status" in caps and caps["service.status"].get("units"):
            action, params = "service.status", {"unit": caps["service.status"]["units"][0]}
        else:
            out.append({"node": str(n.id), "result": "no read-only runbook available"})
            continue
        jid = agentclient.new_job_id()
        try:
            body = agentclient.build_request(priv, action=action, params=params, node_id=str(n.id), job_id=jid,
                                             ttl=rt.settings.agent_request_ttl_seconds, epoch=rt.agent_epoch())
            _, resp = agentclient.call(n, priv, action=action, params=params, job_id=jid, deadline=30,
                                       allow_loopback=rt.settings.allow_loopback_endpoints, req_override=body)
            out.append({"node": str(n.id), "result": resp.get("code"), "agent_epoch": resp.get("agent_epoch")})
        except Exception as e:  # noqa: BLE001
            out.append({"node": str(n.id), "result": f"unreachable: {type(e).__name__}"})
    return out


UNCERTAIN = {"code": "uncertain_after_promotion",
             "message": "this job was queued or running in the replica when the standby was promoted: the old primary may already have executed it. "
                        "It is never run automatically; check the target, then submit a new plan if it is still needed."}


def quarantine_inflight(db) -> list[str]:
    """HA R1 (docs/status/ha-partition-results.md): jobs that were queued/running in the replica at promotion may have run on the old primary inside
    the replication gap. Provider mutations have no idempotency key, so the new primary must not re-claim them: they are failed with an explicit
    `uncertain_after_promotion` error (operator decides), their plan secrets are scrubbed, and each gets an audit event. Same transaction as the epoch bump."""
    from sqlalchemy import text
    rows = db.execute(text("SELECT id, plan_id, action, status FROM jobs WHERE status IN ('queued', 'running') FOR UPDATE")).all()
    for r in rows:
        db.execute(text("UPDATE jobs SET status = 'failed', finished_at = now(), error = CAST(:e AS jsonb) WHERE id = :i"),
                   {"e": audit.canon({**UNCERTAIN, "was": r.status}), "i": r.id})
        db.execute(text("UPDATE plans SET secret_enc = NULL WHERE id = :i"), {"i": r.plan_id})
        audit.append(db, "job.failed", actor_name="promotion", resource="job", resource_id=str(r.id),
                     details={"action": r.action, "error": {**UNCERTAIN, "was": r.status}})
    return [str(r.id) for r in rows]


def promote(args) -> int:
    t0 = time.time()
    hostname = socket.gethostname()
    if os.geteuid() != 0:
        print("promote must run as root on the standby host", file=sys.stderr)
        return 2
    rt = Runtime()
    if rt.settings.role != "standby":
        print("refusing: ICS_ROLE is not 'standby' on this host", file=sys.stderr)
        return 1
    if _pg("SELECT pg_is_in_recovery()") != "t":
        print("refusing: PostgreSQL here is not in recovery (already promoted?)", file=sys.stderr)
        return 1
    wal = _pg("SELECT coalesce(status, 'none') FROM pg_stat_wal_receiver") or "none"
    fenced_old = False
    if wal == "streaming":
        if not args.fence_old_dsn_file:
            print("refusing: the primary is still streaming to this standby. Stop it first (systemctl stop ics postgresql there) or give\n"
                  "--fence-old-dsn-file (a file holding a postgresql+psycopg:// URL of the old primary's app role) to fence it now.", file=sys.stderr)
            return 1
        try:
            fence_old_primary(open(args.fence_old_dsn_file).read().strip(), f"fenced by promotion on {hostname}")
            fenced_old = True
        except Exception as e:  # noqa: BLE001
            print(f"refusing: could not fence the reachable old primary ({type(e).__name__}); nothing was changed", file=sys.stderr)
            return 1
    if rt.settings.witness_state_file:
        # review 7 H-5: the old primary may be alive behind a partition. Stop the witness granting, then wait until any lease it holds has expired
        # (T + margin since the last grant). Only then is it safe to become the single writer.
        from .lease import Witness
        w = Witness(None, None, lease_seconds=rt.settings.lease_seconds, state_path=rt.settings.witness_state_file)
        print(f"witness: revoked epochs <= {w.revoke()}; waiting until no controller can hold a valid lease "
              f"(T={rt.settings.lease_seconds:.0f}s + margin {rt.settings.witness_margin_seconds:.0f}s since the last grant)")
        w.wait_proven(rt.settings.witness_margin_seconds, progress=lambda left: print(f"  ... {left:.0f} s", flush=True))
        print("witness: proven - the old primary's lease has expired")
    else:
        print("NOTE: no ICS_WITNESS_STATE_FILE on this host: promotion is NOT lease-proven (an isolated old primary keeps acting until an agent refuses it)", file=sys.stderr)
    phrase = f"promote {hostname}"
    answer = args.confirm
    if answer is None:
        print(f"PROMOTION makes THIS host the only writer. The old primary must stay down (or be re-cloned as a standby).\nType exactly: {phrase}")
        answer = sys.stdin.readline().strip()
    if answer != phrase:
        print("confirmation did not match; nothing was changed", file=sys.stderr)
        return 1
    with rt.session() as db:
        pos = db.execute(text("SELECT pg_last_wal_replay_lsn()::text AS lsn, pg_last_xact_replay_timestamp()::text AS ts, "
                              "(SELECT max(at)::text FROM worker_heartbeat) AS hb, (SELECT count(*) FROM audit_events) AS audit_rows")).first()
    print(f"standby position: replay_lsn={pos.lsn} last_replayed_commit={pos.ts} last_primary_heartbeat={pos.hb} audit_rows={pos.audit_rows}")
    t_pg = time.time()
    _pg("SELECT pg_promote(true, 60)")
    for _ in range(120):
        if _pg("SELECT pg_is_in_recovery()") == "f":
            break
        time.sleep(0.5)
    else:
        print("PostgreSQL did not leave recovery within 60 s", file=sys.stderr)
        return 1
    rt.engine.dispose()
    operator = os.environ.get("SUDO_USER") or "root"
    with rt.session() as db:
        old, new = epochmod.bump_for_promotion(db, hostname, f"promoted by {operator}")
        uncertain = quarantine_inflight(db)
        audit.append(db, "controller.promoted", actor_name=f"cli:{operator}", resource="controller", resource_id=hostname,
                     details={"old_epoch": old, "new_epoch": new, "replay_lsn": pos.lsn, "last_replayed_commit": pos.ts,
                              "last_primary_heartbeat": pos.hb, "audit_rows_at_promotion": int(pos.audit_rows),
                              "old_primary_fenced_in_db": fenced_old, "wal_receiver_before": wal,
                              "jobs_marked_uncertain": uncertain})
        db.commit()
    with rt.session() as db:
        chain = audit.verify_chain(db)
    print(f"epoch {old} -> {new}; audit chain {chain}; {len(uncertain)} in-flight job(s) marked uncertain (never re-run automatically)")
    if not chain["ok"]:
        print("AUDIT CHAIN VERIFICATION FAILED after promotion - do not start the controller; investigate", file=sys.stderr)
        return 3
    set_env(ENV_FILE, {"ICS_ROLE": "primary", "ICS_WORKER_ENABLED": "true", "ICS_MONITOR_ENABLED": "true"})
    if not args.no_restart:
        subprocess.run(["systemctl", "restart", "ics.service"], check=False, timeout=60)
    os.environ.pop("ICS_ROLE", None)
    rt2 = Runtime()   # reloads ics.env: now a primary
    ann = announce(rt2) if not args.no_announce else []
    for a in ann:
        print("announce:", a)
    print(f"PROMOTED. controller epoch {new}. pg_promote->done {time.time() - t_pg:.1f}s, total {time.time() - t0:.1f}s. "
          f"Move the console address/DNS to this host, then re-clone the old primary as a standby (docs/runbooks/ics-recovery.md).")
    return 0
