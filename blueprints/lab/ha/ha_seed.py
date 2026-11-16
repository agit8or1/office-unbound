"""LAB ONLY. Runs INSIDE a controller machine of the HA proof, as the `ics` user, with the controller's own code and database:
    cd /opt/office-unbound/ics && runuser -u ics -- env ICS_ENV_FILE=/etc/office-unbound/ics.env .venv/bin/python scripts/ha_seed.py <cmd> [json-args]
It uses the SAME functions the API uses (actions.create_plan / decide_plan: typed plan -> approvals -> durable job), so the controller's real worker /
monitor / backup loops do the work; nothing here performs a side effect itself. Commands (output: one JSON line):
  seed ARGS     users (operator + 2 approvers), enrol the node agent, webhook channel, one tcp_tls check, provider provisioning (preview + apply) against the
                recorder's fake Proxmox, one backup policy.   ARGS: {node_ip, node_tls_fp, node_key_fp, node_token, rec_ip, rec_fp, rec_root_pw}
  stimulate ARGS  create + approve plans (they become queued jobs): {"token_rotates":N,"backup_runs":N,"runbooks":N,"webhooks":N} -> plan/job ids
  state         controller_state, job status counts, audit row count, own process view is NOT used (database only)
  jobs          list jobs (id, action, status, started/finished)"""
import json
import re
import sys
import time
import uuid

import pyotp
from sqlalchemy import text

from ics import actions, agentclient, audit, auth
from ics.actions import ActionType
from ics.runtime import Runtime

PW = "correct horse battery staple 1"
POLICY = {"preset": "deploy", "scope": {"nodes": ["pve06"], "storages": ["PVE06-Storage"], "pools": ["officeunbound-pve06"], "networks": ["vmbr0"],
                                        "template_vmids": [9612, 131], "protected_vmids": [126], "vmid_ranges": [[2000, 2999]]}}
rt = Runtime()


def user(name):
    with rt.session() as db:
        row = db.execute(text("SELECT * FROM users WHERE username = :u"), {"u": name}).first()
        return auth.User(row)


def mk_user(name, role):
    with rt.session() as db:
        if db.execute(text("SELECT 1 FROM users WHERE username = :u"), {"u": name}).first():
            return
        auth.create_invite(db, rt, name, role, created_by=None, actor="ha-seed")
        tok = auth.issue_enrollment_token(db, rt, name, actor="ha-seed")
        uri = auth.enroll_begin(db, rt, name, tok, PW, "127.0.0.1")
        sec = re.search(r"secret=([A-Z2-7]+)", uri).group(1)
        auth.enroll_confirm(db, rt, name, tok, pyotp.TOTP(sec).now(), "127.0.0.1")


def submit(action, params, wait=False, requester="ha-op"):
    """typed plan -> as many distinct approvers as the risk needs -> queued job. Returns {plan_id, job_id, status}."""
    op = user(requester)
    with rt.session() as db:
        p = actions.create_plan(db, rt, op, ActionType(action), params, "127.0.0.1")
        db.commit()
    job_id = p.get("job_id")
    status = p.get("status")
    for ap in ("ha-ap1", "ha-ap2"):
        if status == "approved":
            break
        with rt.session() as db:
            r = actions.decide_plan(db, rt, user(ap), uuid.UUID(p["plan_id"]), True, "127.0.0.1")
        status, job_id = r["status"], r.get("job_id")
    out = {"plan_id": p["plan_id"], "job_id": str(job_id) if job_id else None, "status": status, "action": action}
    if wait and job_id:
        out["job"] = wait_job(job_id)
    return out


def wait_job(job_id, timeout=240):
    end = time.time() + timeout
    while time.time() < end:
        with rt.session() as db:
            j = db.execute(text("SELECT status, result, error FROM jobs WHERE id = :i"), {"i": str(job_id)}).first()
        if j and j.status in ("succeeded", "failed"):
            return {"status": j.status, "error": j.error, "result": j.result if j.status == "succeeded" else None}
        time.sleep(1)
    return {"status": "timeout"}


def enroll_node(a):
    with rt.session() as db:
        if db.execute(text("SELECT 1 FROM nodes WHERE name = 'ha-node1'")).first():
            return db.execute(text("SELECT id FROM nodes WHERE name = 'ha-node1'")).scalar()
    priv = agentclient.load_signing_key(rt.settings.signing_key_file)
    ident = agentclient.identity(a["node_ip"], 8443, a["node_tls_fp"])
    assert agentclient.key_fingerprint(ident["agent_pubkey"]) == a["node_key_fp"], "agent key fingerprint mismatch"
    nid = uuid.uuid4()
    resp = agentclient.enroll(a["node_ip"], 8443, a["node_tls_fp"], token=a["node_token"], ics_pubkey_b64=agentclient.pub_b64(priv.public_key()), node_id=str(nid),
                              expect_agent_pubkey_b64=ident["agent_pubkey"])
    with rt.session() as db:
        db.execute(text("INSERT INTO nodes (id, name, address, port, tls_fingerprint_sha256, agent_pubkey, agent_key_fp, capabilities, agent_version, last_seen_at) "
                        "VALUES (:id, :n, :a, 8443, :t, :k, :f, CAST(:c AS jsonb), :v, now())"),
                   {"id": str(nid), "n": "ha-node1", "a": a["node_ip"], "t": a["node_tls_fp"], "k": ident["agent_pubkey"], "f": a["node_key_fp"],
                    "c": audit.canon(resp.get("capabilities", {})), "v": str(resp.get("agent_version"))[:40]})
        audit.append(db, "node.enrolled", actor_name="ha-seed", resource="node", resource_id=str(nid), details={"name": "ha-node1"})
        db.commit()
    return str(nid)


def seed(a):
    out = {}
    for n, r in (("ha-op", "operator"), ("ha-ap1", "approver"), ("ha-ap2", "approver")):
        mk_user(n, r)
    out["node_id"] = str(enroll_node(a))
    base = f"https://{a['rec_ip']}:8006"
    conn = {"name": "ha-pve", "base_url": base, "fingerprint_sha256": a["rec_fp"], "admin_username": "root@pam", "admin_password": a["rec_root_pw"]}
    def have(table, name):
        with rt.session() as db:
            return db.execute(text(f"SELECT id FROM {table} WHERE name = :n"), {"n": name}).scalar()
    out["errors"] = {}

    def step(key, table, name, action, params, pre=None):
        if (i := have(table, name)):
            out[key] = "exists"
            return i, None
        r = submit(action, params, wait=True)
        out[key] = r["job"]["status"]
        if r["job"]["status"] != "succeeded":
            out["errors"][key] = r["job"].get("error")
        return have(table, name), r

    if not have("endpoints", "ha-pve"):
        pv = submit("provider.provision.plan_preview", {**conn, "policy": POLICY}, wait=True)
        out["preview"] = pv["job"]["status"]
        res = pv["job"]["result"] or {}
        ap = submit("provider.provision.apply", {**conn, "preview_id": res["preview_id"], "plan_hash": res["plan_hash"]}, wait=True)
        out["apply"] = ap["job"]["status"]
        if ap["job"]["status"] != "succeeded":
            out["errors"]["apply"] = ap["job"].get("error")
    out["endpoint_id"] = str(have("endpoints", "ha-pve"))
    step("channel", "alert_channels", "ha-hook", "alert_channel.create",
         {"name": "ha-hook", "kind": "webhook", "config": {"url": f"https://{a['rec_ip']}:8007/hook", "fingerprint_sha256": a["rec_fp"]}, "secret": "ha-lab-webhook-secret-0123456789"})
    step("check", "checks", "ha-probe", "check.create",
         {"name": "ha-probe", "kind": "tcp_tls", "config": {"host": a["rec_ip"], "port": 8010, "fingerprint_sha256": a["rec_fp"]},
          "interval_seconds": 15, "fail_threshold": 1, "recover_threshold": 1})
    step("backup_policy", "backup_policies", "ha-files", "backup.policy.create",
         {"name": "ha-files", "tier": "files", "deployment": "ha", "runner_node_id": out["node_id"], "schedule": {"every_hours": 1}, "rpo_seconds": 86400, "rto_seconds": 3600,
          "repo": {"backend": "rest", "url": f"https://{a['rec_ip']}:8011/{'c-0000000000000000000000000000a001'}/files", "ca_sha256": a["rec_fp"]}})
    with rt.session() as db:     # the backup scheduler refuses a policy whose offline recovery key was not acknowledged (what an operator does with ics.cli backup-recovery-ack)
        from ics.backups import ops as backup_ops
        if db.execute(text("SELECT recovery_exported_at FROM backup_policies WHERE name = 'ha-files'")).scalar() is None:
            backup_ops.recovery_ack(db, "ha-files", "0123456789abcdef")
    return out


def stimulate(a):
    out = {"plans": []}
    with rt.session() as db:
        ep = db.execute(text("SELECT id FROM endpoints ORDER BY created_at LIMIT 1")).scalar()
        ch = db.execute(text("SELECT id FROM alert_channels LIMIT 1")).scalar()
        node = db.execute(text("SELECT id FROM nodes WHERE name = 'ha-node1'")).scalar()
    for _ in range(int(a.get("token_rotates", 0))):
        out["plans"].append(submit("provider.token.rotate", {"endpoint_id": str(ep), "admin_username": "root@pam", "admin_password": a["rec_root_pw"]}))
    for _ in range(int(a.get("backup_runs", 0))):
        out["plans"].append(submit("backup.run", {"policy": "ha-files", "trigger": "manual"}))
    for _ in range(int(a.get("runbooks", 0))):
        out["plans"].append(submit("runbook.execute", {"node_id": str(node), "runbook": "service.status", "unit": "systemd-networkd"}))
    for _ in range(int(a.get("webhooks", 0))):
        out["plans"].append(submit("alert_channel.test", {"channel_id": str(ch)}))
    return out


def state(_):
    with rt.session() as db:
        st = db.execute(text("SELECT epoch, role, note, extract(epoch FROM changed_at) AS at FROM controller_state WHERE id = 1")).first()
        jobs = db.execute(text("SELECT status, count(*) FROM jobs GROUP BY 1")).all()
        rows = db.execute(text("SELECT count(*) FROM audit_events")).scalar()
        rec = db.execute(text("SELECT pg_is_in_recovery()")).scalar()
    return {"epoch": st.epoch, "role": st.role, "note": st.note, "changed_at": float(st.at), "jobs": {r[0]: r[1] for r in jobs}, "audit_rows": rows, "in_recovery": rec}


def jobs(_):
    with rt.session() as db:
        rows = db.execute(text("SELECT j.id, j.action, j.status, j.started_at, j.finished_at, j.error FROM jobs j ORDER BY j.created_at")).all()
    return [{"id": str(r.id), "action": r.action, "status": r.status, "started": r.started_at.isoformat() if r.started_at else None,
             "finished": r.finished_at.isoformat() if r.finished_at else None, "error": r.error} for r in rows]


if __name__ == "__main__":
    cmd = sys.argv[1]
    args = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    print(json.dumps({"seed": seed, "stimulate": stimulate, "state": state, "jobs": jobs}[cmd](args), default=str))
