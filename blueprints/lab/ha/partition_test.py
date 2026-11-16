#!/usr/bin/env python3
"""LAB ONLY. Two-controller partition / failover proof (owner requirement: "only one controller can execute infrastructure operations").
Driver, runs on the lab HOST (needs sudo for systemd-run -M / machinectl). Usage via blueprints/lab/ha/partition-test.sh:
    partition_test.py up | deploy | run S1 S2 ... | down       (run without names = all scenarios)

Machines: ou-ha1 / ou-ha2 (the two controllers; roles swap between scenarios), ou-ha-node1 (one node agent + the central RECORDER: fake Proxmox,
webhook receiver, backup helper stub, agent exec log). EVERY assertion is made on the recorder's data (what actually arrived at the provider, the
webhook receiver, the agent and the backup helper), never on a controller's own log. The only controller-side facts used are the epoch the
promotion committed in the NEW primary's database (T_commit) and the verdicts of /readyz and the API (which are the thing under test in S3).
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "../../.."))
IP = {"ou-ha1": "192.168.186.52", "ou-ha2": "192.168.186.123"}
NODE, NODE_IP = "ou-ha-node1", "192.168.186.27"
MEM = {"ou-ha1": "1500M", "ou-ha2": "1500M", "ou-ha-node1": "1G"}
REC = f"http://{NODE_IP}:8099"
OPT = "/opt/office-unbound/ics"
PYENV = f"cd {OPT} && runuser -u ics -- env PYTHONPATH={OPT} ICS_ENV_FILE=/etc/office-unbound/ics.env {OPT}/.venv/bin/python"
OBSERVE = int(os.environ.get("HA_OBSERVE_SECONDS", "45"))      # how long the old primary is watched after the promotion committed
T_LEASE = int(os.environ.get("HA_LEASE_SECONDS", "30"))        # BU's self-fence timeout T (S8); the observation after the standby went away is T + margin
EVIDENCE = os.path.join(REPO, "docs/status/ha-partition-evidence.json")
LOG: list[str] = []


def now() -> float:
    return time.time()


def say(msg: str) -> None:
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    LOG.append(line)
    print(line, flush=True)


# ---------------------------------------------------------------------------------------------------------------- machine access
def sh(m: str, cmd: str, timeout: int = 900, check: bool = False, stdin: bytes | None = None) -> tuple[int, str]:
    r = subprocess.run(["sudo", "systemd-run", "-M", m, "--pipe", "--wait", "-q", "/bin/bash", "-c", cmd], input=stdin, capture_output=True, timeout=timeout)
    out = (r.stdout + r.stderr).decode("utf-8", "replace")
    if check and r.returncode:
        raise RuntimeError(f"{m}: `{cmd[:80]}` failed rc={r.returncode}: {out[-400:]}")
    return r.returncode, out


def host_cat(m: str, path: str) -> bytes:
    return subprocess.run(["sudo", "cat", f"/var/lib/machines/{m}{path}"], capture_output=True, check=True).stdout


def put(m: str, path: str, data: bytes, mode: str = "0644") -> None:
    sh(m, f"cat > {path} && chmod {mode} {path}", stdin=data, check=True)


def mem_available_gib() -> float:
    for line in open("/proc/meminfo"):
        if line.startswith("MemAvailable"):
            return int(line.split()[1]) / 1048576
    return 0.0


def machine_running(m: str) -> bool:
    return subprocess.run(["machinectl", "show", m, "-p", "State", "--value"], capture_output=True, text=True).stdout.strip() == "running"


def start(m: str) -> None:
    if machine_running(m):
        return
    avail = mem_available_gib()
    if avail < 2.0:
        raise SystemExit(f"abort: host MemAvailable {avail:.1f} GiB < 2 GiB before starting {m}")
    subprocess.run(["sudo", "machinectl", "start", m], check=True)
    subprocess.run(["sudo", "systemctl", "set-property", "--runtime", f"systemd-nspawn@{m}", f"MemoryMax={MEM[m]}"], check=False)
    for _ in range(60):
        if sh(m, "systemctl is-system-running --wait >/dev/null 2>&1; echo up", timeout=60)[1].strip().endswith("up"):
            break
        time.sleep(1)
    say(f"started {m} (host MemAvailable {avail:.1f} GiB)")


def seed(m: str, cmd: str, args: dict | None = None, timeout: int = 600) -> dict:
    a = json.dumps(args or {})
    rc, out = sh(m, f"{PYENV} scripts/ha_seed.py {cmd} '{a}'", timeout=timeout)
    try:
        return json.loads(out.strip().splitlines()[-1])
    except Exception:
        raise RuntimeError(f"ha_seed {cmd} on {m} failed rc={rc}: {out[-500:]}") from None


def rec_get() -> dict:
    return json.load(urllib.request.urlopen(REC + "/state", timeout=20))


def rec_post(path: str, body: dict) -> dict:
    req = urllib.request.Request(REC + path, data=json.dumps(body).encode(), method="POST")
    return json.load(urllib.request.urlopen(req, timeout=20))


def stim(m: str, **kw) -> dict:
    return seed(m, "stimulate", {**kw, "rec_root_pw": rec_get_cert()["root_password"]})


_CERT: dict = {}


def rec_get_cert() -> dict:
    if not _CERT:
        _CERT.update(json.load(urllib.request.urlopen(REC + "/cert", timeout=20)))
    return _CERT


def psql(m: str, sql: str, db: str = "ics") -> str:
    return sh(m, f"runuser -u postgres -- psql -X -Atq -d {db} -c \"{sql}\"")[1].strip()


def readyz(m: str) -> dict:
    rc, out = sh(m, f"curl -s -m 8 --cacert /etc/office-unbound/tls/ca.crt -w '\\n%{{http_code}}' https://{IP[m]}/readyz")
    body, _, code = out.rpartition("\n")
    try:
        j = json.loads(body)
    except ValueError:
        j = {}
    return {"http": int(code) if code.strip().isdigit() else None, **j}


def api_mutation(m: str) -> dict:
    rc, out = sh(m, f"curl -s -m 8 -o /dev/null -D - --cacert /etc/office-unbound/tls/ca.crt -X POST -H 'content-type: application/json' -d '{{}}' https://{IP[m]}/api/v1/plans")
    code = re.search(r"HTTP/[\d.]+ (\d+)", out)
    role = re.search(r"(?i)x-ou-role: (\S+)", out)
    return {"http": int(code.group(1)) if code else None, "x_ou_role": role.group(1) if role else None}


# ---------------------------------------------------------------------------------------------------------------- topology
def partition(a: str, b: str) -> None:
    for m, peer in ((a, IP[b]), (b, IP[a])):
        sh(m, "nft delete table inet hapart 2>/dev/null; nft add table inet hapart && "
              "nft add chain inet hapart i '{ type filter hook input priority -400; policy accept; }' && "
              "nft add chain inet hapart o '{ type filter hook output priority -400; policy accept; }' && "
              f"nft add rule inet hapart i ip saddr {peer} drop && nft add rule inet hapart o ip daddr {peer} drop", check=True)


def heal(a: str, b: str) -> None:
    for m in (a, b):
        sh(m, "nft delete table inet hapart 2>/dev/null; true")


def tune_pg(m: str) -> None:
    psql(m, "ALTER SYSTEM SET wal_sender_timeout = '5s'", "postgres")
    psql(m, "ALTER SYSTEM SET wal_receiver_timeout = '5s'", "postgres")
    psql(m, "SELECT pg_reload_conf()", "postgres")


def cstate(m: str) -> dict | None:
    try:
        return seed(m, "state", timeout=60)
    except Exception:
        return None


def healthy_primary(m: str) -> bool:
    if not machine_running(m):
        return False
    s = cstate(m)
    return bool(s and s["role"] == "primary" and not s["in_recovery"] and sh(m, "systemctl is-active ics")[1].strip() == "active")


def standby_ok(m: str) -> bool:
    if not machine_running(m):
        return False
    r = readyz(m)
    return r.get("role") == "standby" and bool(r.get("ready")) and "rebuilt" not in r


def build_standby(sb: str, pr: str) -> None:
    """(re)build `sb` as a warm standby of `pr`: prepare the primary for it, hand over bundle + passphrase, bootstrap --standby-of ... --rebuild"""
    t = now()
    tune_pg(pr)
    sh(pr, f"rm -rf /root/ics-standby /root/standby.pass; cd /root/src && OU_BUNDLE_PASSPHRASE_OUT=/root/standby.pass bash ics/deploy/standby/ics-standby-prepare-primary.sh "
           f"--primary-ip {IP[pr]} --standby-ip {IP[sb]}", check=True)
    put(sb, "/root/bundle", host_cat(pr, "/root/ics-standby/ics-standby-keys.bundle"), "0600")
    put(sb, "/root/bundle.pass", host_cat(pr, "/root/standby.pass"), "0600")
    sh(pr, "rm -rf /root/ics-standby /root/standby.pass")
    sh(sb, "systemctl stop ics 2>/dev/null; true")
    sh(sb, f"cd /root/src && bash ics/deploy/bootstrap.sh --standby-of {IP[pr]} --key-bundle /root/bundle --bundle-passphrase-file /root/bundle.pass "
           f"--listen-ip {IP[sb]} --allow-cidr 192.168.186.0/24 --rebuild", check=True)
    sh(sb, "install -m 0644 -o root -g ics /root/src/blueprints/lab/ha/ha_seed.py /opt/office-unbound/ics/scripts/ha_seed.py", check=True)
    for _ in range(60):
        if standby_ok(sb):
            break
        time.sleep(2)
    else:
        raise RuntimeError(f"{sb} did not become a healthy standby: {readyz(sb)}")
    say(f"{sb} rebuilt as standby of {pr} in {now() - t:.0f} s")


def ensure_pair() -> tuple[str, str]:
    """returns (primary, standby), rebuilding whatever is not a healthy primary + streaming standby. Also resets recorder knobs and opens the probe."""
    for m in (NODE, "ou-ha1", "ou-ha2"):
        start(m)
    for m in ("ou-ha1", "ou-ha2"):
        heal("ou-ha1", "ou-ha2")
    # an old primary that was never fenced in its OWN database still looks like a healthy primary: the highest epoch wins, the other one is rebuilt as the standby
    cands = sorted((m for m in ("ou-ha1", "ou-ha2") if healthy_primary(m)), key=lambda m: -cstate(m)["epoch"])
    pr = cands[0] if cands else None
    if pr is None:
        raise SystemExit("no healthy primary: run `partition-test.sh build` (from-scratch setup) first")
    sb = "ou-ha2" if pr == "ou-ha1" else "ou-ha1"
    streaming = psql(pr, "SELECT count(*) FROM pg_stat_replication WHERE state = 'streaming'") == "1"
    if not (streaming and standby_ok(sb)):
        build_standby(sb, pr)
    tune_pg(pr)
    tune_pg(sb)
    rec_post("/config", {"delay_ms": 0})
    rec_post("/probe", {"open": True})
    say(f"pair: primary {pr} (epoch {cstate(pr)['epoch']}), standby {sb}")
    return pr, sb


def promote(sb: str, fence_dsn_file: str | None = None) -> dict:
    host = sh(sb, "hostname")[1].strip()
    extra = f" --fence-old-dsn-file {fence_dsn_file}" if fence_dsn_file else ""
    t0 = now()
    rc, out = sh(sb, f"{OPT}/deploy/standby/ics-promote.sh --confirm 'promote {host}'{extra}", timeout=300)
    t1 = now()
    st = cstate(sb) if rc == 0 else None
    return {"rc": rc, "out": out[-1500:], "t_start": t0, "t_end": t1, "seconds": round(t1 - t0, 1), "t_commit": st["changed_at"] if st else None,
            "epoch": st["epoch"] if st else None}


# ---------------------------------------------------------------------------------------------------------------- analysis (recorder data only)
def activity(state: dict, ctrl: str, after: float, before: float = 1e18) -> dict:
    ip = IP[ctrl]
    rs = [r for r in state["records"] if r.get("src") == ip and after < r["ts"] <= before]
    ag = [a for a in state["agent"] if a.get("peer") == ip and after < a["ts"] <= before]
    admitted = [a for a in ag if a.get("status") in ("ok", "error") and a.get("action") != "enroll"]
    out = {
        "provider_mutating": [r for r in rs if r["kind"] == "pve" and r["mutating"]],
        "provider_reads": [r for r in rs if r["kind"] == "pve" and not r["mutating"]],
        "webhooks": [r for r in rs if r["kind"] == "webhook"],
        "agent_executed": admitted,
        "agent_backup_runs": [a for a in admitted if str(a.get("action", "")).startswith("backup.")],
        "agent_rejected": [a for a in ag if a.get("status") == "rejected"],
        "enrollments": [a for a in ag if a.get("action") == "enroll"],
    }
    return out


def counts(act: dict) -> dict:
    return {k: len(v) for k, v in act.items()}


def violations(act: dict) -> dict:
    """what an old primary must NOT do after the new epoch was committed: executed side effects (rejected agent attempts are reported separately)"""
    return {k: len(act[k]) for k in ("provider_mutating", "provider_reads", "webhooks", "agent_executed", "agent_backup_runs", "enrollments")}


def duplicates(state: dict) -> dict:
    """no job / step may be executed twice, nor by both controllers (idempotency evidence at the provider and the agent)"""
    ctrl = {v: k for k, v in IP.items()}
    by_job: dict[str, set] = {}
    steps: dict[tuple, list] = {}
    for r in state["records"]:
        if r["kind"] == "pve" and r["mutating"] and r.get("job"):
            by_job.setdefault(r["job"], set()).add(ctrl.get(r["src"], r["src"]))
            steps.setdefault((r["job"], r["method"], r["path"], json.dumps(r["fields"], sort_keys=True)), []).append(r)
    for a in state["agent"]:
        if a.get("status") in ("ok", "error") and a.get("action") != "enroll" and a.get("job_id"):
            by_job.setdefault(a["job_id"], set()).add(ctrl.get(a["peer"], a["peer"]))
    two_ctrl = sorted(j for j, c in by_job.items() if len(c) > 1)
    twice = sorted({k[0] + " " + k[1] + " " + k[2] for k, v in steps.items() if len(v) > 1})
    return {"jobs_executed_by_both_controllers": two_ctrl, "steps_executed_twice": twice}


def wait_for(pred, timeout: float, every: float = 1.0):
    end = now() + timeout
    while now() < end:
        v = pred()
        if v:
            return v
        time.sleep(every)
    return None


def verdict(ok: bool) -> str:
    return "PASS" if ok else "FAIL"


# ---------------------------------------------------------------------------------------------------------------- scenarios
def s1(ctx) -> dict:
    """S1 clean promotion: the old primary is stopped, the standby is promoted; the new primary then drives every class and the agent accepts epoch+1."""
    pr, sb = ensure_pair()
    e0 = cstate(pr)["epoch"]
    t_stop = now()
    sh(pr, "systemctl stop ics postgresql", check=True)
    p = promote(sb)
    if p["rc"]:
        return {"result": "FAIL", "why": "promotion failed", "promote": p}
    t_commit = p["t_commit"]
    s = stim(sb, token_rotates=1, runbooks=1, backup_runs=1, webhooks=1)
    def seen():
        st = rec_get()
        a = activity(st, sb, t_commit)
        return st if (a["provider_mutating"] and a["agent_executed"] and a["webhooks"] and a["agent_backup_runs"]) else None
    st = wait_for(seen, 90) or rec_get()
    new = activity(st, sb, t_commit)
    old = activity(st, pr, t_commit)
    first_agent = min((a["ts"] for a in new["agent_executed"]), default=None)
    epochs = {"provider_epoch_headers": sorted({r.get("epoch") for r in new["provider_mutating"]}), "agent_req_epochs": sorted({a.get("req_epoch") for a in new["agent_executed"]}),
              "webhook_epochs": sorted({r.get("epoch") for r in new["webhooks"]})}
    ok = (p["epoch"] == e0 + 1 and all(len(new[k]) > 0 for k in ("provider_mutating", "agent_executed", "webhooks", "agent_backup_runs"))
          and sum(violations(old).values()) == 0 and epochs["agent_req_epochs"] == [e0 + 1])
    return {"result": verdict(ok), "old_primary": pr, "new_primary": sb, "epoch": f"{e0} -> {p['epoch']}", "promote_seconds": p["seconds"],
            "rto_stop_to_first_agent_exec_seconds": round(first_agent - t_stop, 1) if first_agent else None,
            "new_primary_counts": counts(new), "old_primary_after_commit": violations(old), "epochs_seen_at_recorder": epochs, "stimulus": s["plans"] and len(s["plans"])}


def s2_s3(ctx) -> dict:
    """S2 + S3: partition primary<->standby, promote the standby while the old primary is alive and still reaches agent + provider; then heal."""
    pr, sb = ensure_pair()
    e0 = cstate(pr)["epoch"]
    stim(pr, runbooks=1, backup_runs=1, webhooks=1)
    base = wait_for(lambda: (lambda a: a if a["agent_executed"] and a["webhooks"] else None)(activity(rec_get(), pr, now() - 120)), 90)
    say(f"S2 baseline: old primary active before the partition: {counts(base) if base else 'NOT ACTIVE'}")
    if not base:
        return {"S2": {"result": "INVALID", "why": f"{pr} was not active before the partition"}, "S3": {"result": "INVALID", "why": "see S2"}}
    t_part = now()
    partition(pr, sb)
    t_det = wait_for(lambda: now() if psql(sb, "SELECT count(*) FROM pg_stat_wal_receiver WHERE status = 'streaming'") == "0" else None, 90)
    detect = round(t_det - t_part, 1) if t_det else None
    say(f"standby noticed the partition after {detect} s")
    rec_post("/config", {"delay_ms": 1500})
    stim(pr, token_rotates=2, runbooks=2, backup_runs=1, webhooks=1)        # operator work accepted by the (still believed) primary during the partition
    p = promote(sb)
    if p["rc"]:
        heal(pr, sb)
        return {"S2": {"result": "FAIL", "why": "promotion refused/failed under partition", "promote": p, "detect_seconds": detect}}
    tc = p["t_commit"]
    say(f"promotion committed (epoch {p['epoch']}) at +{tc - t_part:.1f} s; old primary alive, partitioned; stimulating it again")
    stim(pr, token_rotates=1, runbooks=2, backup_runs=1, webhooks=2)        # work that arrives AFTER the new epoch exists
    rec_post("/probe", {"open": False})                                      # monitor loop: the check fails -> notification
    time.sleep(20)
    rec_post("/probe", {"open": True})                                       # ... and recovers -> notification
    stim(sb, runbooks=1, webhooks=1)                                         # the new primary works normally meanwhile
    time.sleep(OBSERVE)
    st = rec_get()
    act = activity(st, pr, tc)
    v = violations(act)
    per = {k: (round(min(x["ts"] for x in act[k]) - tc, 1), round(max(x["ts"] for x in act[k]) - tc, 1)) for k in act if act[k]}
    new = activity(st, sb, tc)
    s2 = {"result": verdict(sum(v.values()) == 0), "old_primary": pr, "new_primary": sb, "epoch": f"{e0} -> {p['epoch']}", "detect_seconds": detect,
          "promote_seconds": p["seconds"], "old_primary_after_commit": v, "old_primary_agent_rejections_after_commit": len(act["agent_rejected"]),
          "first_last_seconds_after_commit": per, "new_primary_counts": counts(new), "observed_seconds": OBSERVE,
          "old_primary_active_before_partition": bool(base)}
    # ---- S3: heal; the old primary must now be fenced and silent
    t_heal = now()
    heal(pr, sb)
    time.sleep(30)
    st2 = rec_get()
    quiet = activity(st2, pr, t_heal + 10)
    ps = cstate(pr)
    rz = readyz(pr)
    api = api_mutation(pr)
    loops_silent = sum(violations(quiet).values()) == 0
    s3 = {"result": verdict(loops_silent and not rz.get("ready", True) and api["http"] == 503), "old_primary_role_in_its_own_db": ps and ps["role"], "readyz": {k: rz.get(k) for k in ("http", "ready", "fenced", "role")},
          "api_mutation": api, "side_effects_from_old_primary_20s_window_after_heal": violations(quiet), "agent_rejections_total_after_commit": len(activity(st2, pr, tc)["agent_rejected"])}
    return {"S2": s2, "S3": s3}


def s2b(ctx) -> dict:
    """S2b: like S2 but the old primary's work mix contains NO agent call (provider + notification only): nothing can ever tell it that it was superseded,
    so only its own lease/witness logic can stop it. Observed for 2 x OBSERVE seconds after the new epoch was committed."""
    pr, sb = ensure_pair()
    e0 = cstate(pr)["epoch"]
    stim(pr, webhooks=1)
    if not wait_for(lambda: activity(rec_get(), pr, now() - 60)["webhooks"], 60):
        return {"result": "INVALID", "why": f"{pr} was not active before the partition (no webhook reached the recorder): the test proves nothing"}
    partition(pr, sb)
    wait_for(lambda: psql(sb, "SELECT count(*) FROM pg_stat_wal_receiver WHERE status = 'streaming'") == "0", 90)
    rec_post("/config", {"delay_ms": 1000})
    p = promote(sb)
    if p["rc"]:
        heal(pr, sb)
        return {"result": "FAIL", "why": "promotion failed", "promote": p}
    tc = p["t_commit"]
    n = 0
    for _ in range(0, 2 * OBSERVE, 15):
        stim(pr, token_rotates=1, webhooks=1)
        rec_post("/probe", {"open": bool(n % 2)})
        n += 1
        time.sleep(15)
    rec_post("/probe", {"open": True})
    st = rec_get()
    act = activity(st, pr, tc)
    v = violations(act)
    last = {k: round(max(x["ts"] for x in act[k]) - tc, 1) for k in act if act[k]}
    heal(pr, sb)
    return {"result": verdict(sum(v.values()) == 0), "old_primary": pr, "new_primary": sb, "epoch": f"{e0} -> {p['epoch']}", "old_primary_after_commit": v,
            "last_call_seconds_after_commit": last, "observed_seconds": 2 * OBSERVE, "agent_rejections": len(act["agent_rejected"])}


def s4(ctx) -> dict:
    """S4: a long-running multi-step provider job is in flight on the primary at partition time, more jobs are queued; promote; nothing may run twice."""
    pr, sb = ensure_pair()
    e0 = cstate(pr)["epoch"]
    rec_post("/config", {"delay_ms": 2500})
    t0 = now()
    stim(pr, token_rotates=1, runbooks=2, backup_runs=1, webhooks=1)
    inflight = wait_for(lambda: len(activity(rec_get(), pr, t0)["provider_mutating"]) >= 2, 120)
    say(f"S4: job in flight on {pr} (provider steps so far: {len(activity(rec_get(), pr, t0)['provider_mutating'])})")
    time.sleep(3)         # let replication carry the 'running' state
    partition(pr, sb)
    wait_for(lambda: psql(sb, "SELECT count(*) FROM pg_stat_wal_receiver WHERE status = 'streaming'") == "0", 90)
    p = promote(sb)
    if p["rc"]:
        heal(pr, sb)
        return {"result": "FAIL", "why": "promotion failed", "promote": p}
    tc = p["t_commit"]
    time.sleep(OBSERVE + 30)
    st = rec_get()
    dup = duplicates({**st, "records": [r for r in st["records"] if r["ts"] > t0], "agent": [a for a in st["agent"] if a["ts"] > t0]})
    after = violations(activity(st, pr, tc))
    heal(pr, sb)
    ok = not dup["jobs_executed_by_both_controllers"] and not dup["steps_executed_twice"]       # S4 criterion: nothing runs twice; "after commit" activity is S2's criterion, reported here
    return {"result": verdict(ok), "old_primary": pr, "new_primary": sb, "epoch": f"{e0} -> {p['epoch']}", "in_flight_before_partition": bool(inflight),
            "duplicates": dup, "old_primary_after_commit": after, "old_primary_silent_after_commit": sum(after.values()) == 0, "new_primary_counts": counts(activity(st, sb, tc))}


def s5(ctx) -> dict:
    """S5 (review 6 L7): the agent restarts with an empty / corrupt epoch file -> fails closed; re-seeded from a doc signed by the current controller."""
    pr, sb = ensure_pair()
    nid = psql(pr, "SELECT id FROM nodes WHERE name = 'ha-node1'")
    sh(NODE, "systemctl stop ou-agent; cp -a /var/lib/ou-agent/epoch.json /root/epoch.json.keep; cp -a /var/lib/ou-agent/epoch.json.bak /root/epoch.json.bak.keep 2>/dev/null; "
             ": > /var/lib/ou-agent/epoch.json; : > /var/lib/ou-agent/epoch.json.bak; chown ou-agent:ou-agent /var/lib/ou-agent/epoch.json*; systemctl start ou-agent", check=True)
    time.sleep(2)
    t0 = now()
    stim(pr, runbooks=2)
    st = wait_for(lambda: (lambda s: s if [a for a in s["agent"] if a["ts"] > t0 and a.get("action") == "service.status"] else None)(rec_get()), 60) or rec_get()
    during = [a for a in st["agent"] if a["ts"] > t0 and a.get("action") == "service.status"]
    refused = bool(during) and all(a.get("code") == "epoch_state_corrupt" for a in during)
    # re-seed: the CURRENT controller signs an attest document; the operator applies it on the node console
    rc, doc = sh(pr, f"{PYENV} -m ics.cli epoch-attest --node {nid}")
    doc = doc.strip().splitlines()[-1]
    put(NODE, "/var/tmp/reseed.json", doc.encode(), "0644")
    rc2, out2 = sh(NODE, "cd /opt/ou-agent && setpriv --reuid=ou-agent --regid=ou-agent --clear-groups env PYTHONPATH=/opt/ou-agent python3 -m ou_agent reseed-epoch /var/tmp/reseed.json 2>&1; systemctl restart ou-agent")
    time.sleep(2)
    t1 = now()
    stim(pr, runbooks=1)
    st2 = wait_for(lambda: (lambda s: s if [a for a in s["agent"] if a["ts"] > t1 and a.get("action") == "service.status"] else None)(rec_get()), 60) or rec_get()
    after = [a for a in st2["agent"] if a["ts"] > t1 and a.get("action") == "service.status"]
    recovered = bool(after) and all(a.get("status") in ("ok", "error") and a.get("code") != "epoch_state_corrupt" for a in after)
    return {"result": verdict(refused and recovered), "requests_while_corrupt": [{"code": a.get("code"), "status": a.get("status")} for a in during],
            "reseed_output": out2.strip()[-200:], "requests_after_reseed": [{"code": a.get("code"), "status": a.get("status")} for a in after]}


def s6(ctx) -> dict:
    """S6: promotion is refused while the primary still streams; the documented forced path (--fence-old-dsn-file) fences the old primary in its own DB first."""
    pr, sb = ensure_pair()
    e0 = cstate(pr)["epoch"]
    refused = promote(sb)
    still_standby = cstate(sb)["in_recovery"] and cstate(pr)["epoch"] == e0 and cstate(pr)["role"] == "primary"
    rc, url = sh(sb, "grep ^ICS_DATABASE_URL= /etc/office-unbound/ics.env | cut -d= -f2-")
    dsn = re.sub(r"@[^:/]+:5432", f"@{IP[pr]}:5432", url.strip()) + "?sslmode=verify-full&sslrootcert=/etc/office-unbound/primary-ca.crt"
    put(sb, "/root/fence.dsn", dsn.encode(), "0600")
    stim(pr, runbooks=1, backup_runs=1, webhooks=1)
    time.sleep(8)
    p = promote(sb, "/root/fence.dsn")
    sh(sb, "rm -f /root/fence.dsn")
    if p["rc"]:
        return {"result": "FAIL", "why": "forced promotion failed", "refusal": {"rc": refused["rc"], "out": refused["out"][-300:]}, "promote": p}
    tc = p["t_commit"]
    t_fence = psql(pr, "SELECT extract(epoch from changed_at) FROM controller_state") if True else None
    stim(pr, runbooks=2, backup_runs=1, webhooks=2, token_rotates=1)         # the old primary is alive AND reachable: it is fenced through its database
    rec_post("/probe", {"open": False})
    time.sleep(OBSERVE)
    rec_post("/probe", {"open": True})
    st = rec_get()
    after = violations(activity(st, pr, tc + 3))                              # 3 s of grace: the worker notices the fenced row on its next pass
    ps, rz, api = cstate(pr), readyz(pr), api_mutation(pr)
    ok = (refused["rc"] != 0 and "still streaming" in refused["out"] and still_standby and sum(after.values()) == 0 and ps["role"] == "fenced"
          and not rz.get("ready", True) and api["http"] == 503)
    return {"result": verdict(ok), "refusal_while_streaming": {"rc": refused["rc"], "message": refused["out"].strip().splitlines()[-1][:200], "nothing_changed": bool(still_standby)},
            "forced_promotion": {"epoch": f"{e0} -> {p['epoch']}", "seconds": p["seconds"]}, "old_primary_role_in_its_db": ps["role"],
            "old_primary_after_commit_plus_3s": after, "readyz": {k: rz.get(k) for k in ("http", "ready", "fenced")}, "api_mutation": api}


def s7(ctx) -> dict:
    """S7: the old primary comes back from a BACKUP (lower epoch) while the new primary is serving: every egress must be refused."""
    pr, sb = ensure_pair()
    e0 = cstate(pr)["epoch"]
    sh(pr, "rm -f /var/tmp/ha-backup.dump; runuser -u postgres -- pg_dump -Fc -f /var/tmp/ha-backup.dump ics && chmod 644 /var/tmp/ha-backup.dump", check=True)
    sh(pr, "systemctl stop ics postgresql", check=True)
    p = promote(sb)
    if p["rc"]:
        return {"result": "FAIL", "why": "promotion failed", "promote": p}
    tc = p["t_commit"]
    # resurrect the old primary: fresh cluster state = the backup (epoch e0) restored over an empty database, role primary
    sh(pr, "systemctl start postgresql && runuser -u postgres -- bash -c 'pg_restore -d ics --clean --if-exists --no-owner --role=ics_owner /var/tmp/ha-backup.dump' >/var/tmp/restore.log 2>&1; "
           "psql() { runuser -u postgres -- psql -X -Atq -d ics -c \"$1\"; }; psql 'select 1'", check=True)
    st0 = cstate(pr)
    if not st0 or st0["epoch"] != e0 or st0["role"] != "primary":
        return {"result": "INVALID", "why": f"the restored database is not the backup (state {st0}, restore log: {sh(pr, 'tail -3 /var/tmp/restore.log')[1][-300:]})"}
    t_up = now()
    sh(pr, "systemctl start ics", check=True)
    stim(pr, runbooks=2, backup_runs=1, webhooks=2, token_rotates=1)
    rec_post("/probe", {"open": False})
    time.sleep(OBSERVE)
    rec_post("/probe", {"open": True})
    st = rec_get()
    act = activity(st, pr, t_up)
    v = violations(act)
    ps, rz, api = cstate(pr), readyz(pr), api_mutation(pr)
    return {"result": verdict(sum(v.values()) == 0), "restored_epoch": st0 and st0["epoch"], "current_epoch": p["epoch"], "old_primary_after_restart": v,
            "agent_rejections": len(act["agent_rejected"]), "agent_rejection_codes": sorted({a.get("code") for a in act["agent_rejected"]}),
            "old_primary_role_after": ps and ps["role"], "readyz": {k: rz.get(k) for k in ("http", "ready", "fenced")}, "api_mutation": api}


def s8(ctx) -> dict:
    """S8: the standby / witness disappears WITHOUT any network partition: a primary that cannot prove it is still the only one must self-fence after T
    (unless the audited standalone override is set). Observed for T + 30 s at the recorder."""
    pr, sb = ensure_pair()
    stim(pr, runbooks=1, webhooks=1)
    if not wait_for(lambda: activity(rec_get(), pr, now() - 60)["agent_executed"], 60):
        return {"result": "INVALID", "why": f"{pr} was not active before the standby was stopped: the test proves nothing"}
    t_down = now()
    sh(sb, "systemctl stop ics postgresql", check=True)
    say(f"S8: standby {sb} stopped; watching {pr} for {T_LEASE + 30} s")
    marks = []
    for i in range(0, T_LEASE + 30, 10):
        stim(pr, runbooks=1, webhooks=1, backup_runs=1)
        rec_post("/probe", {"open": bool(i % 20)})
        time.sleep(10)
        marks.append({"t": i + 10, "executed_in_last_10s": len(activity(rec_get(), pr, now() - 10)["agent_executed"]) + len(activity(rec_get(), pr, now() - 10)["webhooks"])})
    rec_post("/probe", {"open": True})
    st = rec_get()
    late = violations(activity(st, pr, t_down + T_LEASE + 10))                 # 10 s margin after T
    rz = readyz(pr)
    ps = cstate(pr)
    return {"result": verdict(sum(late.values()) == 0 and not rz.get("ready", True)), "standby_down_for": T_LEASE + 30, "T": T_LEASE, "side_effects_after_T_plus_10": late,
            "readyz": {k: rz.get(k) for k in ("http", "ready", "fenced")}, "role": ps and ps["role"], "timeline": marks,
            "note": "without a lease the primary keeps acting forever: this is the availability-preserving behaviour of the fixes-r7 code; BU's lease turns this into a self-fence"}


SCENARIOS = {"S1": s1, "S2b": s2b, "S2": s2_s3, "S3": s2_s3, "S4": s4, "S5": s5, "S6": s6, "S7": s7, "S8": s8}


def main(argv) -> int:
    cmd = argv[1] if len(argv) > 1 else "run"
    if cmd == "up":
        for m in (NODE, "ou-ha1", "ou-ha2"):
            start(m)
        return 0
    if cmd == "down":
        for m in ("ou-ha1", "ou-ha2", NODE):
            subprocess.run(["sudo", "machinectl", "poweroff", m], check=False)
        return 0
    if cmd == "deploy":
        subprocess.run([os.path.join(HERE, "push.sh"), "ou-ha1", "ou-ha2", NODE], check=True)
        for m in ("ou-ha1", "ou-ha2"):
            sh(m, "cd /root/src && rsync -a --exclude=tests --exclude=.venv ics/ /opt/office-unbound/ics/ics/ && rsync -a ics/agent/ /opt/office-unbound/ics/agent/ && "
                  "rsync -a ics/migrations/ /opt/office-unbound/ics/migrations/ && rsync -a ics/deploy/ /opt/office-unbound/ics/deploy/ && "
                  "install -m 0644 -o root -g ics /root/src/blueprints/lab/ha/ha_seed.py /opt/office-unbound/ics/scripts/ha_seed.py", check=True)
        sh(NODE, "bash /root/src/blueprints/lab/ha/node-setup.sh " + NODE_IP + " >/dev/null; systemctl restart ha-recorder", check=True)
        sh("ou-ha1", "systemctl restart ics-migrate ics 2>&1 | tail -2; systemctl restart ics")
        sh("ou-ha2", "systemctl restart ics")
        return 0
    names = argv[2:] or ["S1", "S2", "S2b", "S4", "S5", "S6", "S7", "S8"]
    if "S2" in names and "S3" in names:
        names.remove("S3")
    results: dict = {}
    for n in names:
        say(f"===== {n} =====")
        t = now()
        try:
            r = SCENARIOS[n](None)
        except Exception as e:  # noqa: BLE001
            r = {"result": "ERROR", "error": f"{type(e).__name__}: {e}"}
        if n in ("S2", "S3") and "S2" in r:
            results.update(r)
        else:
            results[n] = r
        say(f"{n} -> {json.dumps({k: v.get('result') if isinstance(v, dict) else v for k, v in (r.items() if 'S2' in r else [(n, r)])})}  ({now() - t:.0f} s)")
    results["_meta"] = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "git": subprocess.run(["git", "-C", REPO, "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip(),
                        "observe_seconds": OBSERVE, "lease_T": T_LEASE}
    out = os.environ.get("HA_EVIDENCE", EVIDENCE)
    json.dump(results, open(out, "w"), indent=1, default=str)
    print(json.dumps(results, indent=1, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
