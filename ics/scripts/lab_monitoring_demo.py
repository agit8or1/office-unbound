#!/usr/bin/env python3
"""Lab demonstration on ou-gw1 (acceptance tests 15+16): drives the RUNNING ICS (http://127.0.0.1:8088) through its public API only.

phase setup  : accounts (host CLI break-glass), alert channel, node enrollment (2 approvers), checks incl. bound remediation
phase failure: stop gromox-imap inside ou-gw1 (the one allowed manual disruption), then observe detection -> incident -> auto restart
               via the signed agent request -> verified recovery -> recovery email (read back over IMAP)
phase escalate: a check with a deliberately wrong port bound to a harmless `service.status` policy: stops at max attempts, escalates
Secrets are read from root-readable lab files and never printed. Usage: lab_monitoring_demo.py {setup|failure|escalate} [token-file]
"""
import datetime
import imaplib
import json
import re
import secrets
import ssl
import subprocess
import sys
import time

import httpx
import pyotp

BASE = "http://127.0.0.1:8088/api/v1"
CA = open("/etc/office-unbound/lab/gw1-ca.crt").read()
ICS_PY = "/opt/office-unbound/ics/.venv/bin/python"
STATE = "/tmp/ou-demo-creds.json"      # lab-only throwaway account passwords (mode 600), never printed
PW = dict(l.strip().split("=", 1) for l in open("/etc/office-unbound/lab/gw1-users.env") if l.startswith("OU_GW1_PW_"))
HOST = "gw1.ou-lab.internal"


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def log(msg):
    print(f"{now().strftime('%H:%M:%S.%f')[:-3]}Z  {msg}", flush=True)


class Api:
    def __init__(self, user, password, secret, step_offset):
        self.http = httpx.Client(timeout=30)
        code = pyotp.TOTP(secret).at(time.time() + 30 * step_offset)
        r = self.http.post(f"{BASE}/auth/login", json={"username": user, "password": password, "totp_code": code})
        r.raise_for_status()
        self.csrf = r.json()["csrf_token"]
        m = re.search(r"__Host-ics_session=([^;]+)", r.headers["set-cookie"])
        self.cookie = {"Cookie": f"__Host-ics_session={m.group(1)}"}
        self.user = user

    def get(self, p):
        r = self.http.get(f"{BASE}/{p}", headers=self.cookie)
        r.raise_for_status()
        return r.json()

    def post(self, p, body=None):
        r = self.http.post(f"{BASE}/{p}", json=body or {}, headers={**self.cookie, "X-CSRF-Token": self.csrf})
        if r.status_code >= 400:
            raise SystemExit(f"POST {p} -> {r.status_code} {r.text[:300]}")
        return r.json()


def cli(*args):
    return subprocess.run(["sudo", "-u", "ics", ICS_PY, "-m", "ics.cli", *args], cwd="/opt/office-unbound/ics", capture_output=True, text=True)


def setup_accounts():
    creds = {}
    for name, role in (("lab-op", "operator"), ("lab-ap1", "approver"), ("lab-ap2", "approver")):
        out = cli("create-admin", "--username", name, "--role", role)
        if out.returncode != 0 or "token" not in out.stdout:
            out = cli("issue-enrollment", "--username", name)
        token = [l for l in out.stdout.splitlines() if re.fullmatch(r"[A-Za-z0-9_-]{20,}", l.strip())][-1].strip()
        pw = secrets.token_urlsafe(18)
        r = httpx.post(f"{BASE}/auth/enroll", json={"username": name, "token": token, "password": pw})
        r.raise_for_status()
        secret = re.search(r"secret=([A-Z2-7]+)", r.json()["totp_provisioning_uri"]).group(1)
        httpx.post(f"{BASE}/auth/enroll/confirm", json={"username": name, "token": token, "totp_code": pyotp.TOTP(secret).now()}).raise_for_status()
        creds[name] = {"password": pw, "secret": secret}
    with open(STATE, "w") as f:
        json.dump(creds, f)
    import os
    os.chmod(STATE, 0o600)
    return creds


def login_all(offset):
    creds = json.load(open(STATE))
    return [Api(n, creds[n]["password"], creds[n]["secret"], offset) for n in ("lab-op", "lab-ap1", "lab-ap2")]


def submit(op, a1, a2, action, params, high=False):
    r = op.post("plans", {"action": action, "params": params})
    job = r["job_id"]
    if r["status"] == "pending_approval":
        assert high, (action, r)
        a1.post(f"plans/{r['plan_id']}/approve")
        job = a2.post(f"plans/{r['plan_id']}/approve")["job_id"]
    for _ in range(120):
        j = op.get(f"jobs/{job}")
        if j["status"] in ("succeeded", "failed"):
            break
        time.sleep(0.5)
    if j["status"] != "succeeded":
        raise SystemExit(f"{action}: job {j['status']} {json.dumps(j['error'])[:400]}")
    log(f"plan {action} -> job {j['status']} ({'2 approvers' if high else 'auto-approved low risk'})")
    return j["result"]


def mail_subjects():
    ctx = ssl.create_default_context(cadata=CA)
    m = imaplib.IMAP4_SSL(HOST, 993, ssl_context=ctx, timeout=15)
    m.login(f"grace@{HOST}", PW["OU_GW1_PW_grace"])
    m.select("INBOX", readonly=True)
    typ, data = m.search(None, "SUBJECT", "[OU-ICS]")
    out = []
    for num in data[0].split():
        _, d = m.fetch(num, "(INTERNALDATE BODY.PEEK[HEADER.FIELDS (SUBJECT)])")
        hdr = d[0][1].decode(errors="replace").replace("\r\n", " ").strip()
        out.append((num.decode(), hdr, re.search(r'INTERNALDATE "([^"]+)"', d[0][0].decode()).group(1)))
    m.logout()
    return out


def setup(token_file):
    creds = setup_accounts()
    op, a1, a2 = login_all(1)
    log("accounts lab-op (operator), lab-ap1, lab-ap2 (approvers) ready")
    ch = submit(op, a1, a2, "alert_channel.create", {
        "name": "mail-grace", "kind": "email", "config": {
            "host": HOST, "port": 25, "tls": "starttls", "ca_pem": CA, "from_addr": f"ics-alerts@{HOST}", "to_addrs": [f"grace@{HOST}"]}}, high=True)
    submit(op, a1, a2, "alert_channel.test", {"channel_id": ch["channel_id"]})
    tok = [l for l in open(token_file).read().splitlines() if l.startswith("ENROLLMENT TOKEN")][0].split(": ")[1].strip()
    fps = dict(l.split("=") for l in open(token_file).read().splitlines() if l.startswith(("tls_fingerprint", "agent_key_fingerprint")))
    node = submit(op, a1, a2, "node.enroll", {"name": "ou-gw1", "address": "192.168.186.218", "port": 8443,
                                              "tls_fingerprint_sha256": fps["tls_fingerprint_sha256"],
                                              "agent_key_fingerprint_sha256": fps["agent_key_fingerprint_sha256"], "enrollment_token": tok}, high=True)
    log(f"node ou-gw1 enrolled; agent allowlist: {json.dumps(node['capabilities'])}")
    nid = node["node_id"]
    mon_pw = PW["OU_GW1_PW_frank"]
    base = {"interval_seconds": 10, "recover_threshold": 2}
    imap_rem = {"node_id": nid, "runbook": "service.restart", "unit": "gromox-imap", "mode": "auto", "max_attempts": 3,
                "window_seconds": 900, "backoff_seconds": 10, "verify_timeout_seconds": 45}
    submit(op, a1, a2, "check.create", {**base, "name": "gw1-imap-login", "kind": "imap_login", "fail_threshold": 3, "password": mon_pw,
                                        "config": {"host": HOST, "port": 993, "username": f"frank@{HOST}", "ca_pem": CA}, "remediation": imap_rem})
    submit(op, a1, a2, "check.create", {**base, "name": "gw1-ews-getfolder", "kind": "ews_getfolder", "fail_threshold": 3, "password": mon_pw,
                                        "config": {"url": f"https://{HOST}/EWS/Exchange.asmx", "username": f"frank@{HOST}", "ca_pem": CA}})
    submit(op, a1, a2, "check.create", {**base, "name": "gw1-web-http", "kind": "http", "fail_threshold": 3,
                                        "config": {"url": f"https://{HOST}/web/", "ca_pem": CA, "expect_status": 200, "warn_latency_ms": 3000}})
    submit(op, a1, a2, "check.create", {**base, "name": "gw1-imaps-cert", "kind": "tcp_tls", "fail_threshold": 2,
                                        "config": {"host": HOST, "port": 993, "ca_pem": CA, "warn_days": 21, "crit_days": 7}})
    submit(op, a1, a2, "check.create", {**base, "name": "gw1-smtp-banner", "kind": "smtp_banner", "fail_threshold": 3,
                                        "config": {"host": HOST, "port": 25, "banner_contains": "ESMTP"}})
    log("checks created; waiting for all to report")
    for _ in range(60):
        st = {c["name"]: c["state"] for c in op.get("checks")}
        if len(st) >= 5 and all(v == "ok" for k, v in st.items() if k.startswith("gw1-") and k != "gw1-wrong-port"):
            break
        time.sleep(2)
    log("check states: " + json.dumps(st))


def failure():
    op, a1, a2 = login_all(0)
    base = {m[0] for m in mail_subjects()}
    cs = {c["name"]: c for c in op.get("checks")}
    assert cs["gw1-imap-login"]["state"] == "ok", "imap check not ok before the test"
    log("BASELINE all ok; stopping gromox-imap inside ou-gw1 (simulated failure)")
    t0 = time.time()
    r = subprocess.run(["sudo", "systemd-run", "-M", "ou-gw1", "--wait", "-P", "systemctl", "stop", "gromox-imap"], capture_output=True, text=True)
    t_stop = time.time()
    log(f"T0 gromox-imap stopped (rc={r.returncode})")
    seen = {}
    deadline = time.time() + 240
    while time.time() < deadline:
        c = {x["name"]: x for x in op.get("checks")}["gw1-imap-login"]
        inc = [i for i in op.get("incidents") if i["check_name"] == "gw1-imap-login"]
        t = time.time() - t_stop
        for key, cond in (("check_critical", c["state"] == "critical"), ("incident_open", bool(inc)),
                          ("attempt_created", bool(op.get(f"checks/{c['id']}/remediation"))),
                          ("recovered_state_ok", "check_critical" in seen and c["state"] == "ok"),
                          ("incident_recovered", bool(inc) and inc[0]["status"] == "recovered")):
            if cond and key not in seen:
                seen[key] = t
                log(f"+{t:6.1f}s {key}")
        if "incident_recovered" in seen:
            break
        time.sleep(0.5)
    time.sleep(1)
    # other checks must have stayed ok (only the imap service was stopped)
    log("final states: " + json.dumps({x["name"]: x["state"] for x in op.get("checks")}))
    inc = [i for i in op.get("incidents?status=recovered") if i["check_name"] == "gw1-imap-login"][0]
    det = op.get(f"incidents/{inc['id']}")
    log("incident opened_at=%s recovered_at=%s" % (inc["opened_at"], inc["recovered_at"]))
    for a in det["remediation"]:
        log(f"remediation attempt #{a['attempt_no']} {a['runbook']} status={a['status']} verified={a['verified']} at={a['at']} finished={a['finished_at']} job={a['job_id']}")
        j = op.get(f"jobs/{a['job_id']}")
        log(f"  job started={j['started_at']} finished={j['finished_at']} result.verified={j['result'].get('verified')} :: {j['result'].get('verification')}")
        log(f"  agent result: {json.dumps(j['result'].get('agent_result'))}")
    # email receipt over IMAP
    got = {}
    for _ in range(60):
        for num, subj, idate in mail_subjects():
            if num not in base:
                got[num] = (subj, idate, time.time() - t_stop)
        if any("RECOVERED" in s for s, _, _ in got.values()):
            break
        time.sleep(2)
    for num, (subj, idate, t) in sorted(got.items()):
        log(f"EMAIL via IMAP (grace@): {subj}  internaldate={idate}")
    log("notification rows: " + json.dumps([(n["event"], n["status"], n["sent_at"]) for n in det["notifications"]]))
    print("SUMMARY", json.dumps({k: round(v, 1) for k, v in seen.items()}), flush=True)
    return seen


def escalate():
    op, a1, a2 = login_all(0)
    nid = op.get("nodes")[0]["id"]
    rem = {"node_id": nid, "runbook": "service.status", "unit": "nginx", "mode": "auto", "max_attempts": 3, "window_seconds": 900,
           "backoff_seconds": 5, "verify_timeout_seconds": 0}
    submit(op, a1, a2, "check.create", {"name": "gw1-wrong-port", "kind": "http", "interval_seconds": 10, "fail_threshold": 2, "recover_threshold": 2,
                                        "config": {"url": f"https://{HOST}:8444/", "ca_pem": CA, "timeout_seconds": 3}, "remediation": rem})
    t0 = time.time()
    seen = set()
    while time.time() - t0 < 240:
        c = {x["name"]: x for x in op.get("checks")}["gw1-wrong-port"]
        att = op.get(f"checks/{c['id']}/remediation")
        inc = [i for i in op.get("incidents") if i["check_name"] == "gw1-wrong-port"]
        for k, cond in (("critical", c["state"] == "critical"), ("incident", bool(inc)), ("attempt1", len(att) >= 1), ("attempt2", len(att) >= 2),
                        ("attempt3", len(att) >= 3), ("escalated", bool(inc) and inc[0]["escalated_at"])):
            if cond and k not in seen:
                seen.add(k)
                log(f"+{time.time() - t0:6.1f}s {k}")
        if "escalated" in seen:
            break
        time.sleep(0.5)
    log("waiting 60 s to prove no further attempts happen")
    time.sleep(60)
    c = {x["name"]: x for x in op.get("checks")}["gw1-wrong-port"]
    att = op.get(f"checks/{c['id']}/remediation")
    log("attempts after the wait: %d -> %s" % (len(att), json.dumps([(a["attempt_no"], a["status"], a["verified"]) for a in att])))
    inc = [i for i in op.get("incidents") if i["check_name"] == "gw1-wrong-port"][0]
    # clean up the demo check: ack + disable
    submit(op, a1, a2, "incident.ack", {"incident_id": inc["id"], "note": "demo: expected escalation"})
    submit(op, a1, a2, "check.set_enabled", {"check_id": c["id"], "enabled": False})
    time.sleep(8)
    for num, subj, idate in mail_subjects()[-4:]:
        log(f"EMAIL via IMAP: {subj} internaldate={idate}")


if __name__ == "__main__":
    {"setup": lambda: setup(sys.argv[2]), "failure": failure, "escalate": escalate}[sys.argv[1]]()
