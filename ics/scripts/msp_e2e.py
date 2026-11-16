"""End-to-end run of the MSP API against a DEV ICS on 127.0.0.1:8125 with the throw-away database ics_test_f (never production).

    python scripts/msp_e2e.py            (from ics/, with the project venv)

Starts uvicorn as a child process with its own temp vault/audit keys and the in-process worker, rebuilds the ics_test_f schema, creates
console accounts, then drives everything through the REAL HTTP API with the reference client (clients/msp-python): approved key creation ->
signed requests -> customer plan (approved by two humans, executed by the worker) -> deployment plan preview -> user plan -> webhook
delivery, plus signature/replay/idempotency probes. The Proxmox endpoint and the identity stack are database rows (no real infrastructure).
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pyotp
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text

HERE = os.path.dirname(os.path.abspath(__file__))
ICS_DIR = os.path.join(HERE, "..")
sys.path.insert(0, ICS_DIR)
sys.path.insert(0, os.path.join(ICS_DIR, "..", "clients", "msp-python"))

from ics import auth  # noqa: E402
from ics.config import Settings, _load_env_file  # noqa: E402
from ics.runtime import Runtime  # noqa: E402
from ou_msp import MspApiError, MspClient, verify_signature  # noqa: E402

PORT, HOOK_PORT, DB = 8125, 8126, "ics_test_f"
BASE = f"http://127.0.0.1:{PORT}"
t0 = time.time()


def say(msg: str) -> None:
    print(f"[{time.time() - t0:6.1f}s] {msg}", flush=True)


def swap_db(url: str) -> str:
    assert re.search(r"/ics_test(_[a-z0-9]{1,12})?$", url), "refusing a non-test database"
    return re.sub(r"/ics_test(_[a-z0-9]{1,12})?$", f"/{DB}", url)


def main() -> int:
    env = _load_env_file(os.environ.get("ICS_TEST_ENV_FILE", "/etc/office-unbound/ics-test.env"))
    app_url, owner_url = swap_db(env["ICS_TEST_DATABASE_URL"]), swap_db(env["ICS_TEST_OWNER_DATABASE_URL"])
    owner = create_engine(owner_url, isolation_level="AUTOCOMMIT")
    with owner.connect() as c:
        busy = c.execute(text("SELECT count(*) FROM pg_stat_activity WHERE datname = :d AND pid <> pg_backend_pid()"), {"d": DB}).scalar()
        if busy:
            say(f"{DB} is in use by {busy} other connection(s); refusing to touch it")
            return 2
        c.execute(text("DROP SCHEMA public CASCADE"))
        c.execute(text("CREATE SCHEMA public"))
    cfg = Config(os.path.join(ICS_DIR, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(ICS_DIR, "migrations"))
    cfg.attributes["url"], cfg.attributes["app_role"] = owner_url, "ics_test_app"
    command.upgrade(cfg, "head")
    say(f"schema rebuilt in {DB} (alembic head)")

    keys = tempfile.mkdtemp(prefix="msp-e2e-keys-")
    for n in ("vault.key", "audit.key"):
        with open(os.path.join(keys, n), "wb") as f:
            f.write(os.urandom(32))
        os.chmod(os.path.join(keys, n), 0o600)
    srv_env = {**os.environ, "ICS_ENV_FILE": "/nonexistent", "ICS_DATABASE_URL": app_url, "ICS_VAULT_KEY_FILE": os.path.join(keys, "vault.key"),
               "ICS_AUDIT_KEY_FILE": os.path.join(keys, "audit.key"), "ICS_COOKIE_SECURE": "false", "ICS_WORKER_ENABLED": "true",
               "ICS_MONITOR_ENABLED": "false", "ICS_ALLOW_LOOPBACK_ENDPOINTS": "true"}
    server = subprocess.Popen([sys.executable, "-m", "uvicorn", "--factory", "ics.main:create_app", "--host", "127.0.0.1", "--port", str(PORT),
                               "--log-level", "warning"], cwd=ICS_DIR, env=srv_env)
    try:
        for _ in range(60):
            try:
                if urllib.request.urlopen(BASE + "/healthz", timeout=2).status == 200:
                    break
            except OSError:
                time.sleep(0.5)
        else:
            say("server did not come up")
            return 1
        say(f"dev ICS up on {BASE} (db {DB}, worker on)")
        return scenario(app_url, srv_env, keys)
    finally:
        server.terminate()
        try:
            server.wait(15)
        except subprocess.TimeoutExpired:
            server.kill()
        say("dev ICS stopped")


def scenario(app_url: str, srv_env: dict, keys: str) -> int:
    rt = Runtime(Settings(database_url=app_url, vault_key_file=os.path.join(keys, "vault.key"), audit_key_file=os.path.join(keys, "audit.key"),
                          worker_enabled=False, cookie_secure=False))
    steps: dict[str, int] = {}

    def mk(username, role):
        with rt.session() as db:
            auth.create_invite(db, rt, username, role, actor="e2e")
            tok = auth.issue_enrollment_token(db, rt, username, actor="e2e")
            uri = auth.enroll_begin(db, rt, username, tok, "correct horse battery", "127.0.0.1")
            secret = re.search(r"secret=([A-Z2-7]+)", uri).group(1)
            steps[username] = int(time.time() // 30)
            auth.enroll_confirm(db, rt, username, tok, pyotp.TOTP(secret).at(steps[username] * 30), "127.0.0.1")
        return {"u": username, "secret": secret}

    class Console:
        def __init__(self, acct):
            self.acct, self.c, self.h = acct, httpx.Client(base_url=BASE), {}
            steps[acct["u"]] += 1
            r = self.c.post("/api/v1/auth/login", json={"username": acct["u"], "password": "correct horse battery",
                                                         "totp_code": pyotp.TOTP(acct["secret"]).at(steps[acct["u"]] * 30)})
            assert r.status_code == 200, r.text
            self.h = {"X-CSRF-Token": r.json()["csrf_token"]}

        def post(self, path, body=None):
            r = self.c.post("/api/v1" + path, json=body, headers=self.h)
            assert r.status_code in (200, 201), (path, r.status_code, r.text)
            return r.json()

    adm, ap1, ap2 = Console(mk("e2e-admin", "admin")), Console(mk("e2e-ap1", "approver")), Console(mk("e2e-ap2", "approver"))
    say("console accounts ready (1 admin, 2 approvers; TOTP enrolled)")

    # ---- 1. API client created by an approved plan, key shown once --------------------------------------------------------------
    plan = adm.post("/plans", {"action": "msp.client.create", "params": {"name": "e2e-integration", "all_customers": True,
                                                                          "permissions": ["view", "plan"], "rate_limit_per_minute": 300}})
    say(f"msp.client.create plan {plan['plan_id'][:8]}: status={plan['status']} risk={plan['risk']} approvals_required={plan['approvals_required']}")
    ap1.post(f"/plans/{plan['plan_id']}/approve")
    ap2.post(f"/plans/{plan['plan_id']}/approve")
    wait_job(adm, plan["plan_id"])
    key = adm.post(f"/msp/clients/{plan['plan_id']}/reveal")
    r2 = adm.c.post(f"/api/v1/msp/clients/{plan['plan_id']}/reveal", headers=adm.h)
    say(f"key revealed once: client_id={key['client_id']} secret=mspk_*** (second reveal -> HTTP {r2.status_code})")

    api = MspClient(BASE, key["client_id"], key["secret"])
    say("GET /me -> " + json.dumps(api.me()))

    # ---- 2. webhook receiver + subscription ---------------------------------------------------------------------------------------
    received: list[dict] = []
    wh_secret: dict = {}

    class Hook(BaseHTTPRequestHandler):
        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            ok = verify_signature(wh_secret["s"], raw, self.headers.get("X-MSP-Signature", ""))
            received.append({"signature_ok": ok, "event": json.loads(raw), "attempt": self.headers.get("X-MSP-Delivery-Attempt")})
            self.send_response(204 if ok else 401)
            self.end_headers()

        def log_message(self, *a):
            pass

    hook = HTTPServer(("127.0.0.1", HOOK_PORT), Hook)
    threading.Thread(target=hook.serve_forever, daemon=True).start()
    wh = api.create_webhook(f"http://127.0.0.1:{HOOK_PORT}/hook", ["plan.approved", "plan.rejected", "job.completed", "job.failed"], "e2e")
    wh_secret["s"] = wh["secret"]
    say(f"webhook {wh['id'][:8]} registered (secret shown once: whsec_***)")

    # ---- 3. customer through the API ------------------------------------------------------------------------------------------------
    cust_plan = api.create_customer(name="E2E Example GmbH", external_ref="crm-e2e-1", contact_email="it@e2e.example")
    say(f"POST /customers -> plan {cust_plan['plan_id'][:8]} {cust_plan['status']} risk={cust_plan['risk']} approvals_required={cust_plan['approvals_required']}")
    replay = MspClient(BASE, key["client_id"], key["secret"]).request("POST", "/customers", body={"name": "E2E Example GmbH", "external_ref": "crm-e2e-1",
                                                                                                    "contact_email": "it@e2e.example"},
                                                                      idempotency_key="e2e-replay-key-1")
    again = MspClient(BASE, key["client_id"], key["secret"]).request("POST", "/customers", body={"name": "E2E Example GmbH", "external_ref": "crm-e2e-1",
                                                                                                   "contact_email": "it@e2e.example"},
                                                                     idempotency_key="e2e-replay-key-1")
    say(f"idempotent replay: same plan id = {replay['plan_id'] == again['plan_id']}")
    try:
        MspClient(BASE, key["client_id"], key["secret"]).request("POST", "/customers", body={"name": "Different"}, idempotency_key="e2e-replay-key-1")
    except MspApiError as e:
        say(f"same key, different body -> HTTP {e.status} {e.code}")
    ap1.post(f"/plans/{cust_plan['plan_id']}/approve")
    ap2.post(f"/plans/{cust_plan['plan_id']}/approve")
    done = api.wait_for_plan(cust_plan["plan_id"], timeout=60, interval=0.5)
    cid = done["execution"]["result"]["customer_id"]
    c = api.get_customer(cid)
    say(f"customer plan executed: {done['execution']['status']} -> customer {cid[:8]} slug={c['slug']} external_ref={c['external_ref']}")
    # the duplicate pending plans created above must not execute: reject them
    for p in api.plans(status="pending_approval")["items"]:
        if p["plan_id"] != cust_plan["plan_id"] and p["action"] == "customer.create":
            ap1.post(f"/plans/{p['plan_id']}/reject")

    # ---- 4. deployment plan preview -------------------------------------------------------------------------------------------------
    with rt.session() as db:
        eid = db.execute(text("INSERT INTO endpoints (name, type, base_url, token_id, token_secret_enc, fingerprint_sha256, customer_id) "
                              "VALUES ('e2e-lab', 'proxmox', 'https://pve.invalid:8006', 'u@pve!t', :s, :f, :c) RETURNING id"),
                         {"s": b"x", "f": "ab" * 32, "c": cid}).scalar()
        GiB = 1024 ** 3
        data = {"nodes": [{"node": f"pve{i}", "status": "online", "info": {"maxcpu": 64, "maxmem": 256 * GiB}, "qemu": [], "lxc": [],
                           "storage": [{"storage": "local-lvm", "content": "images", "avail": 4000 * GiB, "active": 1}],
                           "network": [{"iface": "vmbr0", "type": "bridge"}]} for i in (1, 2)]}
        db.execute(text("INSERT INTO inventory_snapshots (endpoint_id, collected_at, data) VALUES (:e, now(), CAST(:d AS jsonb))"), {"e": str(eid), "d": json.dumps(data)})
        db.commit()
    spec = {"deployment_id": "e2e-prod", "profile": "small", "users": 40, "domain": "e2e.example", "endpoint": "e2e-lab", "pool": "e2e"}
    pv = api.preview_deployment(cid, spec)
    say(f"deployment preview: executable={pv['executable']} vms={pv['consumption']['vms']} cores={pv['consumption']['cores']} "
        f"memory_mb={pv['consumption']['memory_mb']} disk_gb={pv['consumption']['disk_gb']} plan_hash={pv['plan_hash'][:12]} "
        f"errors={[e['code'] for e in pv['errors']]} warnings={[e['code'] for e in pv['warnings']]}")
    if pv["executable"]:
        dp = api.create_deployment(cid, spec, pv["plan_hash"])
        say(f"deployment plan submitted: {dp['plan_id'][:8]} {dp['status']} risk={dp['risk']}")
    else:
        say("not submitting the deployment: the catalog's OCI digests are not pinned in this dev build (executable=false is the engine's own refusal)")

    # ---- 5. user plan -----------------------------------------------------------------------------------------------------------------
    with rt.session() as db:
        db.execute(text("INSERT INTO idm_stacks (name, config, secret_enc, customer_id) VALUES ('e2e-idm', CAST(:c AS jsonb), :s, :cu)"),
                   {"c": json.dumps({"mail_domain": "e2e.example", "allowed_groups": ["mail-users", "staff", "admins"], "entitlement_group": "mail-users",
                                     "privileged_groups": ["admins"]}), "s": b"x", "cu": cid})
        db.commit()
    up = api.create_user(cid, uid="alice", display_name="Alice Example", mail="alice@e2e.example", groups=["staff"])
    say(f"POST /customers/{{id}}/users -> plan {up['plan_id'][:8]} {up['status']} risk={up['risk']} approvals_required={up['approvals_required']}")
    ap1.post(f"/plans/{up['plan_id']}/reject")
    say(f"user plan rejected by an approver -> API view: {api.plan(up['plan_id'])['status']}")

    # ---- 6. probes ------------------------------------------------------------------------------------------------------------------------
    bad = MspClient(BASE, key["client_id"], "mspk_" + "0" * 43, max_retries=0)
    try:
        bad.me()
    except MspApiError as e:
        say(f"wrong key -> HTTP {e.status} {e.code}")
    ts, nonce = str(int(time.time())), "e2e-nonce-" + "x" * 12
    from ou_msp import sign
    hdr = {"X-MSP-Client": key["client_id"], "X-MSP-Timestamp": ts, "X-MSP-Nonce": nonce,
           "X-MSP-Signature": sign(key["secret"], "GET", "/api/msp/v1/me", ts, nonce, b"")}
    codes = []
    for _ in range(2):
        try:
            urllib.request.urlopen(urllib.request.Request(BASE + "/api/msp/v1/me", headers=hdr), timeout=5)
            codes.append(200)
        except urllib.error.HTTPError as e:
            codes.append((e.code, json.loads(e.read())["error"]["code"]))
    say(f"identical signed request sent twice -> {codes}")
    old = str(int(time.time()) - 600)
    hdr2 = {**hdr, "X-MSP-Timestamp": old, "X-MSP-Nonce": "e2e-nonce-old-" + "y" * 8, "X-MSP-Signature": sign(key["secret"], "GET", "/api/msp/v1/me", old, "e2e-nonce-old-" + "y" * 8, b"")}
    try:
        urllib.request.urlopen(urllib.request.Request(BASE + "/api/msp/v1/me", headers=hdr2), timeout=5)
    except urllib.error.HTTPError as e:
        say(f"request signed 600 s in the past -> HTTP {e.code} {json.loads(e.read())['error']['code']}")

    # ---- 7. webhooks arrived ----------------------------------------------------------------------------------------------------------------
    deadline = time.time() + 30
    while time.time() < deadline and not {"plan.approved", "job.completed", "plan.rejected"} <= {r["event"]["type"] for r in received}:
        time.sleep(1)
    say("webhook deliveries received: " + ", ".join(f"{r['event']['type']}(sig_ok={r['signature_ok']},attempt={r['attempt']})" for r in received))
    ids = [r["event"]["id"] for r in received]
    say(f"event ids unique: {len(ids) == len(set(ids))}; feed: {[e['type'] for e in api.events()['items']]}")
    say("usage: " + json.dumps({k: v for k, v in api.usage(cid).items() if k in ("users", "mailboxes", "vm", "storage")}))
    with rt.session() as db:
        n = db.execute(text("SELECT count(*) FROM audit_events WHERE action = 'msp.request' AND actor_name = :a"), {"a": "msp:" + key["client_id"]}).scalar()
        f = db.execute(text("SELECT count(*) FROM audit_events WHERE action = 'msp.auth_failed'")).scalar()
        from ics import audit
        v = audit.verify_chain(db)
    say(f"audit: {n} msp.request rows for {key['client_id']}, {f} msp.auth_failed rows, chain ok={v['ok']} ({v['checked']} entries)")
    ok = bool(received) and all(r["signature_ok"] for r in received) and done["execution"]["status"] == "succeeded" and v["ok"]
    say("E2E " + ("PASSED" if ok else "FAILED"))
    return 0 if ok else 1


def wait_job(console, plan_id, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        for j in console.c.get("/api/v1/jobs", headers=console.h).json():
            if j["plan_id"] == plan_id and j["status"] in ("succeeded", "failed"):
                assert j["status"] == "succeeded", j
                return
        time.sleep(0.5)
    raise TimeoutError(plan_id)


if __name__ == "__main__":
    sys.exit(main())
