#!/usr/bin/env python3
"""Lab acceptance (item 19): ONE user lifecycle through the RUNNING ICS (public API only), then measured effective access removal.

  setup      : accounts, enroll the OpenCloud node agent, register the customer stack (idm.stack.register, 2 approvers)   [idempotent]
  lifecycle  : create (plan -> 1 approver -> job) -> one-time enrollment token (reveal to requester only) -> the user sets their own password
               -> logins on Keycloak, OpenCloud WebDAV, IMAP, EWS, ActiveSync + SSO/offline refresh tokens, an OpenCloud app token (opencloudcmd style)
               and an IMAP session that stays open -> update_groups -> DISABLE (rotate_credentials=false: the user's REAL credentials stay as they were)
               -> every path is polled once per second and the seconds until refusal are recorded (target <= 60 s)
               -> enable (new enrollment) -> disable again with a canary credential (the ICS's own VERIFY measures) -> reconcile incl. an injected drift
               -> delete -> audit/secret hygiene checks
Prints a per-path table: PASS (refused within 60 s) / FAIL (measured seconds, or "NOT REVOKED"). Passwords/tokens are never printed.
usage: lab_user_lifecycle.py {setup|lifecycle|all|matrix|cleanup}
  matrix: Matrix (MAS) downstream. Needs OU_MATRIX_PYTHON (collab test venv) and a lab ICS instance of this code (ics/scripts/lab_ics_instance.py):
          OU_ICS_BASE=http://127.0.0.1:8099/api/v1 OU_DEMO_CREDS=<creds.json>. Measures when Synapse/MAS refuse the user's OWN Matrix access and refresh
          token after the lock, a new SSO login, unlock on enable, reconcile drift, and deactivation on delete.
"""
import json
import os
import re
import secrets
import ssl
import subprocess
import sys
import time

import httpx

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, "/opt/office-unbound/ics")
from ics import idprobe  # noqa: E402  (same prober the ICS uses for its VERIFY step)
import lab_monitoring_demo as demo  # noqa: E402  (Api, accounts, TOTP handling)

demo.BASE = os.environ.get("OU_ICS_BASE", demo.BASE)   # a lab ICS instance instead of the production service
BASE = demo.BASE
STACK = "lab-acme"
MAIL_DOMAIN = "ou-lab.internal"
TARGET = 60.0
HORIZON = 90.0


def log(m):
    demo.log(m)


def sh(machine, cmd, timeout=120, args=()):
    p = subprocess.run(["sudo", "-n", "systemd-run", "-M", machine, "--quiet", "--pipe", "--wait", *args, "/bin/bash", "-c", cmd],
                       capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout + p.stderr


def secret_file(machine, path):
    rc, out = sh(machine, f"cat {path}")
    if rc != 0:
        raise SystemExit(f"cannot read {path} in {machine}")
    return out.strip()


def api_login():
    """lab-op / lab-ap1 / lab-ap2; TOTP accepts +-1 step and refuses replays, so retry with the neighbouring steps."""
    creds = json.load(open(demo.STATE))
    out = []
    for n in ("lab-op", "lab-ap1", "lab-ap2"):
        for attempt in range(8):
            try:
                out.append(demo.Api(n, creds[n]["password"], creds[n]["secret"], (0, 1, -1)[attempt % 3]))
                break
            except httpx.HTTPStatusError:
                time.sleep(11)
        else:
            raise SystemExit(f"login of {n} failed")
    return out


def run_plan(op, approvers, action, params, expect_fail=False):
    r = op.post("plans", {"action": action, "params": params})
    need = r["approvals_required"] if r["status"] == "pending_approval" else 0
    job = r["job_id"]
    if r["status"] == "pending_approval":
        for ap in approvers[:need]:
            res = ap.post(f"plans/{r['plan_id']}/approve")
            job = res.get("job_id") or job
    for _ in range(400):
        j = op.get(f"jobs/{job}")
        if j["status"] in ("succeeded", "failed"):
            break
        time.sleep(0.5)
    ok = j["status"] == "succeeded"
    log(f"plan {action:24s} risk={r['risk']:6s} approvals={need} -> job {j['status']}" + ("" if ok else f" :: {json.dumps(j['error'])[:300]}"))
    if ok == expect_fail:
        raise SystemExit(f"unexpected outcome for {action}")
    return r["plan_id"], j


def mint_files_node(op, aps):
    nodes = {n["name"]: n for n in op.get("nodes")}
    if "ou-files1" in nodes:
        return nodes["ou-files1"]["id"]
    rc, out = sh("ou-files1", "rm -f /var/lib/ou-agent/trust.json; setpriv --reuid=ou-agent --regid=ou-agent --clear-groups env PYTHONPATH=/opt/ou-agent python3 -m ou_agent arm-enroll")
    tok = re.search(r"TOKEN[^:]*: (\S+)", out).group(1)
    fps = dict(re.findall(r"(tls_fingerprint_sha256|agent_key_fingerprint_sha256)=([0-9a-f]{64})", out))
    _, j = run_plan(op, aps, "node.enroll", {"name": "ou-files1", "address": "192.168.186.242", "port": 8443,
                                              "tls_fingerprint_sha256": fps["tls_fingerprint_sha256"],
                                              "agent_key_fingerprint_sha256": fps["agent_key_fingerprint_sha256"], "enrollment_token": tok})
    return j["result"]["node_id"]


def setup():
    demo.setup_accounts() if not os.path.exists(demo.STATE) else None
    op, a1, a2 = api_login()
    aps = [a1, a2]
    gw = {n["name"]: n for n in op.get("nodes")}["ou-gw1"]["id"]
    files = mint_files_node(op, aps)
    if any(s["name"] == STACK for s in op.get("identity/stacks")):
        log(f"stack {STACK} already registered")
        return
    id_ca = secret_file("ou-id1", "/etc/ou-lab/tls/ca.crt")
    base = "dc=ou-lab,dc=internal"
    run_plan(op, aps, "idm.stack.register", {
        "name": STACK, "ldap_url": "ldaps://ldap.ou-lab.internal", "ldap_bind_dn": f"cn=svc-ics,ou=system,{base}",
        "ldap_bind_password": secret_file("ou-id1", "/root/ou-lab-secrets/ldap-ics-password"),
        "ldap_people_dn": f"ou=people,{base}", "ldap_groups_dn": f"ou=groups,{base}", "mail_domain": MAIL_DOMAIN,
        "entitlement_group": "mail-users",
        "allowed_groups": ["mail-users", "opencloudUser", "opencloudGuest", "opencloudSpaceAdmin", "opencloudAdmin"],
        "privileged_groups": ["opencloudAdmin"],
        "kc_url": "https://auth.ou-lab.internal", "kc_realm": "ou-lab", "kc_client_id": "ou-ics",
        "kc_client_secret": secret_file("ou-id1", "/root/ou-lab-secrets/kc-ics-client-secret"),
        "kc_offline_clients": ["web", "OpenCloudDesktop", "OpenCloudAndroid", "OpenCloudIOS", "ou-lab-test"],
        "identity_ca_pem": id_ca, "files_url": "https://cloud.ou-lab.internal", "files_node_id": files, "gromox_node_id": gw,
        "mail_host": "gw1.ou-lab.internal", "mail_ca_pem": open("/etc/office-unbound/lab/gw1-ca.crt").read(),
        "probe_client_id": "ou-lab-test", "reconcile_interval_seconds": 120})
    log("stack registered")


# ---------------------------------------------------------------------------------------------------------------------------------------
def probe_cfg():
    return idprobe.ProbeConfig(kc_url="https://auth.ou-lab.internal", realm="ou-lab", client_id="ou-lab-test", files_url="https://cloud.ou-lab.internal",
                               mail_host="gw1.ou-lab.internal", kc_ca_pem=secret_file("ou-id1", "/etc/ou-lab/tls/ca.crt"),
                               files_ca_pem=secret_file("ou-id1", "/etc/ou-lab/tls/ca.crt"), mail_ca_pem=open("/etc/office-unbound/lab/gw1-ca.crt").read())


def app_token(uid, expiration="3h"):
    """opencloudcmd authenticates with Basic user:app-token (T07). Minted like the lab test does; never printed."""
    rc, out = sh("ou-files1", f"/usr/local/bin/opencloud auth-app create --user-name {uid} --expiration {expiration}")
    for line in out.splitlines():
        if line.strip().startswith("token:"):
            return line.split("token:", 1)[1].strip()
    raise SystemExit("could not mint an OpenCloud app token")


def enroll_user(op, plan_id, stack, uid, password):
    tok = op.post(f"identity/enrollments/{plan_id}/reveal")
    r = httpx.post(f"{BASE}/identity/enroll", json={"stack": stack, "uid": uid, "token": tok["token"], "password": password}, timeout=30)
    if r.status_code != 200:
        raise SystemExit(f"enrollment redemption failed: {r.status_code} {r.text[:120]}")
    r2 = httpx.post(f"{BASE}/identity/enroll", json={"stack": stack, "uid": uid, "token": tok["token"], "password": password}, timeout=30)
    return tok["token"], r2.status_code


def table(title, rows, lock_epoch):
    print(f"\n{title}")
    print(f"{'credential path':32s} {'result':8s} {'refused after':>14s}   note")
    fails = 0
    for name, o in rows.items():
        if o["status"] == "refused":
            secs = float(o["epoch"]) - float(lock_epoch) if lock_epoch and o.get("epoch") else float(o["seconds"])
            secs = max(0.0, secs)
            ok = secs <= TARGET
            print(f"{name:32s} {'PASS' if ok else 'FAIL':8s} {secs:12.1f} s")
            fails += 0 if ok else 1
        else:
            print(f"{name:32s} {'FAIL':8s} {'NOT REVOKED':>14s}   {o['status']} after {HORIZON:.0f} s of polling")
            fails += 1
    return fails


def lifecycle():
    op, a1, a2 = api_login()
    aps = [a1, a2]
    pc = probe_cfg()
    uid = "lc" + secrets.token_hex(3)
    mail = f"{uid}@{MAIL_DOMAIN}"
    pw1, pw2 = secrets.token_urlsafe(18), secrets.token_urlsafe(18)
    summary: dict = {}
    t_all = time.time()
    log(f"== lifecycle of {uid} in stack {STACK}")
    # ---- provision -------------------------------------------------------------------------------------------------------------------
    plan_id, j = run_plan(op, aps, "idm.user.create", {"stack": STACK, "uid": uid, "display_name": f"Lifecycle {uid}", "mail": mail,
                                                       "groups": ["opencloudUser"], "mailbox": True})
    res = j["result"]
    log("create steps: " + "; ".join(f"{s['step']} {s['ms']}ms" for s in res["steps"]))
    log(f"stable id (idm user id) {res['user_id']}  entryUUID {res['entry_uuid']}  opencloud_visible={res.get('opencloud_visible')}")
    assert a1.http.post(f"{BASE}/identity/enrollments/{plan_id}/reveal", headers={**a1.cookie, "X-CSRF-Token": a1.csrf}).status_code == 404, \
        "an approver (not the requester) must NOT get the enrollment token"
    log("approver cannot reveal the enrollment token (404): OK")
    token, second = enroll_user(op, plan_id, STACK, uid, pw1)
    log(f"user set their own password via the one-time token; second use of the token -> HTTP {second}; second reveal -> "
        f"{op.http.post(f'{BASE}/identity/enrollments/{plan_id}/reveal', headers={**op.cookie, 'X-CSRF-Token': op.csrf}).status_code}")
    # ---- logins ----------------------------------------------------------------------------------------------------------------------
    v, sso = idprobe.kc_password_grant(pc, uid, pw1)
    v2, off = idprobe.kc_password_grant(pc, uid, pw1, offline=True)
    imap_ok = idprobe.imap_login(pc, mail, pw1)
    sess = idprobe.imap_open(pc, mail, pw1)
    basics = {"Keycloak login": v, "Keycloak offline login": v2, "OpenCloud Graph /me (bearer)": idprobe.files_bearer(pc, sso.get("access_token", ""), uid),
              "OpenCloud WebDAV (bearer)": idprobe.files_webdav_bearer(pc, sso.get("access_token", ""), uid), "IMAP login": imap_ok,
              "IMAP session open": bool(sess and idprobe.imap_session_alive(sess)), "EWS GetFolder": idprobe.ews_getfolder(pc, mail, pw1),
              "ActiveSync OPTIONS": idprobe.activesync_options(pc, mail, pw1)}
    apptok = app_token(uid)
    basics["OpenCloud WebDAV (app token)"] = idprobe.files_webdav_basic(pc, uid, apptok)
    log("logins with the user's own password/tokens: " + json.dumps(basics))
    if not all(basics.values()):
        raise SystemExit("baseline logins failed; cannot measure revocation")
    # ---- change ----------------------------------------------------------------------------------------------------------------------
    _, j = run_plan(op, aps, "idm.user.update_groups", {"stack": STACK, "uid": uid, "add": ["opencloudGuest"], "remove": []})
    log("groups now: " + json.dumps(j["result"]["groups"]))
    _, j = run_plan(op, aps, "idm.user.update_groups", {"stack": STACK, "uid": uid, "add": [], "remove": ["opencloudGuest"]})
    r = op.post("plans", {"action": "idm.user.update_groups", "params": {"stack": STACK, "uid": uid, "add": ["opencloudAdmin"], "remove": []}})
    log(f"privileged group change -> risk={r['risk']} approvals_required={r['approvals_required']} (high = 2 approvers)")
    a2.post(f"plans/{r['plan_id']}/reject")  # not executed: only the risk tier was of interest
    # tokens issued before the next login are kept: they are the 'issued before disable' credentials
    sso2 = idprobe.kc_password_grant(pc, uid, pw1)[1]   # after the group change (needed because update_groups(remove) ends SSO sessions)
    off2 = idprobe.kc_password_grant(pc, uid, pw1, offline=True)[1]
    sess2 = idprobe.imap_open(pc, mail, pw1)
    try:
        sess.shutdown()
    except Exception:  # noqa: BLE001
        pass
    # ---- DISABLE with the real credentials untouched, independent measurement --------------------------------------------------------
    probes = {
        "keycloak password login": lambda: idprobe.kc_password_grant(pc, uid, pw1)[0],
        "keycloak SSO refresh token": lambda: idprobe.kc_refresh(pc, sso2["refresh_token"]),
        "keycloak offline refresh token": lambda: idprobe.kc_refresh(pc, off2["refresh_token"]),
        "opencloud Graph (access token)": lambda: idprobe.files_bearer(pc, sso2["access_token"], uid),
        "opencloud WebDAV (access token)": lambda: idprobe.files_webdav_bearer(pc, sso2["access_token"], uid),
        "opencloud WebDAV (app token)": lambda: idprobe.files_webdav_basic(pc, uid, apptok),
        "imap fresh login": lambda: idprobe.imap_login(pc, mail, pw1),
        "imap session opened BEFORE": lambda: idprobe.imap_session_alive(sess2),
        "ews GetFolder": lambda: idprobe.ews_getfolder(pc, mail, pw1),
        "activesync OPTIONS": lambda: idprobe.activesync_options(pc, mail, pw1),
    }
    pre = {k: f() for k, f in probes.items()}
    log("all paths accepted before the disable: " + json.dumps(pre))
    assert all(pre.values()), pre
    r = op.post("plans", {"action": "idm.user.disable", "params": {"stack": STACK, "uid": uid, "rotate_credentials": False,
                                                                    "verify_timeout_seconds": 60, "reason": "lab acceptance: leaver"}})
    log(f"disable plan risk={r['risk']} approvals_required={r['approvals_required']}; requester cannot approve own plan: "
        f"{op.http.post(f'{BASE}/plans/{r['plan_id']}/approve', headers={**op.cookie, 'X-CSRF-Token': op.csrf}).status_code}")
    t_approve = time.monotonic()
    appr = a1.post(f"plans/{r['plan_id']}/approve")
    log(f"approved by 1 approver -> {appr['status']}; polling every 1 s")
    measured = idprobe.measure(probes, t_approve, HORIZON)
    for _ in range(300):
        jd = op.get(f"jobs/{appr['job_id']}")
        if jd["status"] in ("succeeded", "failed"):
            break
        time.sleep(1)
    ver = (jd["result"] or {}).get("verification") if jd["status"] == "succeeded" else None
    lock_epoch = float((ver or {}).get("lock_applied_epoch") or 0) or None
    if not lock_epoch:
        row = [u for u in op.get("identity/users") if u["uid"] == uid][0]
        lock_epoch = float((row["last_verification"] or {}).get("lock_applied_epoch") or 0) or None
        ver = row["last_verification"]
    log(f"disable job {jd['status']}" + (f" :: {jd['error']}" if jd["status"] == "failed" else ""))
    for s in (jd["result"] or {}).get("steps", []):
        log(f"   step {s['step']:28s} {s['ms']:6d} ms" + (f"  (at +{s['at']} s after lock)" if "at" in s else ""))
    fails = table("A. independent measurement (user's REAL credentials/tokens issued before the disable; clock starts when the ICS locks the account)",
                  measured, lock_epoch)
    summary["independent_fail"] = fails
    summary["independent"] = {k: (round(o["epoch"] - lock_epoch, 1) if o["status"] == "refused" else "NOT REVOKED") for k, o in measured.items()}
    if ver:
        log("ICS VERIFY (state_only mode, rotate_credentials=false): overall=%s state=%s paths=%s" % (
            ver["overall"], json.dumps(ver["state"]), json.dumps({k: (o["status"], o["seconds"]) for k, o in ver["paths"].items()})))
    # ---- enable again (new one-time enrollment; old password dead) ---------------------------------------------------------------------
    plan_id2, j = run_plan(op, aps, "idm.user.enable", {"stack": STACK, "uid": uid, "reason": "lab: returning from leave"})
    log("enable steps: " + "; ".join(f"{s['step']} {s['ms']}ms" for s in j["result"]["steps"]))
    log(f"old password after enable (must be refused): imap={idprobe.imap_login(pc, mail, pw1)} kc={idprobe.kc_password_grant(pc, uid, pw1)[0]}")
    enroll_user(op, plan_id2, STACK, uid, pw2)
    log(f"re-enrolled with a new password: kc={idprobe.kc_password_grant(pc, uid, pw2)[0]} imap={idprobe.imap_login(pc, mail, pw2)} "
        f"ews={idprobe.ews_getfolder(pc, mail, pw2)}")
    resurrect = idprobe.files_webdav_basic(pc, uid, apptok)
    log(f"FINDING: OpenCloud app token minted BEFORE the first disable, after enable -> {'ACCEPTED AGAIN (token resurrected)' if resurrect else 'still refused'}")
    summary["app_token_resurrected_after_enable"] = bool(resurrect)
    # ---- disable again with the canary (ICS-side active VERIFY with baseline) ------------------------------------------------------------
    t1 = time.time()
    _, j = run_plan(op, aps, "idm.user.disable", {"stack": STACK, "uid": uid, "rotate_credentials": True, "verify_timeout_seconds": 45,
                                                  "reason": "lab: second disable, ICS-side canary probes"}, expect_fail=False)
    ver2 = j["result"]["verification"]
    summary["ics_verify"] = {k: (o["seconds"] if o["status"] == "refused" else o["status"]) for k, o in ver2["paths"].items()}
    table_rows = {k: {**o, "epoch": None} for k, o in ver2["paths"].items()}
    fails2 = table(f"B. the ICS's own VERIFY step (mode {ver2['mode']}: valid canary credential accepted before, probed every second after)", table_rows, None)
    log("   baseline accepted before revocation: " + json.dumps(ver2["state"]) + f" ; overall {ver2['overall']}")
    summary["ics_verify_fail"] = fails2
    # ---- reconcile + injected drift --------------------------------------------------------------------------------------------------
    _, j = run_plan(op, aps, "idm.reconcile", {"stack": STACK})
    log(f"reconcile (clean): critical={j['result']['critical']} findings={[(f['uid'], f['kind']) for f in j['result']['findings'] if f['uid'] == uid]}")
    rc, out = sh("ou-id1", f"/root/lab/spike-identity-files/kc/ldap-user.sh unlock {uid}")
    log("INJECTED DRIFT: unlocked the directory entry out-of-band (ICS says 'disabled')")
    _, j = run_plan(op, aps, "idm.reconcile", {"stack": STACK})
    drift = [(f["kind"], f["severity"], f["system"]) for f in j["result"]["findings"] if f["uid"] == uid]
    log(f"reconcile after drift: {drift}")
    still_locked = idprobe.kc_password_grant(pc, uid, pw2)[0]
    log(f"reconcile did NOT auto-fix: Keycloak password login now (user disabled in KC, unlocked in LDAP) -> {still_locked}")
    sh("ou-id1", f"/root/lab/spike-identity-files/kc/ldap-user.sh lock {uid}")
    summary["drift_detected"] = any(k == "ldap_not_locked" for k, _, _ in drift)
    # ---- delete ------------------------------------------------------------------------------------------------------------------------
    r = op.post("plans", {"action": "idm.user.delete", "params": {"stack": STACK, "uid": uid, "reason": "lab: end of lifecycle"}})
    log(f"delete plan risk={r['risk']} approvals_required={r['approvals_required']}")
    a1.post(f"plans/{r['plan_id']}/approve")
    jid = a2.post(f"plans/{r['plan_id']}/approve")["job_id"]
    for _ in range(200):
        jd = op.get(f"jobs/{jid}")
        if jd["status"] in ("succeeded", "failed"):
            break
        time.sleep(0.5)
    log(f"delete job {jd['status']}: " + (json.dumps({k: v for k, v in jd['result'].items() if k != 'steps'}) if jd["status"] == "succeeded" else str(jd["error"])))
    _, out = sh("ou-id1", f"ldapsearch -x -H ldaps://ldap.ou-lab.internal -D cn=admin,dc=ou-lab,dc=internal -y /root/ou-lab-secrets/ldap-admin-password -b ou=people,dc=ou-lab,dc=internal uid={uid} dn 2>&1 | grep -c '^dn:'")
    log(f"LDAP entries left for {uid}: {out.strip()}; gromox state: " + sh("ou-gw1", f"mysql -N email -e \"select address_status from users where username='{mail}'\"")[1].strip() + " (1 = suspended, mailbox data retained)")
    # ---- hygiene -------------------------------------------------------------------------------------------------------------------------
    aud = a1.get("audit?limit=500")
    blob = json.dumps(aud)
    leaks = [name for name, val in (("password1", pw1), ("password2", pw2), ("enrollment token", token), ("app token", apptok)) if val and val in blob]
    log(f"audit scan ({len(aud)} newest entries) for the user's passwords / enrollment token / app token: leaks={leaks or 'none'}")
    jobs_blob = json.dumps(op.get("jobs?limit=200"))
    log(f"job results scan: leaks={[n for n, v in (('pw1', pw1), ('pw2', pw2), ('token', token)) if v in jobs_blob] or 'none'}")
    log("audit chain: " + json.dumps(a1.get("audit/verify"))[:160])
    summary["audit_leaks"] = leaks
    total = int(summary["independent_fail"]) + int(summary["ics_verify_fail"])
    print("\nSUMMARY " + json.dumps(summary))
    print(f"RESULT {'PASS' if total == 0 else 'FAIL'}: {total} credential path(s) not refused within {TARGET:.0f} s; total run {time.time() - t_all:.0f} s")
    return 0 if total == 0 else 1


# ---- Matrix (MAS) downstream: stack without nodes, real Keycloak/LDAP/MAS, Matrix access measured independently -----------------------------------
MX_STACK = "lab-mx"
MX_PY = os.environ.get("OU_MATRIX_PYTHON")      # python with requests+playwright+PyJWT (the collab test venv)
MX_PROBE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "blueprints", "lab", "spike-collab", "tests", "matrix_probe.py")
_MX_TOK: dict = {}


def mx_run(args, stdin=None, timeout=240):
    p = subprocess.run([MX_PY, MX_PROBE, *args], input=stdin, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout.strip(), p.stderr.strip()[-300:]


def mx_json(out):
    """Last JSON object line of the helper's stdout (Playwright/MAS libraries may print other lines first)."""
    for line in reversed((out or "").splitlines()):
        if line.startswith("{"):
            return json.loads(line)
    return {}


def mx_secret():
    return secret_file("ou-chat1", "/root/ou-lab-secrets/mas-ics-client-secret")


def mas_admin(method, path):
    """Direct MAS admin call (only to inject/inspect drift in the lab run; the ICS uses its own vault-held credential)."""
    ctx = ssl.create_default_context(cadata=secret_file("ou-id1", "/etc/ou-lab/tls/ca.crt"))
    with httpx.Client(verify=ctx, timeout=20) as c:
        if "t" not in _MX_TOK:
            cid = secret_file("ou-chat1", "/root/ou-lab-secrets/mas-ics-client-id")
            r = c.post("https://mas.ou-lab.internal/oauth2/token", auth=(cid, mx_secret()), data={"grant_type": "client_credentials", "scope": "urn:mas:admin"})
            _MX_TOK["t"] = r.json()["access_token"]
        r = c.request(method, "https://mas.ou-lab.internal/api/admin/v1" + path, headers={"Authorization": "Bearer " + _MX_TOK["t"]})
        r.raise_for_status()
        return r


def setup_matrix(op, aps):
    if any(s["name"] == MX_STACK for s in op.get("identity/stacks")):
        log(f"stack {MX_STACK} already registered")
        return
    base = "dc=ou-lab,dc=internal"
    run_plan(op, aps, "idm.stack.register", {
        "name": MX_STACK, "ldap_url": "ldaps://ldap.ou-lab.internal", "ldap_bind_dn": f"cn=svc-ics,ou=system,{base}",
        "ldap_bind_password": secret_file("ou-id1", "/root/ou-lab-secrets/ldap-ics-password"),
        "ldap_people_dn": f"ou=people,{base}", "ldap_groups_dn": f"ou=groups,{base}", "mail_domain": MAIL_DOMAIN,
        "entitlement_group": "mail-users", "allowed_groups": ["mail-users", "opencloudUser"], "privileged_groups": [],
        "kc_url": "https://auth.ou-lab.internal", "kc_realm": "ou-lab", "kc_client_id": "ou-ics",
        "kc_client_secret": secret_file("ou-id1", "/root/ou-lab-secrets/kc-ics-client-secret"),
        "kc_offline_clients": [], "identity_ca_pem": secret_file("ou-id1", "/etc/ou-lab/tls/ca.crt"),
        "mas_url": "https://mas.ou-lab.internal", "mas_client_id": secret_file("ou-chat1", "/root/ou-lab-secrets/mas-ics-client-id"),
        "mas_client_secret": mx_secret(), "reconcile_interval_seconds": 0})
    log("stack registered (Keycloak + LDAP + MAS; no mail/files nodes)")


def matrix():
    """One user lifecycle with Matrix as a downstream. Measures, with the user's REAL Matrix tokens, how long after the ICS locks the account
    Synapse still honours the access token / MAS still accepts the refresh token; new SSO login after the lock; unlock; reconcile drift; delete."""
    if not MX_PY:
        raise SystemExit("set OU_MATRIX_PYTHON to a python with requests, playwright, PyJWT (the collab test venv)")
    op, a1, a2 = api_login()
    aps = [a1, a2]
    setup_matrix(op, aps)
    uid = "mx" + secrets.token_hex(3)
    pw1, pw2 = secrets.token_urlsafe(18), secrets.token_urlsafe(18)
    tmp = os.path.join(os.path.expanduser("~/.cache/ou-ics-inst"), uid)
    os.makedirs(tmp, mode=0o700, exist_ok=True)
    tokf, resf = os.path.join(tmp, "tokens.json"), os.path.join(tmp, "poll.json")
    res: dict = {}
    t_all = time.time()
    log(f"== Matrix lifecycle of {uid} in stack {MX_STACK}")
    plan_id, j = run_plan(op, aps, "idm.user.create", {"stack": MX_STACK, "uid": uid, "display_name": f"Matrix {uid}", "mail": f"{uid}@{MAIL_DOMAIN}",
                                                       "groups": ["opencloudUser"], "mailbox": False})
    enroll_user(op, plan_id, MX_STACK, uid, pw1)
    rc, out, err = mx_run(["login", uid, "--out", tokf], stdin=pw1 + "\n")
    log(f"Matrix SSO login (real browser, MAS -> Keycloak): rc={rc} {out} {err if rc else ''}")
    if rc:
        raise SystemExit("Matrix login failed")
    # ---- disable: poll the user's own Matrix tokens from before the lock, concurrently with the plan ---------------------------------------
    poll = subprocess.Popen([MX_PY, MX_PROBE, "poll", "--tokens", tokf, "--out", resf, "--horizon", "90"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)   # let the poller prime Synapse's introspection cache the way a live client does
    _, j = run_plan(op, aps, "idm.user.disable", {"stack": MX_STACK, "uid": uid, "rotate_credentials": False, "verify_timeout_seconds": 60,
                                                  "reason": "lab acceptance: leaver (Matrix)"})
    ver = j["result"]["verification"]
    lock = float(ver["lock_applied_epoch"])
    poll.wait(timeout=120)
    pr = json.load(open(resf))
    acc = round(pr["access_refused_epoch"] - lock, 1) if pr.get("access_refused_epoch") else None
    ref = round(pr["refresh_refused_epoch"] - lock, 1) if pr.get("refresh_refused_epoch") else None
    log("ICS steps: " + "; ".join(f"{s['step']} {s['ms']}ms" + (f" (+{s['at']}s)" if "at" in s else "") for s in j["result"]["steps"]))
    log(f"ICS VERIFY overall={ver['overall']} matrix state={json.dumps(ver['state'].get('matrix'))} matrix_access={json.dumps(ver['paths'].get('matrix_access'))}")
    res["disable"] = {"access_token_refused_s": acc, "refresh_token_refused_s": ref, "ics_verify": ver["overall"],
                      "ics_matrix_access_s": (ver["paths"].get("matrix_access") or {}).get("seconds")}
    rc, out, _ = mx_run(["relogin", uid], stdin=pw1 + "\n")
    res["disable"]["new_sso_login_after_lock"] = mx_json(out).get("login")
    log(f"after the lock: access token refused after {acc} s, refresh token refused after {ref} s (target {TARGET:.0f} s); "
        f"new SSO login possible: {res['disable']['new_sso_login_after_lock']}")
    # ---- enable: unlock, user re-enrols, Matrix works again ---------------------------------------------------------------------------------
    plan_id2, j = run_plan(op, aps, "idm.user.enable", {"stack": MX_STACK, "uid": uid, "reason": "lab: back from leave"})
    log("enable steps: " + "; ".join(f"{s['step']} {s['ms']}ms" for s in j["result"]["steps"]))
    enroll_user(op, plan_id2, MX_STACK, uid, pw2)
    rc, out, _ = mx_run(["relogin", uid], stdin=pw2 + "\n")
    res["enable"] = {"matrix_login_again": mx_json(out).get("login")}
    log(f"after enable + re-enrolment: Matrix SSO login possible again: {res['enable']['matrix_login_again']}")
    # ---- second disable, then injected drift (MAS unlocked out of band), reconcile -------------------------------------------------------------
    _, j = run_plan(op, aps, "idm.user.disable", {"stack": MX_STACK, "uid": uid, "rotate_credentials": False, "verify_timeout_seconds": 45,
                                                  "reason": "lab: second disable"})
    log("second disable: " + "; ".join(f"{s['step']} {s['ms']}ms sessions_ended={s.get('sessions_ended')}" for s in j["result"]["steps"] if s["step"].startswith("matrix"))
        + f" -> {j['result']['verification']['overall']}")
    mid = mas_admin("GET", f"/users/by-username/{uid}").json()["data"]["id"]
    mas_admin("POST", f"/users/{mid}/unlock")
    log("INJECTED DRIFT: unlocked the Matrix account out of band (ICS says 'disabled')")
    _, j = run_plan(op, aps, "idm.reconcile", {"stack": MX_STACK})
    drift = [(f["kind"], f["severity"]) for f in j["result"]["findings"] if f["uid"] == uid]
    log(f"reconcile after drift: {drift}")
    res["drift_detected"] = any(k == "matrix_not_locked" for k, _ in drift)
    # ---- delete -> MAS account deactivated ------------------------------------------------------------------------------------------------------
    _, j = run_plan(op, aps, "idm.user.delete", {"stack": MX_STACK, "uid": uid, "reason": "lab: end of Matrix lifecycle"})
    st = mas_admin("GET", f"/users/by-username/{uid}").json()["data"]["attributes"]
    res["delete"] = {"mas_deactivated": bool(st.get("deactivated_at"))}
    log("delete steps: " + "; ".join(f"{s['step']} {s['ms']}ms" for s in j["result"]["steps"]) + f"; MAS account deactivated={res['delete']['mas_deactivated']}")
    blob = json.dumps(a1.get("audit?limit=500")) + json.dumps(op.get("jobs?limit=200"))
    leaks = [n for n, v in (("password1", pw1), ("password2", pw2), ("mas secret", mx_secret())) if v and v in blob]
    log(f"audit + job result scan for passwords / the MAS client secret: leaks={leaks or 'none'}")
    ok = (acc is not None and acc <= TARGET and ref is not None and ref <= TARGET and ver["overall"] == "PASS" and res["disable"]["new_sso_login_after_lock"] is False
          and res["enable"]["matrix_login_again"] is True and res["drift_detected"] and res["delete"]["mas_deactivated"] and not leaks)
    print("\nSUMMARY " + json.dumps(res))
    print(f"RESULT {'PASS' if ok else 'FAIL'}: Matrix access refused within {TARGET:.0f} s of the lock; total run {time.time() - t_all:.0f} s")
    return 0 if ok else 1


def cleanup():
    """Delete earlier lab users (state disabled) of this script through normal 2-approver plans."""
    op, a1, a2 = api_login()
    for u in op.get("identity/users"):
        if u["stack"] in (STACK, MX_STACK) and u["uid"][:2] in ("lc", "mx") and u["state"] == "disabled":
            run_plan(op, [a1, a2], "idm.user.delete", {"stack": u["stack"], "uid": u["uid"], "reason": "lab cleanup of test user"})


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "all"
    if cmd == "cleanup":
        cleanup()
        sys.exit(0)
    if cmd == "matrix":     # Keycloak + LDAP + Matrix (MAS) lifecycle on a stack without nodes; against a lab ICS instance (OU_ICS_BASE, OU_DEMO_CREDS)
        sys.exit(matrix())
    if cmd in ("setup", "all"):
        setup()
    rc = lifecycle() if cmd in ("lifecycle", "all") else 0
    sys.exit(rc)
