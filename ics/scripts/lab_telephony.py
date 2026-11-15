#!/usr/bin/env python3
"""Lab acceptance for telephony as an identity downstream, through a RUNNING lab ICS instance (public API only; never the production service).

  setup    : enrol the PBX node agent (ou-pbx2), register the customer stack `lab-tel` with pbx_node_id (idm.stack.register, 2 approvers)   [idempotent]
  run      : create a user with an extension (idm.user.create) -> two one-time SIP credentials through the ICS (native + desk; revealed once, second reveal 404)
             -> the native device registers (baresip over TLS+SRTP) and holds a LIVE CALL (echo test 600) while the desk credential is probed with REGISTER
             -> idm.user.disable. Measured from the moment the ICS applied the LDAP lock (verification.lock_applied_epoch, same host clock):
                  * first REGISTER refused for the user's previously valid credential
                  * the live call torn down on the PBX (channel gone)
                  * ICS-side VERIFY (pbx_access) seconds
             -> idm.user.enable (extension returns, old credentials do NOT) -> delete
  cleanup  : delete leftover lab users (disabled) of this script
Environment: OU_ICS_BASE (e.g. http://127.0.0.1:8121/api/v1), OU_DEMO_CREDS (creds.json of the lab instance), PBX_MACHINE (default ou-pbx2).
Credentials are never printed."""
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "blueprints", "telephony", "tests"))
import lab_user_lifecycle as lul  # noqa: E402  (Api login, plan runner, secret_file helpers)
from sip_probe import register  # noqa: E402

demo, log, sh, secret_file, run_plan = lul.demo, lul.log, lul.sh, lul.secret_file, lul.run_plan
STACK = "lab-tel"
MACHINE = os.environ.get("PBX_MACHINE", "ou-pbx2")
UID = "lt1dora"
EXT = "1030"
BASE_DN = "dc=ou-lab,dc=internal"
H = "http://127.0.0.1"
RESULTS: list = []


def check(name, ok, detail=""):
    RESULTS.append(bool(ok))
    log(f"{'PASS' if ok else 'FAIL'} {name}{(' - ' + str(detail)) if detail != '' else ''}")
    return ok


def pbx(cmd, timeout=60):
    return sh(MACHINE, cmd, timeout=timeout)[1]


def mint_pbx_node(op, aps):
    nodes = {n["name"]: n for n in op.get("nodes")}
    if MACHINE in nodes:
        return nodes[MACHINE]["id"]
    rc, out = sh(MACHINE, "rm -f /var/lib/ou-agent/trust.json; setpriv --reuid=ou-agent --regid=ou-agent --clear-groups env PYTHONPATH=/opt/ou-agent python3 -m ou_agent arm-enroll")
    tok = re.search(r"TOKEN[^:]*: (\S+)", out).group(1)
    fps = dict(re.findall(r"(tls_fingerprint_sha256|agent_key_fingerprint_sha256)=([0-9a-f]{64})", out))
    _, j = run_plan(op, aps, "node.enroll", {"name": MACHINE, "address": "192.168.186.247", "port": 8443,
                                              "tls_fingerprint_sha256": fps["tls_fingerprint_sha256"],
                                              "agent_key_fingerprint_sha256": fps["agent_key_fingerprint_sha256"], "enrollment_token": tok})
    return j["result"]["node_id"]


def setup():
    op, a1, a2 = lul.api_login()
    aps = [a1, a2]
    node = mint_pbx_node(op, aps)
    if any(s["name"] == STACK for s in op.get("identity/stacks")):
        log(f"stack {STACK} already registered")
        return
    run_plan(op, aps, "idm.stack.register", {
        "name": STACK, "ldap_url": "ldaps://ldap.ou-lab.internal", "ldap_bind_dn": f"cn=svc-ics,ou=system,{BASE_DN}",
        "ldap_bind_password": secret_file("ou-id1", "/root/ou-lab-secrets/ldap-ics-password"),
        "ldap_people_dn": f"ou=people,{BASE_DN}", "ldap_groups_dn": f"ou=groups,{BASE_DN}", "mail_domain": "ou-lab.internal",
        "entitlement_group": "mail-users", "allowed_groups": ["mail-users"], "privileged_groups": [],
        "kc_url": "https://auth.ou-lab.internal", "kc_realm": "ou-lab", "kc_client_id": "ou-ics",
        "kc_client_secret": secret_file("ou-id1", "/root/ou-lab-secrets/kc-ics-client-secret"), "kc_offline_clients": [],
        "identity_ca_pem": secret_file("ou-id1", "/etc/ou-lab/tls/ca.crt"), "pbx_node_id": node, "pbx_domain": "pbx.ou-lab.internal",
        "reconcile_interval_seconds": 0})
    log("stack registered")


def reveal(user_api, plan_id):
    r = user_api.http.post(f"{demo.BASE}/identity/sip-credentials/{plan_id}/reveal", headers={**user_api.cookie, "X-CSRF-Token": user_api.csrf})
    return r


def issue(op, aps, device):
    pid, job = run_plan(op, aps, "idm.user.issue_sip_credential", {"stack": STACK, "uid": UID, "device": device})
    assert "password" not in json.dumps(job), "password leaked into the job result"
    r = reveal(op, pid)
    check(f"{device}: credential revealed once to the requester", r.status_code == 200 and r.headers.get("cache-control") == "no-store")
    cred = r.json()
    check(f"{device}: second reveal refused (one-time)", reveal(op, pid).status_code == 404)
    return cred


def main():
    op, a1, a2 = lul.api_login()
    aps = [a1, a2]
    ca = tempfile.NamedTemporaryFile("w", suffix=".crt", delete=False)
    ca.write(secret_file("ou-id1", "/etc/ou-lab/tls/ca.crt"))
    ca.close()
    if any(u["uid"] == UID and u["state"] != "deleted" for u in op.get("identity/users")):
        raise SystemExit(f"{UID} exists: run cleanup first")
    _, j = run_plan(op, aps, "idm.user.create", {"stack": STACK, "uid": UID, "display_name": "Lab Dora", "mail": f"{UID}@ou-lab.internal",
                                                  "groups": [], "mailbox": False, "extension": EXT})
    step = [s for s in j["result"]["steps"] if s["step"] == "pbx.sync"][0]
    check("create with extension: LDAP telephoneNumber set and PBX knows the extension", step.get("known_to_pbx") is True, step)
    rc, out = sh("ou-id1", f"cd /tmp; LDAPTLS_CACERT=/etc/ou-lab/tls/ca.crt ldapsearch -LLL -x -H ldaps://ldap.ou-lab.internal -D cn=svc-bind,ou=system,{BASE_DN} "
                           f"-y /root/ou-lab-secrets/ldap-bind-password -b uid={UID},ou=people,{BASE_DN} telephoneNumber 2>&1 | grep -i telephoneNumber")
    check("directory really holds telephoneNumber", EXT in out, out.strip())
    native = issue(op, aps, "native")
    desk = issue(op, aps, "desk")
    pw = f"{native['password']}\n{desk['password']}\n"
    leak = subprocess.run(["sudo", "systemd-run", "-M", MACHINE, "--quiet", "--pipe", "--wait", "bash", "-c",
                           "umask 077; cat > /run/pw.tmp; grep -rlF -f /run/pw.tmp /var/log /var/lib/ou-pbx /etc/asterisk /etc/ou-pbx /run/ou-rb /run/ou-rb-secret /var/spool 2>/dev/null; "
                           "journalctl --no-pager 2>/dev/null | grep -cF -f /run/pw.tmp; rm -f /run/pw.tmp; true"], input=pw, capture_output=True, text=True).stdout.strip()
    check("PBX stores only digests: the issued passwords are in no file, log or journal on the PBX (grep hits: file list + journal count)", leak in ("0", ""), leak[:200])
    check("desk REGISTER with the issued credential accepted", register(desk["username"], desk["password"], ca.name) == 200)

    # live call: baresip (TLS + mandatory SDES-SRTP) as <uid>.native calls the echo test for 80 s
    script = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "blueprints", "telephony", "tests", "native-baresip.sh")).read()
    subprocess.run(["sudo", "systemd-run", "-M", MACHINE, "--quiet", "--pipe", "--wait", "bash", "-c", "cat > /root/native-baresip.sh"], input=script, text=True)
    bout = {}

    def call():
        p = subprocess.run(["sudo", "systemd-run", "-M", MACHINE, "--quiet", "--pipe", "--wait", "bash", "/root/native-baresip.sh", "600", "80"],
                           input=f"{native['username']} {native['password']}\n", capture_output=True, text=True, timeout=150)
        bout["o"] = p.stdout

    th = threading.Thread(target=call)
    th.start()
    t0 = time.time()
    while time.time() - t0 < 30 and f"PJSIP/{UID}.native" not in pbx('asterisk -rx "core show channels concise"'):
        time.sleep(0.5)
    live = f"PJSIP/{UID}.native" in pbx('asterisk -rx "core show channels concise"')
    check("live call of the user is up on the PBX (echo test 600 via baresip TLS+SRTP)", live)
    time.sleep(3)

    # pollers: first non-200 REGISTER for the desk credential; first moment no channel of the user exists
    seen: dict = {}
    stop = threading.Event()

    def poll_register():
        while not stop.is_set():
            try:
                code = register(desk["username"], desk["password"], ca.name)
            except Exception as e:  # noqa: BLE001
                code = f"err:{type(e).__name__}"
            if code != 200 and "reg" not in seen:
                seen["reg"] = (time.time(), code)
            time.sleep(0.3)

    def poll_call():
        while not stop.is_set():
            if UID not in pbx('asterisk -rx "core show channels concise"') and "call" not in seen:
                seen["call"] = time.time()
            time.sleep(0.2)

    ths = [threading.Thread(target=poll_register), threading.Thread(target=poll_call)]
    [t.start() for t in ths]
    time.sleep(1)
    _, dj = run_plan(op, aps, "idm.user.disable", {"stack": STACK, "uid": UID, "rotate_credentials": False, "verify_timeout_seconds": 30, "reason": "lab telephony run"})
    time.sleep(2)
    stop.set()
    [t.join() for t in ths]
    v = dj["result"]["verification"]
    lock = float(v["lock_applied_epoch"])
    kick = [s for s in dj["result"]["steps"] if s["step"] == "pbx.kick"][0]
    log("pbx.kick step: " + json.dumps(kick))
    reg_s = seen["reg"][0] - lock if "reg" in seen else None
    call_s = seen["call"] - lock if "call" in seen else None
    log(f"MEASURED (from LDAP lock applied by the ICS): REGISTER refused {reg_s if reg_s is None else round(reg_s, 2)}s (status {seen.get('reg', (0, None))[1]}), "
        f"live call dropped on the PBX {call_s if call_s is None else round(call_s, 2)}s, ICS VERIFY pbx_access {v['paths'].get('pbx_access')}")
    check("disable: REGISTER with the previously valid credential refused within 60 s", reg_s is not None and 0 <= reg_s < 60, f"{reg_s}")
    check("disable: live call dropped within 60 s", call_s is not None and 0 <= call_s < 60, f"{call_s}")
    check("disable: ICS VERIFY (pbx_access) refused and overall PASS", v["overall"] == "PASS" and v["paths"]["pbx_access"]["status"] == "refused", v["overall"])
    check("disable: registrations removed and channel hung up reported by the PBX runbook", (kick.get("registrations_removed") or 0) >= 1 and (kick.get("channels_hung_up") or 0) >= 1, kick)
    th.join(timeout=100)
    log("baresip after the drop: " + " | ".join(l for l in (bout.get("o") or "").splitlines() if re.search(r"(?i)terminat|closed|hangup|bye|Call with|reg.*(fail|401|403|404)", l))[:400])
    check("native REGISTER refused for the disabled user (fresh probe)", register(native["username"], native["password"], ca.name) in (401, 403, 404))
    # re-enable: extension is back, old credentials are not
    _, ej = run_plan(op, aps, "idm.user.enable", {"stack": STACK, "uid": UID})
    pst = [s for s in ej["result"]["steps"] if s["step"] == "pbx.sync"]
    check("enable: extension back on the PBX", pst and pst[0].get("known_to_pbx") is True, pst)
    check("enable: the OLD credential is not resurrected", register(desk["username"], desk["password"], ca.name) in (401, 403, 404))
    desk2 = issue(op, aps, "desk")
    check("enable: a NEWLY issued credential works", register(desk2["username"], desk2["password"], ca.name) == 200 and desk2["password"] != desk["password"])
    check("rotation: re-issuing a device credential stops the previous one",
          register(desk["username"], desk["password"], ca.name) in (401, 403, 404))
    # end: disable + delete (user and extension removed)
    run_plan(op, aps, "idm.user.disable", {"stack": STACK, "uid": UID, "rotate_credentials": False, "verify_timeout_seconds": 20, "reason": "lab telephony cleanup"})
    run_plan(op, aps, "idm.user.delete", {"stack": STACK, "uid": UID, "reason": "lab telephony run finished"})
    state = pbx(f"sudo -u ou-pbx ou-pbx state --user {UID}")
    check("after delete the PBX knows nothing of the user", '"endpoint_present": false' in state and '"known_to_pbx": false' in state, state.strip()[:200])
    os.unlink(ca.name)
    n_fail = RESULTS.count(False)
    log(f"== telephony lab run: {RESULTS.count(True)} PASS / {n_fail} FAIL")
    return 1 if n_fail else 0


def cleanup():
    op, a1, a2 = lul.api_login()
    for u in op.get("identity/users"):
        if u["stack"] == STACK and u["uid"].startswith("lt1") and u["state"] == "disabled":
            run_plan(op, [a1, a2], "idm.user.delete", {"stack": STACK, "uid": u["uid"], "reason": "lab cleanup"})


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    {"setup": setup, "cleanup": cleanup}.get(cmd, lambda: sys.exit(main()))()
