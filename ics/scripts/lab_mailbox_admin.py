#!/usr/bin/env python3
"""Lab proof for mailbox + storage administration (agent BE). A DEVELOPMENT ICS on 127.0.0.1:8126 (database ics_test_f) with SIDECAR agents
(ou-agent-be, port 8446, own trust, own code copy in /opt/ou-agent-be) on ou-gw1 and ou-files1: the production ICS, its database and the production
agents' trust are never touched. Real LDAP + Keycloak + Gromox (IMAP/EWS/SMTP) + OpenCloud (WebDAV). Plans go through the operator API (same executors
as the tenant API; the tenant layer is covered by ics/tests/test_mailadmin.py and the portal tests).

  prep      deploy the sidecars (needs /root/be-src on the nodes, see the results doc), OpenCloud quota identity in LDAP
  up        dev ICS + operators + nodes + stack + three test people (passwords set through the one-time enrollment flow)
  prove     the acceptance run (aliases, shared mailbox + grants + revoke, mail quota, storage quota)
  cleanup   disable + delete the test people, remove the shared mailbox grants
  down      stop the dev ICS (by recorded pid)
State (passwords, tokens) lives in $BE_DIR (0700) and is never printed. usage: lab_mailbox_admin.py <cmd>"""
import base64
import email
import imaplib
import json
import os
import re
import secrets
import smtplib
import ssl
import subprocess
import sys
import time
import uuid
from email.message import EmailMessage

import httpx

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import lab_org_admin as L  # noqa: E402  (dev ICS plumbing: database, operators, plans)

BE = os.environ.get("BE_DIR", os.path.expanduser("~/.cache/ou-mailbox-admin-lab"))
L.AX, L.DB, L.PORT_ICS = BE, "ics_test_f", 8126
L.STATE, L.BASE = os.path.join(BE, "state.json"), "http://127.0.0.1:8126/api/v1"
_dev_env = L.dev_env


def _env():
    e = _dev_env()
    k = os.path.join(BE, "signing.key")
    if not os.path.exists(k):
        os.makedirs(BE, mode=0o700, exist_ok=True)
        fd = os.open(k, os.O_WRONLY | os.O_CREAT, 0o600)
        os.write(fd, os.urandom(32))
        os.close(fd)
    return {**e, "ICS_SIGNING_KEY_FILE": k}


L.dev_env = _env
STACK, DOMAIN, GW, GW_CA = "be-lab", "ou-lab.internal", "gw1.ou-lab.internal", "/etc/office-unbound/lab/gw1-ca.crt"
NODES = {"ou-gw1": "192.168.186.218", "ou-files1": "192.168.186.242"}
RUN = uuid.uuid4().hex[:6]
R = {"PASS": 0, "FAIL": 0}
log, sh, secret_file, load, save = L.log, L.sh, L.secret_file, L.load, L.save


def check(name, cond, ok="ok", bad="FAILED"):
    R["PASS" if cond else "FAIL"] += 1
    print(("PASS " if cond else "FAIL ") + name + " - " + (ok if cond else bad), flush=True)
    return bool(cond)


# ---- prep / up ------------------------------------------------------------------------------------------------------------------------
def prep():
    """OpenCloud quota identity: ONE directory user in group opencloudAdmin (Keycloak maps the group to the realm role opencloudAdmin)."""
    s = load()
    if s.get("oc_quota_pw"):
        return log("quota identity exists")
    rc, out = sh("ou-id1", "bash /root/lab/spike-identity-files/kc/ldap-user.sh add svc-ocquota opencloudAdmin >/dev/null 2>&1; "
                 "grep '^OU_PASSWORD_SVC-OCQUOTA=' /root/ou-lab-secrets/test-users.env | tail -1 | cut -d= -f2-")
    pw = out.strip().splitlines()[-1] if rc == 0 and out.strip() else ""
    if not pw:
        raise SystemExit("could not create/read the quota identity")
    s["oc_quota_pw"] = pw
    save(s)
    log("quota identity svc-ocquota created in LDAP (group opencloudAdmin); password kept in the state dir")


def mint_node(op, aps, machine):
    nodes = {n["name"]: n for n in op.get("/nodes")}
    if machine in nodes:
        return nodes[machine]["id"]
    rc, out = sh(machine, "sh /root/be-src/lab_agent_sidecar_be.sh /root/be-src arm")
    tok = re.search(r"TOKEN[^:]*: (\S+)", out).group(1)
    fps = dict(re.findall(r"(tls_fingerprint_sha256|agent_key_fingerprint_sha256)=([0-9a-f]{64})", out))
    _, j = L.run_plan(op, aps, "node.enroll", {"name": machine, "address": NODES[machine], "port": 8446, "tls_fingerprint_sha256": fps["tls_fingerprint_sha256"],
                                                "agent_key_fingerprint_sha256": fps["agent_key_fingerprint_sha256"], "enrollment_token": tok})
    return j["result"]["node_id"]


def ids_ca():
    return secret_file("ou-id1", "/etc/ou-lab/tls/ca.crt")


def up():
    L.ics_up()
    s = load()
    ops = s.setdefault("ops", {})
    rt = L.runtime()
    for n, role in (("be-op", "operator"), ("be-ap1", "approver"), ("be-ap2", "approver")):
        c = L.mk_operator(rt, n, role)
        if c:
            ops[n] = c
    save(s)
    op, a1, a2 = (L.Api(n, ops[n]["password"], ops[n]["secret"]) for n in ("be-op", "be-ap1", "be-ap2"))
    aps = [a1, a2]
    gw, files = mint_node(op, aps, "ou-gw1"), mint_node(op, aps, "ou-files1")
    if not any(x["name"] == STACK for x in op.get("/identity/stacks")):
        base = "dc=ou-lab,dc=internal"
        L.run_plan(op, aps, "idm.stack.register", {
            "name": STACK, "ldap_url": "ldaps://ldap.ou-lab.internal", "ldap_bind_dn": f"cn=svc-ics,ou=system,{base}",
            "ldap_bind_password": secret_file("ou-id1", "/root/ou-lab-secrets/ldap-ics-password"), "ldap_people_dn": f"ou=people,{base}", "ldap_groups_dn": f"ou=groups,{base}",
            "mail_domain": DOMAIN, "entitlement_group": "mail-users", "allowed_groups": ["mail-users", "opencloudUser", "opencloudGuest", "opencloudSpaceAdmin", "opencloudAdmin"],
            "privileged_groups": ["opencloudAdmin"], "kc_url": "https://auth.ou-lab.internal", "kc_realm": "ou-lab", "kc_client_id": "ou-ics",
            "kc_client_secret": secret_file("ou-id1", "/root/ou-lab-secrets/kc-ics-client-secret"),
            "kc_offline_clients": ["web", "OpenCloudDesktop", "OpenCloudAndroid", "OpenCloudIOS", "ou-lab-test"], "identity_ca_pem": ids_ca(),
            "files_url": "https://cloud.ou-lab.internal", "files_node_id": files, "gromox_node_id": gw, "mail_host": GW, "mail_ca_pem": open(GW_CA).read(),
            "probe_client_id": "ou-lab-test", "reconcile_interval_seconds": 0, "oc_quota_user": "svc-ocquota", "oc_quota_password": s["oc_quota_pw"]})
    people = s["people"] = {}
    for uid, grp in ((f"mba{RUN}", ["mail-users", "opencloudUser"]), (f"mbb{RUN}", ["mail-users", "opencloudUser"]), (f"mbc{RUN}", ["mail-users", "opencloudUser"])):
        if uid in people:
            continue
        pid, j = L.run_plan(op, aps, "idm.user.create", {"stack": STACK, "uid": uid, "display_name": f"BE Lab {uid[2]}", "mail": f"{uid}@{DOMAIN}", "groups": grp})
        tok = op.post(f"/identity/enrollments/{pid}/reveal")["token"]
        pw = secrets.token_urlsafe(18) + "aA1"
        httpx.post(f"{L.BASE}/identity/enroll", json={"stack": STACK, "uid": uid, "token": tok, "password": pw}).raise_for_status()
        people[uid] = {"password": pw}
        save(s)
    s["people_order"] = list(people)
    save(s)
    log("up: " + ", ".join(people))


# ---- protocol helpers -------------------------------------------------------------------------------------------------------------------------
def imap(user, pw):
    im = imaplib.IMAP4_SSL(GW, 993, ssl_context=ssl.create_default_context(cafile=GW_CA))
    im.login(f"{user}@{DOMAIN}", pw)
    return im


def inbox_find(user, pw, token, wait=25):
    for _ in range(wait):
        im = imap(user, pw)
        try:
            im.select("INBOX")
            t, d = im.search(None, "SUBJECT", f'"{token}"')
            if d and d[0].split():
                _, m = im.fetch(d[0].split()[0], "(BODY.PEEK[HEADER])")
                return email.message_from_bytes(m[0][1])
        finally:
            im.logout()
        time.sleep(1)
    return None


def smtp_to(rcpt, subject, size=0, sender="outsider@example.test"):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = sender, rcpt, subject
    m.set_content("be lab " + ("x" * 80 + "\n") * (size // 81 if size else 1))
    s = smtplib.SMTP(GW, 25, timeout=60)
    try:
        return s.send_message(m)
    finally:
        s.quit()


EWS = ('<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" '
       'xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"><soap:Body>%s</soap:Body></soap:Envelope>')


def ews(user, pw, body):
    return httpx.post(f"https://{GW}/EWS/Exchange.asmx", content=(EWS % body).encode(), auth=(f"{user}@{DOMAIN}", pw), headers={"Content-Type": "text/xml"},
                      verify=ssl.create_default_context(cafile=GW_CA), timeout=90)


def ews_find(user, pw, mailbox):
    return ews(user, pw, '<m:FindItem Traversal="Shallow"><m:ItemShape><t:BaseShape>Default</t:BaseShape></m:ItemShape><m:ParentFolderIds><t:DistinguishedFolderId Id="inbox">'
                         f'<t:Mailbox><t:EmailAddress>{mailbox}</t:EmailAddress></t:Mailbox></t:DistinguishedFolderId></m:ParentFolderIds></m:FindItem>')


def ews_send(user, pw, frm, to, subject, save_in=None):
    """save_in: mailbox whose Sent Items receives the copy (Exchange semantics for send-as/on-behalf: the copy goes to the represented mailbox)."""
    box = f"<t:Mailbox><t:EmailAddress>{save_in}</t:EmailAddress></t:Mailbox>" if save_in else ""
    return ews(user, pw, f'<m:CreateItem MessageDisposition="SendAndSaveCopy"><m:SavedItemFolderId><t:DistinguishedFolderId Id="sentitems">{box}</t:DistinguishedFolderId></m:SavedItemFolderId><m:Items>'
                         f'<t:Message><t:Subject>{subject}</t:Subject><t:Body BodyType="Text">be lab send</t:Body><t:ToRecipients><t:Mailbox><t:EmailAddress>{to}</t:EmailAddress></t:Mailbox></t:ToRecipients>'
                         f'<t:From><t:Mailbox><t:EmailAddress>{frm}</t:EmailAddress></t:Mailbox></t:From></t:Message></m:Items></m:CreateItem>')


def codes(r):
    return ",".join(re.findall(r"ResponseCode>([^<]+)", r.text)) or f"HTTP {r.status_code}"


def kc_token(uid, pw):
    ctx = ssl.create_default_context(cadata=ids_ca())
    r = httpx.post("https://auth.ou-lab.internal/realms/ou-lab/protocol/openid-connect/token", verify=ctx,
                   data={"grant_type": "password", "client_id": "ou-lab-test", "username": uid, "password": pw, "scope": "openid"})
    return r.json().get("access_token") if r.status_code == 200 else None


def oc(method, path, tok, **kw):
    ctx = ssl.create_default_context(cadata=ids_ca())
    return httpx.request(method, "https://cloud.ou-lab.internal" + path, headers={"Authorization": f"Bearer {tok}"}, verify=ctx, timeout=120, **kw)


# ---- prove -----------------------------------------------------------------------------------------------------------------------------
def prove():
    s = load()
    ops = s["ops"]
    op, a1, a2 = (L.Api(n, ops[n]["password"], ops[n]["secret"]) for n in ("be-op", "be-ap1", "be-ap2"))
    aps = [a1, a2]
    A, B, C = s["people_order"]
    pw = {u: s["people"][u]["password"] for u in (A, B, C)}
    plan = lambda action, params, **k: L.run_plan(op, aps, action, {"stack": STACK, **params}, **k)  # noqa: E731
    time.sleep(2)
    for u in (A, B, C):
        check(f"{u} can use mail (IMAP login with the directory password)", imap(u, pw[u]).logout()[0] == "BYE", "logged in", "login refused")

    # 1. alias ------------------------------------------------------------------------------------------------------------------------------
    alias = f"sales{RUN}@{DOMAIN}"
    plan("idm.user.set_aliases", {"uid": A, "add": [alias]})
    tok = f"BE-ALIAS-{RUN}"
    r = smtp_to(alias, tok)
    check("SMTP accepts mail for the alias address", not r, "accepted by postfix (virtual alias map)", str(r))
    h = inbox_find(A, pw[A], tok)
    check("mail to the alias is delivered to the owner (IMAP)", h is not None, f"arrived in {A}'s INBOX, To: {h['To'] if h else ''}", "not delivered")
    try:
        r2 = smtp_to(f"sales{RUN}x@{DOMAIN}", "no such alias")
        check("an address that is not an alias is refused", False, "", "accepted")
    except smtplib.SMTPRecipientsRefused as e:
        check("an address that is not an alias is refused", True, f"refused: {list(e.recipients.values())[0][0]}")
    rr = op.c.post("/plans", headers=op.h, json={"action": "idm.user.set_aliases", "params": {"stack": STACK, "uid": B, "add": [alias]}})
    check("an alias already used by another person is refused (409)", rr.status_code == 409, rr.json().get("detail", "")[:80], f"HTTP {rr.status_code}")
    rr = op.c.post("/plans", headers=op.h, json={"action": "idm.user.set_aliases", "params": {"stack": STACK, "uid": B, "add": ["x@outside.test"]}})
    check("an alias in a domain that is not the customer's is refused (422)", rr.status_code == 422, rr.json().get("detail", "")[:90], f"HTTP {rr.status_code}")
    plan("idm.user.set_aliases", {"uid": A, "remove": [alias]})
    time.sleep(2)
    try:
        smtp_to(alias, "after removal")
        check("after removal the alias is refused again", False, "", "accepted")
    except smtplib.SMTPRecipientsRefused as e:
        check("after removal the alias is refused again", True, f"refused: {list(e.recipients.values())[0][0]}")

    # 2. shared mailbox ----------------------------------------------------------------------------------------------------------------------
    sh_name = f"support{RUN}"
    sh_addr = f"{sh_name}@{DOMAIN}"
    plan("idm.shared_mailbox.create", {"name": sh_name, "display_name": f"Support {RUN}"})
    tok = f"BE-SHARED-{RUN}"
    check("mail to the shared mailbox is accepted", not smtp_to(sh_addr, tok), "accepted")
    time.sleep(4)
    try:
        imap(sh_name, "anything")
        check("nobody can log in to the shared mailbox directly", False, "", "login worked")
    except imaplib.IMAP4.error as e:
        check("nobody can log in to the shared mailbox directly", True, f"refused: {str(e)[:60]}")
    check("a person without a grant cannot read it (EWS)", "ErrorAccessDenied" in ews_find(B, pw[B], sh_addr).text or tok not in ews_find(B, pw[B], sh_addr).text,
          codes(ews_find(B, pw[B], sh_addr)))
    plan("idm.shared_mailbox.grant", {"name": sh_name, "uid": B, "kind": "full_access"})
    time.sleep(1)
    r = ews_find(B, pw[B], sh_addr)
    check("the grantee reads the shared mailbox via EWS", tok in r.text, "message visible", codes(r))
    check("another person (no grant) still cannot", tok not in ews_find(C, pw[C], sh_addr).text, codes(ews_find(C, pw[C], sh_addr)))
    plan("idm.shared_mailbox.revoke", {"name": sh_name, "uid": B, "kind": "full_access"})   # from here B holds nothing but what each step grants
    r = ews_find(B, pw[B], sh_addr)
    check("after revoking full access the person is refused (EWS)", tok not in r.text, codes(r), "still readable")
    # Gromox 3.13 (lab build) EWS, measured: delegates.txt (send-on-behalf) is what lets a person submit in the mailbox's name; a person with ONLY
    # sendas.txt is refused and the delivered From header stays the submitter (see the results doc, "findings").
    plan("idm.shared_mailbox.grant", {"name": sh_name, "uid": B, "kind": "send_on_behalf"})
    time.sleep(1)
    otok = f"BE-ONBEHALF-{RUN}"
    r = ews_send(B, pw[B], sh_addr, f"{A}@{DOMAIN}", otok)
    check("a person on the delegate list can submit mail in the shared mailbox's name (EWS)", codes(r) == "NoError", codes(r), codes(r))
    h = inbox_find(A, pw[A], otok, wait=15)
    check("the mail is delivered", h is not None, "arrived", "not delivered")
    print(f"INFO headers of the delegated mail: From={h['From'] if h else None} Sender={h['Sender'] if h else None}", flush=True)
    r = ews_send(C, pw[C], sh_addr, f"{A}@{DOMAIN}", f"BE-DENY-{RUN}")
    check("a person without any grant cannot submit in its name", codes(r) != "NoError", codes(r), "was allowed")
    plan("idm.shared_mailbox.revoke", {"name": sh_name, "uid": B, "kind": "send_on_behalf"})
    time.sleep(1)
    rtok = f"BE-REVOKED-{RUN}"
    r = ews_send(B, pw[B], sh_addr, f"{A}@{DOMAIN}", rtok)
    check("after revoking, the same person is refused", codes(r) != "NoError", codes(r), "still allowed: " + codes(r))
    check("nothing arrived from the refused attempt", inbox_find(A, pw[A], rtok, wait=5) is None, "nothing delivered", "a mail arrived")
    plan("idm.shared_mailbox.grant", {"name": sh_name, "uid": B, "kind": "send_as"})
    time.sleep(1)
    r = ews_send(B, pw[B], sh_addr, f"{A}@{DOMAIN}", f"BE-SENDASONLY-{RUN}")
    print(f"INFO send-as list only (sendas.txt): EWS answered {codes(r)} on this build", flush=True)
    plan("idm.shared_mailbox.revoke", {"name": sh_name, "uid": B, "kind": "send_as"})

    # 3. mail quota ----------------------------------------------------------------------------------------------------------------------------
    plan("idm.user.set_mail_quota", {"uid": C, "limit_mb": 1})
    rc, out = sh("ou-gw1", f"sqlite3 /var/lib/gromox/user/{C}@{DOMAIN}/exmdb/exchange.sqlite3 'select printf(\"%x\",proptag), propval from store_properties order by 1'")
    check("quota stored in the mailbox's store properties", "666e0003|1024" in out and "666a0003|1024" in out and "3ff50003|1024" in out, out.replace("\n", " "), out)
    for i in range(3):
        smtp_to(f"{C}@{DOMAIN}", f"BE-FILL-{RUN}-{i}", size=600_000)
        time.sleep(2)
    filled = [i for i in range(3) if inbox_find(C, pw[C], f"BE-FILL-{RUN}-{i}", wait=6) is not None]
    check("mail below the limit is delivered", len(filled) >= 1, f"{len(filled)} of 3 fill mails delivered before the limit applied", "nothing delivered")
    time.sleep(3)
    tok = f"BE-OVER-{RUN}"
    try:
        smtp_to(f"{C}@{DOMAIN}", tok)
        accepted = True
    except smtplib.SMTPException:
        accepted = False
    time.sleep(8)
    h = inbox_find(C, pw[C], tok, wait=6)
    rc, logs = sh("ou-gw1", f"journalctl -u gromox-delivery -u postfix --since '-2 min' --no-pager 2>/dev/null | grep -i -E 'full|quota|bounced|status=' | tail -4")
    check("receive limit enforced: mail over the quota is NOT delivered", h is None, f"not delivered (SMTP accepted: {accepted}); log: {logs.strip()[-200:]}", "delivered despite the limit")
    r = ews_send(C, pw[C], f"{C}@{DOMAIN}", f"{A}@{DOMAIN}", f"BE-OVERSEND-{RUN}")
    h = inbox_find(A, pw[A], f"BE-OVERSEND-{RUN}", wait=6)
    check("send limit enforced: a person over quota cannot send", h is None and "NoError" not in r.text.replace("ErrorQuota", ""), codes(r), "mail was sent: " + codes(r))
    plan("idm.user.set_mail_quota", {"uid": C, "limit_mb": None})
    time.sleep(2)
    tok = f"BE-AFTER-{RUN}"
    smtp_to(f"{C}@{DOMAIN}", tok)
    check("quota removed: delivery works again", inbox_find(C, pw[C], tok, wait=20) is not None, "delivered", "not delivered")

    # 4. storage quota (OpenCloud) --------------------------------------------------------------------------------------------------------------------
    t = kc_token(A, pw[A])
    check("the person signs in to the files service", t is not None, "token issued", "sign-in failed")
    r = oc("GET", "/graph/v1.0/me/drive", t)
    check("personal drive exists", r.status_code == 200, f"HTTP 200 quota={r.json().get('quota')}", f"HTTP {r.status_code}")
    plan("idm.user.set_storage_quota", {"uid": A, "quota_mb": 1})
    r = oc("GET", "/graph/v1.0/me/drive", t)
    check("quota visible to the person's own client", r.status_code == 200 and (r.json().get("quota") or {}).get("total") == 1048576, str(r.json().get("quota")), r.text[:200])
    small = oc("PUT", f"/remote.php/dav/files/{A}/small-{RUN}.bin", t, content=b"s" * 100_000)
    big = oc("PUT", f"/remote.php/dav/files/{A}/big-{RUN}.bin", t, content=os.urandom(2_000_000))
    check("an upload within the quota succeeds", small.status_code in (201, 204), f"HTTP {small.status_code}", f"HTTP {small.status_code} {small.text[:120]}")
    check("an upload beyond the quota is refused", big.status_code == 507, f"HTTP {big.status_code} (Insufficient Storage)", f"HTTP {big.status_code} {big.text[:120]}")
    plan("idm.user.set_storage_quota", {"uid": A, "quota_mb": None})
    ok = oc("PUT", f"/remote.php/dav/files/{A}/big2-{RUN}.bin", t, content=os.urandom(2_000_000))
    check("quota removed: the same upload now succeeds", ok.status_code in (201, 204), f"HTTP {ok.status_code}", f"HTTP {ok.status_code}")
    for n in (f"small-{RUN}.bin", f"big2-{RUN}.bin"):
        oc("DELETE", f"/remote.php/dav/files/{A}/{n}", t)

    # 5. hygiene -------------------------------------------------------------------------------------------------------------------------------------
    from sqlalchemy import text
    with L.runtime().session() as d:
        blob = json.dumps([str(x[0]) for x in d.execute(text("SELECT details FROM audit_events")).all()] + [str(x[0]) for x in d.execute(text("SELECT result FROM jobs")).all()])
    check("no password or token in the audit log", s["oc_quota_pw"] not in blob and all(p["password"] not in blob for p in s["people"].values()), "none found", "FOUND")
    print(f"-- mailbox admin lab: {R['PASS']} PASS, {R['FAIL']} FAIL", flush=True)
    return 1 if R["FAIL"] else 0


def cleanup():
    s = load()
    ops = s["ops"]
    op, a1, a2 = (L.Api(n, ops[n]["password"], ops[n]["secret"]) for n in ("be-op", "be-ap1", "be-ap2"))
    for u in [u for u in op.get("/identity/users", params={"stack": STACK}) if u["state"] != "deleted"]:
        if u["state"] == "active":
            L.run_plan(op, [a1, a2], "idm.user.disable", {"stack": STACK, "uid": u["uid"], "reason": "lab cleanup"})
        L.run_plan(op, [a1, a2], "idm.user.delete", {"stack": STACK, "uid": u["uid"], "reason": "lab cleanup"})


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "prep":
        prep()
    elif cmd == "up":
        up()
    elif cmd == "prove":
        sys.exit(prove())
    elif cmd == "cleanup":
        cleanup()
    elif cmd == "down":
        L.down()
