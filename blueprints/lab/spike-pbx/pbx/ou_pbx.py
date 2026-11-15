#!/usr/bin/env python3
"""Office Unbound PBX provisioner (lab spike) - LDAP -> Asterisk PJSIP/dialplan/voicemail, ICS-provisioning-ready.

Source of truth: the authoritative OpenLDAP. A person gets a phone only if their inetOrgPerson entry has `telephoneNumber`
(= the 4-digit internal extension) and is NOT locked (`pwdAccountLockedTime` absent). The provisioner is idempotent:
  ou-pbx sync                         re-read LDAP, rewrite /etc/asterisk/ou/*.conf, reload Asterisk only if something changed;
                                      endpoints of users who vanished / were locked are dropped, their contacts deleted and live calls hung up.
  ou-pbx issue --user U --device D    create (or rotate) the SIP credential of device D (web|native|desk) and print it ONCE as JSON.
  ou-pbx revoke --user U [--device D]
  ou-pbx list                         no secrets.

Credential handling: only md5_cred = MD5(user:realm:password) is stored on the PBX (Asterisk `auth_type=md5`); the clear password is
returned to the caller once and is never written to disk or logs by this code. NOTE: that HA1 is password-EQUIVALENT for SIP digest auth
(whoever reads it can register as the device), so it is as sensitive as the password: state and generated config are root/ou-pbx-only, and
web credentials are short-lived (see below).
Web credentials carry an expiry (`expires`, tied to the Keycloak session of the softphone page): sync() drops expired devices, kicks their
registrations, and a re-issue kicks the previous contact. Logout / back-channel logout / LDAP lock revoke immediately (security review 4, M10). (Voicemail PINs, which Asterisk needs in clear in
voicemail.conf, are the one exception and are separate from SIP credentials.)

Fail-static: if LDAP is unreachable or the answer looks wrong, sync raises and leaves the running config untouched.
Config: JSON at $OU_PBX_CONF (default /etc/ou-pbx/ou-pbx.json).
"""
import argparse
import fcntl
import hashlib
import json
import os
import re
import secrets
import ssl
import subprocess
import sys
import tempfile
import time

import ldap3

CONF = os.environ.get("OU_PBX_CONF", "/etc/ou-pbx/ou-pbx.json")
EXT_RE = re.compile(r"^[1-9][0-9]{3}$")
UID_RE = re.compile(r"^[a-z][a-z0-9_-]{0,30}$")
DEV_RE = re.compile(r"^[a-z]{2,10}$")
DEVICE_KINDS = ("web", "native", "desk")
_NAME_BAD = re.compile(r"[^\w .'\-]", re.U)


def safe_name(name, uid):
    """Display name for callerid / voicemail.conf: letters, digits, space . ' - only. `,` `;` `|` `=` `"` `\\` newlines would shift voicemail.conf
    fields or comment out the rest of the line (L7)."""
    n = " ".join(_NAME_BAD.sub("", str(name)).split())[:60]
    return n or uid
EMERGENCY = ("112", "911", "999", "110", "933")

_cfg = None


def cfg():
    global _cfg
    if _cfg is None:
        _cfg = json.load(open(CONF))
    return _cfg


def log(msg):
    print("[ou-pbx] " + msg, file=sys.stderr, flush=True)


# ---------------------------------------------------------------- LDAP
def ldap_users():
    c = cfg()["ldap"]
    tls = ldap3.Tls(ca_certs_file=c["ca"], validate=ssl.CERT_REQUIRED)
    srv = ldap3.Server(c["host"], use_ssl=True, tls=tls, connect_timeout=5)
    pw = open(c["bind_pw_file"]).read().strip()
    conn = ldap3.Connection(srv, c["bind_dn"], pw, auto_bind=True, receive_timeout=10)
    attrs = ["uid", "mail", "displayName", "telephoneNumber", "pwdAccountLockedTime"]
    conn.search(c["people_dn"], "(&(objectClass=inetOrgPerson)(telephoneNumber=*))", attributes=attrs)
    if conn.result.get("result") != 0:
        raise RuntimeError("LDAP search failed: %s" % conn.result)
    out, seen = {}, set()
    for e in conn.entries:
        uid = str(e.uid.value or "")
        ext = str(e.telephoneNumber.values[0]) if e.telephoneNumber.values else ""
        if not UID_RE.match(uid) or not EXT_RE.match(ext):
            log("skip %r: invalid uid/extension %r" % (uid, ext))
            continue
        if ext in seen:
            log("skip %s: duplicate extension %s" % (uid, ext))
            continue
        seen.add(ext)
        locked = bool(e.pwdAccountLockedTime.values)
        mail = str(e.mail.value or "")
        out[uid] = {"uid": uid, "ext": ext, "mail": mail if re.fullmatch(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}", mail) else "",
                    "name": safe_name(e.displayName.value or uid, uid), "locked": locked}
    conn.unbind()
    return out


# ---------------------------------------------------------------- state
def _state_path():
    return os.path.join(cfg()["state_dir"], "devices.json")


class Lock:
    def __enter__(self):
        os.makedirs(cfg()["state_dir"], exist_ok=True)
        self.f = open(os.path.join(cfg()["state_dir"], "lock"), "w")
        fcntl.flock(self.f, fcntl.LOCK_EX)

    def __exit__(self, *a):
        self.f.close()


def load_state():
    try:
        return json.load(open(_state_path()))
    except FileNotFoundError:
        return {"devices": {}, "vm_pin": {}}


def _inherit_owner(path, dirpath):
    """Run as root (admin CLI) the new file would be root-owned and lock the service user (ou-pbx) out of its own state: give it the directory's owner."""
    if os.geteuid() == 0:
        d = os.stat(dirpath)
        os.chown(path, d.st_uid, d.st_gid)


def save_state(st):
    fd, tmp = tempfile.mkstemp(dir=cfg()["state_dir"])
    with os.fdopen(fd, "w") as f:
        json.dump(st, f, indent=1)
    os.chmod(tmp, 0o600)
    _inherit_owner(tmp, cfg()["state_dir"])
    os.replace(tmp, _state_path())


def md5_cred(user, realm, password):
    return hashlib.md5(("%s:%s:%s" % (user, realm, password)).encode()).hexdigest()


# ---------------------------------------------------------------- rendering
def render(users, st):
    c = cfg()
    realm = c["realm"]
    pj, dp, vm = [], [], []
    endpoints = []
    dp.append("; GENERATED by ou-pbx sync - do not edit. Source: LDAP telephoneNumber.\n[ou-internal]")
    dp.append("; internal-only: no PSTN/outbound pattern exists in this context. Emergency numbers are trapped (see ou-emergency).")
    dp.append("exten => 600,1,NoOp(echo test)\n same => n,Answer()\n same => n,Echo()\n same => n,Hangup()")
    dp.append("exten => *97,1,Answer()\n same => n,VoiceMailMain(${CALLERID(num)}@ou,s)\n same => n,Hangup()")
    for n in EMERGENCY:
        dp.append("exten => %s,1,Goto(ou-emergency,s,1)" % n)
    vm.append("; GENERATED by ou-pbx sync\n[general]\nformat=wav49|gsm\nserveremail=%s\nmailcmd=/usr/local/sbin/ou-pbx-mail\nattach=yes\n"
              "maxsecs=120\nminsecs=3\nmaxsilence=2\nsilencethreshold=128\nmaxmsg=50\nemailsubject=[Voicemail] New message from ${VM_CIDNUM}\n"
              "emailbody=Hello ${VM_NAME},\\n\\nyou have a new voicemail from ${VM_CIDNAME} <${VM_CIDNUM}> (${VM_DUR}, ${VM_DATE}).\\n\\nOffice Unbound PBX (lab)\\n\n"
              "fromstring=Office Unbound PBX\n\n[ou]" % c["server_email"])
    for uid, u in sorted(users.items()):
        if u["locked"]:
            continue
        devs = st["devices"].get(uid, {})
        names = []
        for dev, rec in sorted(devs.items()):
            if rec.get("expires") and rec["expires"] <= time.time():
                continue
            ep = "%s.%s" % (uid, dev)
            names.append(ep)
            endpoints.append(ep)
            web = dev == "web"
            cid = '"%s" <%s>' % (u["name"].replace('"', ""), u["ext"])
            pj.append("[%s]\ntype=auth\nauth_type=md5\nusername=%s\nmd5_cred=%s\nrealm=%s\n" % (ep, ep, rec["md5"], realm))
            pj.append("[%s]\ntype=aor\nmax_contacts=1\nremove_existing=yes\nminimum_expiration=60\nmaximum_expiration=3600\ndefault_expiration=600\n" % ep)
            base = "[%s]\ntype=endpoint\ncontext=ou-internal\ndisallow=all\nallow=ulaw,alaw\naors=%s\nauth=%s\ncallerid=%s\ndirect_media=no\n" \
                   "rtp_symmetric=yes\nforce_rport=yes\nrewrite_contact=yes\ntrust_id_inbound=no\nsend_pai=no\ndevice_state_busy_at=1\n" % (ep, ep, ep, cid)
            if web:
                base += "webrtc=yes\ndtls_auto_generate_cert=yes\n"
            else:
                base += "transport=transport-tls\nmedia_encryption=sdes\nmedia_encryption_optimistic=no\n"
            pj.append(base)
        if names:
            dial = "&".join("PJSIP/" + n for n in names)
            pin = st["vm_pin"].setdefault(uid, "%06d" % secrets.randbelow(10**6))
            dp.append("exten => %s,1,NoOp(call to %s)\n same => n,Dial(%s,20,Tt)\n same => n,GotoIf($[\"${DIALSTATUS}\" = \"ANSWER\"]?done)\n"
                      " same => n,VoiceMail(%s@ou,u)\n same => n(done),Hangup()" % (u["ext"], uid, dial, u["ext"]))
            vm.append("%s => %s,%s,%s,,attach=yes" % (u["ext"], pin, u["name"], u["mail"]))
    dp.append("\n[ou-emergency]\n; EMERGENCY CALLING IS NOT AVAILABLE ON THIS SYSTEM (no PSTN trunk). Tell the caller; never ring silently.\n"
              "exten => s,1,NoOp(EMERGENCY NUMBER DIALLED from ${CALLERID(all)} - NOT CONNECTED)\n same => n,Log(WARNING,EMERGENCY number dialled by ${CALLERID(all)}: not connected)\n"
              " same => n,Answer()\n same => n,Playback(ss-noservice)\n same => n,Playback(ss-noservice)\n same => n,Hangup()")
    return "\n".join(pj), "\n".join(dp) + "\n", "\n".join(vm) + "\n", endpoints


def write_if_changed(path, data, mode=0o640):
    try:
        if open(path).read() == data:
            return False
    except FileNotFoundError:
        pass
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=d)
    with os.fdopen(fd, "w") as f:
        f.write(data)
    os.chmod(tmp, mode)
    _inherit_owner(tmp, d)
    os.replace(tmp, path)
    return True


def ast(*cmd):
    r = subprocess.run(["/usr/sbin/asterisk", "-rx", " ".join(cmd)], capture_output=True, text=True, timeout=20)
    return r.stdout


def kick(endpoint):
    """Delete registered contacts and hang up live channels of an endpoint that was removed."""
    for line in ast("database show registrar/contact").splitlines():
        m = re.match(r"^/registrar/contact/(\S+?)\s*:", line)
        if m and m.group(1).split(";")[0] == endpoint:
            ast('database del registrar/contact %s' % m.group(1))
    for line in ast("core show channels concise").splitlines():
        ch = line.split("!")[0]
        if ch.startswith("PJSIP/%s-" % endpoint):
            ast("channel request hangup", ch)


def sync(users=None):
    c = cfg()
    with Lock():
        users = users if users is not None else ldap_users()
        st = load_state()
        # purge expired device credentials (web credentials live as long as the Keycloak session of the softphone page)
        now = time.time()
        for uid in list(st["devices"]):
            for dev in [d for d, r in st["devices"][uid].items() if r.get("expires") and r["expires"] <= now]:
                log("credential of %s.%s expired" % (uid, dev))
                del st["devices"][uid][dev]
            if not st["devices"][uid]:
                del st["devices"][uid]
        # purge credentials of users that are gone or locked (a re-enabled user must be issued new ones)
        for uid in list(st["devices"]):
            if uid not in users or users[uid]["locked"]:
                log("deprovision %s (%s)" % (uid, "locked" if uid in users else "removed from LDAP"))
                del st["devices"][uid]
                st["vm_pin"].pop(uid, None)
        pj, dp, vm, endpoints = render(users, st)
        old = set()
        try:
            old = set(json.load(open(os.path.join(c["state_dir"], "endpoints.json"))))
        except FileNotFoundError:
            pass
        os.makedirs(c["ast_dir"], exist_ok=True)
        ch = [write_if_changed(os.path.join(c["ast_dir"], "pjsip_ou.conf"), pj),
              write_if_changed(os.path.join(c["ast_dir"], "extensions_ou.conf"), dp),
              write_if_changed(c["voicemail_conf"], vm)]
        save_state(st)
        ep_path = os.path.join(c["state_dir"], "endpoints.json")
        json.dump(endpoints, open(ep_path, "w"))
        _inherit_owner(ep_path, c["state_dir"])
        if ch[0]:
            ast("module reload res_pjsip.so")
        if ch[1]:
            ast("dialplan reload")
        if ch[2]:
            ast("voicemail reload")
        for ep in sorted(old - set(endpoints)):
            kick(ep)
        return {"changed": ch, "endpoints": endpoints, "removed": sorted(old - set(endpoints))}


def issue(uid, dev, ttl=None):
    """Create/rotate credential. Returns the clear password ONCE (caller must hand it to the device and drop it).
    ttl (seconds): the credential expires then (sync() removes it); a rotation kicks the contact registered with the previous credential."""
    if not (UID_RE.match(uid) and DEV_RE.match(dev)):
        raise ValueError("bad user/device")
    c = cfg()
    users = ldap_users()
    u = users.get(uid)
    if not u or u["locked"]:
        raise PermissionError("user has no active extension")
    with Lock():
        st = load_state()
        pw = secrets.token_hex(16)
        ep = "%s.%s" % (uid, dev)
        rotated = dev in st["devices"].get(uid, {})
        rec = {"md5": md5_cred(ep, c["realm"], pw), "created": int(time.time())}
        if ttl:
            rec["expires"] = int(time.time()) + int(ttl)
        st["devices"].setdefault(uid, {})[dev] = rec
        save_state(st)
    sync(users)
    if rotated:
        kick(ep)         # the old password must stop working NOW, not when the old registration times out (<= 600 s)
    return {"username": ep, "password": pw, "extension": u["ext"], "display_name": u["name"], "realm": c["realm"],
            "domain": c["domain"], "wss": c["wss_url"], "tls_port": 5061, "outbound_proxy": c["domain"], "expires_in": int(ttl) if ttl else None}


def revoke(uid, dev=None):
    with Lock():
        st = load_state()
        if dev:
            st["devices"].get(uid, {}).pop(dev, None)
        else:
            st["devices"].pop(uid, None)
        save_state(st)
    return sync()


def main():
    ap = argparse.ArgumentParser(prog="ou-pbx")
    sp = ap.add_subparsers(dest="cmd", required=True)
    sp.add_parser("sync")
    sp.add_parser("list")
    a = sp.add_parser("issue"); a.add_argument("--user", required=True); a.add_argument("--device", required=True, choices=DEVICE_KINDS)
    a.add_argument("--ttl", type=int, default=None, help="seconds until the credential expires (default: never)")
    r = sp.add_parser("revoke"); r.add_argument("--user", required=True); r.add_argument("--device")
    ns = ap.parse_args()
    if ns.cmd == "sync":
        print(json.dumps(sync()))
    elif ns.cmd == "list":
        st = load_state()
        print(json.dumps({u: sorted(d) for u, d in st["devices"].items()}))
    elif ns.cmd == "issue":
        print(json.dumps(issue(ns.user, ns.device, ns.ttl)))
    elif ns.cmd == "revoke":
        print(json.dumps(revoke(ns.user, ns.device)))


if __name__ == "__main__":
    main()
