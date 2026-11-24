"""Node-side executor of the CONFIGURATION runbooks (cfgspec.py). Started ONLY by the fixed template unit ou-rb-cfg@<rid>.service (root), which the
agent may start through polkit. Usage: python3 -m ou_agent.cfghelper <rid>

The helper never trusts the spool: it re-validates with the same code the agent used, against the root-owned /etc/ou-agent/agent.json. All commands
are argv lists with absolute paths (no shell); secret values reach programs on STDIN or in 0600 files, never on a command line; every text that
leaves the helper (errors) is scrubbed of the request's secret values. Ported from the lab scripts blueprints/lab/spike-identity-files/kc/
install-openldap.sh and blueprints/build/oci/idfiles/art-prep{1,2}.sh (docs/status/artifacts-core-results.md open item 5)."""
import base64
import hashlib
import io
import json
import os
import pwd
import re
import secrets
import stat
import shutil
import subprocess
import sys
import tarfile
import time

from . import cfgspec as c
from .guestspec import SERVICE_HOME, SERVICE_USER
from .proto import Reject

CONFIG = "/etc/ou-agent/agent.json"
SPOOL_DIR = "/run/ou-agent-spool"
RESULT_DIR = "/run/ou-rb-cfg"
RID_RE = re.compile(r"^r[0-9a-f]{16}$")
MAX_SPOOL = 1 << 20
TLS_DIR = "/etc/ou/tls"
CA_TRUST = "/usr/local/share/ca-certificates/ou-deployment-ca.crt"
HOSTS = "/etc/hosts"
HOSTS_BEGIN, HOSTS_END = "# BEGIN office-unbound deployment (managed by ou-agent cfg.hosts)", "# END office-unbound deployment"
LDAP_TLS = "/etc/ldap/tls"
SLAPD_DEFAULT = "/etc/default/slapd"
LDAP_CONF = "/etc/ldap/ldap.conf"
NGINX_AVAIL, NGINX_ENABLED, NGINX_MAP = "/etc/nginx/sites-available", "/etc/nginx/sites-enabled", "/etc/nginx/conf.d/ou-upgrade-map.conf"
NFT_ALLOW = "/etc/ou-agent/nft-allow.d/ou-peers.nft"   # included by the first-boot /etc/nftables.conf (set inet ou_guest cfg_allow4)
VERIFIED_DIR = os.path.join(SERVICE_HOME, ".local/share/ou-agent/verified")
BIN = {"python3": "/usr/bin/python3", "systemd-run": "/usr/bin/systemd-run", "openssl": "/usr/bin/openssl", "certbot": "/usr/bin/certbot", "update-ca": "/usr/sbin/update-ca-certificates", "debconf-set": "/usr/bin/debconf-set-selections",
       "dpkg-reconfigure": "/usr/sbin/dpkg-reconfigure", "dpkg-query": "/usr/bin/dpkg-query", "ldapsearch": "/usr/bin/ldapsearch",
       "ldapmodify": "/usr/bin/ldapmodify", "systemctl": "/usr/bin/systemctl", "runuser": "/usr/sbin/runuser", "podman": "/usr/bin/podman",
       "psql": "/usr/bin/psql", "nginx": "/usr/sbin/nginx", "nft": "/usr/sbin/nft", "mariadb": "/usr/bin/mariadb", "postconf": "/usr/sbin/postconf",
       "postfix": "/usr/sbin/postfix", "dbop": "/usr/sbin/gromox-dbop", "mkprivate": "/usr/sbin/gromox-mkprivate", "mkmidb": "/usr/sbin/gromox-mkmidb",
       "mkpublic": "/usr/sbin/gromox-mkpublic", "usermod": "/usr/sbin/usermod", "groupadd": "/usr/sbin/groupadd", "getent": "/usr/bin/getent",
       "chown": "/usr/bin/chown", "phpenmod": "/usr/sbin/phpenmod"}
ROOT_ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "DEBIAN_FRONTEND": "noninteractive"}
SECRET_KEYS = ("admin_password", "bind_password", "writer_password", "password", "value", "key_pem", "db_password", "client_secret")


class Failed(Exception):
    """A step failed; the message is already scrubbed and short."""


class Ctx:
    def __init__(self, params):
        nested = [params["sso"]] if isinstance(params.get("sso"), dict) else []
        self.secrets = sorted({str(d[k]) for d in (params, *nested) for k in SECRET_KEYS if isinstance(d.get(k), str) and d.get(k)}, key=len, reverse=True)
        for f in params.get("files", []) or []:   # volume files may embed secrets (realm import, env files): scrub every line of them too
            for line in f["content"].splitlines():
                for m in re.findall(r"[A-Za-z0-9_-]{16,128}", line):
                    self.secrets.append(m)

    def scrub(self, text):
        t = str(text or "")
        for s in self.secrets:
            if s:
                t = t.replace(s, "***")
        return t[-600:]

    def run(self, argv, input=None, env=None, timeout=300, check=True, what=None):
        r = subprocess.run(argv, shell=False, input=input, capture_output=True, text=True, timeout=timeout, env=env or ROOT_ENV, cwd="/")
        if check and r.returncode != 0:
            raise Failed(f"{what or os.path.basename(argv[0])} failed (rc {r.returncode}): {self.scrub(r.stderr or r.stdout)}")
        return r


def atomic_write(path, data, mode, uid=0, gid=0):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.ou-tmp-{secrets.token_hex(4)}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(data)
        os.chown(tmp, uid, gid)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read(path):
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return None


# ---------------------------------------------------------------- cfg.hosts
def hosts(p, x):
    cur = read(HOSTS) or ""
    keep, skip = [], False
    for ln in cur.splitlines():
        if ln == HOSTS_BEGIN:
            skip = True
            continue
        if ln == HOSTS_END:
            skip = False
            continue
        if not skip:
            keep.append(ln)
    block = [HOSTS_BEGIN] + [f"{e['ip']} {' '.join(e['names'])}" for e in p["entries"]] + [HOSTS_END]
    new = "\n".join(keep).rstrip("\n") + "\n" + "\n".join(block) + "\n"
    if new != cur:
        atomic_write(HOSTS, new, 0o644)
    return {"entries": len(p["entries"]), "changed": new != cur}


# ---------------------------------------------------------------- cfg.tls
def _pubkey(x, kind, path):
    argv = [BIN["openssl"], "x509", "-noout", "-pubkey", "-in", path] if kind == "cert" else [BIN["openssl"], "pkey", "-pubout", "-in", path]
    return x.run(argv, what="openssl").stdout.strip()


def tls(p, x):
    os.makedirs(TLS_DIR, mode=0o755, exist_ok=True)
    os.chmod(TLS_DIR, 0o755)
    crt, key = os.path.join(TLS_DIR, p["name"] + ".crt"), os.path.join(TLS_DIR, p["name"] + ".key")
    # "deployment" is the VM's own scope (ca.crt, read by LDAP, gromox, the TLS proxies); another name is a further scope served by the shared
    # edge of a multi-tenant deployment: its CA is kept beside it (<name>.ca.crt) and trusted under its own file
    cafile = os.path.join(TLS_DIR, "ca.crt" if p["name"] == "deployment" else p["name"] + ".ca.crt")
    trust = CA_TRUST if p["name"] == "deployment" else CA_TRUST.replace("ou-deployment-ca", "ou-" + p["name"] + "-ca")
    atomic_write(cafile, p["ca_pem"], 0o644)
    atomic_write(key, p["key_pem"], 0o600)
    atomic_write(crt, p["cert_pem"], 0o644)
    if _pubkey(x, "cert", crt) != _pubkey(x, "key", key):
        raise Failed("the certificate does not belong to the private key")
    x.run([BIN["openssl"], "verify", "-CAfile", cafile, crt], what="openssl verify")
    changed = read(trust) != p["ca_pem"]
    if changed:
        atomic_write(trust, p["ca_pem"], 0o644)
        x.run([BIN["update-ca"]], what="update-ca-certificates")
    return {"name": p["name"], "ca_trust_updated": changed}


# ---------------------------------------------------------------- OpenLDAP
def ssha(pw):
    salt = secrets.token_bytes(8)
    return "{SSHA}" + base64.b64encode(hashlib.sha1(pw.encode() + salt).digest() + salt).decode()


def ldapi(x, ldif, what, add=False):
    argv = [BIN["ldapmodify"], "-Q", "-Y", "EXTERNAL", "-H", "ldapi:///"] + (["-a"] if add else [])
    return x.run(argv, input=ldif, what=what)


def ldap_search(x, base, flt, attrs, scope="sub", limit=None):
    """`limit`: a size limit (-z); hitting it (rc 4, sizeLimitExceeded) still returns the entries read so far."""
    r = x.run([BIN["ldapsearch"], "-LLL", "-o", "ldif-wrap=no", "-Q", "-Y", "EXTERNAL", "-H", "ldapi:///", "-s", scope, "-b", base,
               *(["-z", str(limit)] if limit else []), flt, *attrs], check=False, what="ldapsearch")
    if r.returncode == 32:   # no such object
        return ""
    if limit and r.returncode == 4:
        return r.stdout
    if r.returncode != 0:
        raise Failed(f"ldapsearch failed (rc {r.returncode}): {x.scrub(r.stderr)}")
    return r.stdout


def exists(x, dn):
    return "dn:" in ldap_search(x, dn, "(objectClass=*)", ["1.1"], scope="base")


def _debconf(x, domain, org, pw):
    sel = "\n".join([f"slapd slapd/internal/generated_adminpw password {pw}", f"slapd slapd/internal/adminpw password {pw}",
                     f"slapd slapd/password1 password {pw}", f"slapd slapd/password2 password {pw}", f"slapd slapd/domain string {domain}",
                     f"slapd shared/organization string {org}", "slapd slapd/no_configuration boolean false",
                     "slapd slapd/purge_database boolean true", "slapd slapd/move_old_database boolean true"]) + "\n"
    x.run([BIN["debconf-set"]], input=sel, what="debconf-set-selections")


def _debconf_clear(x):
    x.run([BIN["debconf-set"]], input="".join(f"slapd {q} password \n" for q in ("slapd/internal/generated_adminpw", "slapd/internal/adminpw",
                                                                              "slapd/password1", "slapd/password2")), what="debconf-set-selections")


# what a person may change about themselves through the sign-in service (portal account page); mail and uid are never in it
LDAP_SELF_ATTRS = ("givenName", "sn", "cn", "displayName", "telephoneNumber", "mobile")


def ldap_init(p, x):
    if x.run([BIN["dpkg-query"], "-W", "-f=${Status}", "slapd"], check=False).stdout.strip() != "install ok installed":
        raise Failed("slapd is not installed (pkg.install_pinned must run first)")
    base = c.base_dn(p["domain"])
    bind_dn = f"cn=svc-bind,ou=system,{base}"
    created, reconfigured = [], False
    if f"olcSuffix: {base}" not in ldap_search(x, "cn=config", "(olcSuffix=*)", ["olcSuffix"]):
        _debconf(x, p["domain"], p["organization"], p["admin_password"])   # first configuration for THIS domain (the package install had no answers)
        try:
            x.run([BIN["dpkg-reconfigure"], "-f", "noninteractive", "slapd"], timeout=600, what="dpkg-reconfigure slapd")
        finally:
            _debconf_clear(x)
        reconfigured = True
    # TLS: the deployment certificate, readable by the openldap group only
    gid = pwd.getpwnam("openldap").pw_gid
    os.makedirs(LDAP_TLS, exist_ok=True)
    os.chown(LDAP_TLS, 0, gid)
    os.chmod(LDAP_TLS, 0o750)
    for src, dst, mode, g in (("ca.crt", "ca.crt", 0o644, 0), (p["tls_name"] + ".crt", "server.crt", 0o644, 0), (p["tls_name"] + ".key", "server.key", 0o640, gid)):
        data = read(os.path.join(TLS_DIR, src))
        if data is None:
            raise Failed(f"missing {src}: cfg.tls must run first")
        atomic_write(os.path.join(LDAP_TLS, dst), data, mode, 0, g)
    d = read(SLAPD_DEFAULT) or ""
    want = 'SLAPD_SERVICES="ldap://127.0.0.1:389/ ldaps:/// ldapi:///"'
    nd = re.sub(r"(?m)^SLAPD_SERVICES=.*$", want, d) if re.search(r"(?m)^SLAPD_SERVICES=", d) else d + want + "\n"
    if nd != d:
        atomic_write(SLAPD_DEFAULT, nd, 0o644)
    ldapi(x, "dn: cn=config\nchangetype: modify\nreplace: olcTLSCACertificateFile\nolcTLSCACertificateFile: /etc/ldap/tls/ca.crt\n-\n"
             "replace: olcTLSCertificateFile\nolcTLSCertificateFile: /etc/ldap/tls/server.crt\n-\nreplace: olcTLSCertificateKeyFile\n"
             "olcTLSCertificateKeyFile: /etc/ldap/tls/server.key\n-\nreplace: olcTLSProtocolMin\nolcTLSProtocolMin: 3.3\n", "TLS configuration")
    if read(LDAP_CONF) is None:   # client defaults for admins' tools on this VM (libldap-common is only a Recommends of the packages we install)
        atomic_write(LDAP_CONF, f"# generated by ou-agent (cfg.ldap_init)\nBASE {base}\nURI ldaps://ldap.{p['domain']}\nTLS_CACERT /etc/ssl/certs/ca-certificates.crt\n", 0o644)
    x.run([BIN["systemctl"], "enable", "slapd"], what="systemctl enable slapd")
    x.run([BIN["systemctl"], "restart", "slapd"], what="systemctl restart slapd")
    loaded = ldap_search(x, "cn=module{0},cn=config", "(objectClass=*)", ["olcModuleLoad"], scope="base")
    for m in ("memberof", "refint", "ppolicy"):
        if not re.search(rf"(?m)^olcModuleLoad: (\{{\d+\}})?{m}(\.la)?$", loaded):
            ldapi(x, f"dn: cn=module{{0}},cn=config\nchangetype: modify\nadd: olcModuleLoad\nolcModuleLoad: {m}\n", f"module {m}")
    db = re.search(r"(?m)^dn: (olcDatabase=\{\d+\}mdb,cn=config)$", ldap_search(x, "cn=config", f"(olcSuffix={base})", ["1.1"]))
    if not db:
        raise Failed("no database for the directory suffix")
    db = db.group(1)
    if "dn:" not in ldap_search(x, db, "(olcOverlay=memberof)", ["1.1"]):
        ldapi(x, f"dn: olcOverlay=memberof,{db}\nobjectClass: olcOverlayConfig\nobjectClass: olcMemberOf\nolcOverlay: memberof\nolcMemberOfRefInt: TRUE\n"
                 f"olcMemberOfGroupOC: groupOfNames\nolcMemberOfMemberAD: member\nolcMemberOfMemberOfAD: memberOf\n\n"
                 f"dn: olcOverlay=refint,{db}\nobjectClass: olcOverlayConfig\nobjectClass: olcRefintConfig\nolcOverlay: refint\n"
                 f"olcRefintAttribute: member\nolcRefintAttribute: memberOf\n\n"
                 f"dn: olcOverlay=ppolicy,{db}\nobjectClass: olcOverlayConfig\nobjectClass: olcPPolicyConfig\nolcOverlay: ppolicy\n"
                 f"olcPPolicyDefault: cn=default,ou=policies,{base}\nolcPPolicyHashCleartext: TRUE\nolcPPolicyUseLockout: TRUE\n", "overlays", add=True)
    root = "gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth"
    writer_dn = f"cn=svc-idp,ou=system,{base}"
    # svc-idp (the sign-in service, Keycloak in WRITABLE mode) sets passwords (=w: never reads a hash) and the self-editable profile attributes of
    # people only; svc-bind (shared by files, mail and sign-in) keeps read-only access. Without a writer password the entry does not exist.
    ldapi(x, f"dn: {db}\nchangetype: modify\nreplace: olcAccess\n"
             f"olcAccess: {{0}}to * by dn.exact=\"{root}\" manage by * break\n"
             f"olcAccess: {{1}}to dn.subtree=\"ou=people,{base}\" attrs=userPassword by self write by dn.exact=\"{writer_dn}\" =w by anonymous auth by * none\n"
             f"olcAccess: {{2}}to attrs=userPassword by self write by anonymous auth by * none\n"
             f"olcAccess: {{3}}to attrs=pwdAccountLockedTime,pwdFailureTime,pwdChangedTime,pwdHistory by dn.exact=\"{bind_dn}\" read by dn.exact=\"{writer_dn}\" read by * none\n"
             f"olcAccess: {{4}}to dn.subtree=\"ou=people,{base}\" attrs={','.join(LDAP_SELF_ATTRS)} by dn.exact=\"{writer_dn}\" write by dn.exact=\"{bind_dn}\" read by self read by * none\n"
             f"olcAccess: {{5}}to * by dn.exact=\"{bind_dn}\" read by dn.exact=\"{writer_dn}\" read by self read by * none\n-\n"
             "replace: olcDbIndex\nolcDbIndex: objectClass eq\nolcDbIndex: cn,uid,mail eq,sub\nolcDbIndex: member,memberOf eq\n"
             "olcDbIndex: entryUUID,entryCSN eq\n", "access rules")
    entries = [(f"ou={o},{base}", f"objectClass: organizationalUnit\nou: {o}\n") for o in ("people", "groups", "system", "policies")]
    entries.append((f"cn=default,ou=policies,{base}", "objectClass: device\nobjectClass: pwdPolicy\ncn: default\npwdAttribute: userPassword\n"
                    "pwdLockout: TRUE\npwdLockoutDuration: 0\npwdMaxFailure: 10\npwdFailureCountInterval: 300\npwdAllowUserChange: TRUE\npwdMinLength: 8\n"))
    entries.append((bind_dn, f"objectClass: organizationalRole\nobjectClass: simpleSecurityObject\ncn: svc-bind\nuserPassword: {ssha(p['bind_password'])}\n"))
    entries += [(f"cn={g},ou=groups,{base}", f"objectClass: groupOfNames\ncn: {g}\nmember: {bind_dn}\n") for g in p["groups"]]
    for dn, body in entries:
        if not exists(x, dn):
            ldapi(x, f"dn: {dn}\n{body}", f"add {dn.split(',')[0]}", add=True)
            created.append(dn.split(",")[0])
    ldapi(x, f"dn: {bind_dn}\nchangetype: modify\nreplace: userPassword\nuserPassword: {ssha(p['bind_password'])}\n", "bind password")
    if p.get("writer_password"):
        if not exists(x, writer_dn):
            ldapi(x, f"dn: {writer_dn}\nobjectClass: organizationalRole\nobjectClass: simpleSecurityObject\ncn: svc-idp\n"
                     f"userPassword: {ssha(p['writer_password'])}\n", "add cn=svc-idp", add=True)
            created.append("cn=svc-idp")
        ldapi(x, f"dn: {writer_dn}\nchangetype: modify\nreplace: userPassword\nuserPassword: {ssha(p['writer_password'])}\n", "writer password")
    return {"suffix": base, "reconfigured": reconfigured, "created": created}


def ldap_user(p, x):
    base = c.base_dn(p["domain"])
    dn = f"uid={p['uid']},ou=people,{base}"
    created = not exists(x, dn)
    if created:
        ldapi(x, f"dn: {dn}\nobjectClass: inetOrgPerson\nobjectClass: organizationalPerson\nobjectClass: person\nuid: {p['uid']}\n"
                 f"cn: {p['given_name']} {p['surname']}\nsn: {p['surname']}\ngivenName: {p['given_name']}\n"
                 f"displayName: {p['given_name']} {p['surname']}\nmail: {p['mail']}\nuserPassword: {ssha(p['password'])}\n", "add user", add=True)
    else:
        ldapi(x, f"dn: {dn}\nchangetype: modify\nreplace: userPassword\nuserPassword: {ssha(p['password'])}\n", "user password")
    added = []
    for g in p["groups"]:
        gdn = f"cn={g},ou=groups,{base}"
        if not exists(x, gdn):
            raise Failed(f"group {g} does not exist (cfg.ldap_init creates the groups)")
        if f"member: {dn}" not in ldap_search(x, gdn, "(objectClass=*)", ["member"], scope="base"):
            ldapi(x, f"dn: {gdn}\nchangetype: modify\nadd: member\nmember: {dn}\n", f"group {g}")
            added.append(g)
    return {"uid": p["uid"], "created": created, "groups_added": added}


# ---------------------------------------------------------------- directory accounts (list, groups, lock, delete)
# Fixed bases (ou=people / ou=groups of the domain's suffix), fixed filters, fixed attribute lists; the only request value in a DN is the
# regex-checked uid or group name. Locking uses the ppolicy overlay cfg.ldap_init loads (olcPPolicyUseLockout): pwdAccountLockedTime
# 000001010000Z is the administrative lock (binds refused until it is removed); the password itself is never touched.
MAX_LIST = 2000
LIST_BUDGET = 48 * 1024          # bytes of JSON result; the agent's cfg result cap and the ICS response cap are above this
ADMIN_LOCK = "000001010000Z"
PROTECTED_UID = "ou-admin"
ORG_ADMIN = "org-admin"
PEOPLE_ATTRS = ("uid", "mail", "displayName", "givenName", "sn", "cn", "pwdAccountLockedTime")   # never a password attribute


def ldif_entries(text):
    """[(dn, {attr_lowercase: [values]})] from ldapsearch LDIF: folded lines, `::` base64 values, comments; attribute options are dropped,
    `:<` URL values ignored, password attributes never kept."""
    lines = []
    for ln in (text or "").splitlines():
        if ln.startswith(" ") and lines:
            lines[-1] += ln[1:]
        else:
            lines.append(ln)
    out, dn, attrs = [], None, {}
    for ln in lines + [""]:
        if not ln.strip():
            if dn is not None:
                out.append((dn, attrs))
            dn, attrs = None, {}
            continue
        if ln.startswith("#") or ":" not in ln:
            continue
        name, _, val = ln.partition(":")
        if val.startswith(":"):
            try:
                val = base64.b64decode(val[1:].strip(), validate=True).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                continue
        elif val.startswith("<"):
            continue
        else:
            val = val[1:] if val.startswith(" ") else val
        name = name.split(";")[0].strip().lower()
        if name == "dn":
            dn = val
        elif dn is not None and "password" not in name and name not in ("pwdhistory",):
            attrs.setdefault(name, []).append(val)
    return out


def _people_dn(uid, base):
    return f"uid={uid},ou=people,{base}"


def _member_uid(member, base):
    """The uid of a member DN directly under ou=people of this suffix, else None (svc-bind and other non-people members)."""
    rdn, _, rest = member.partition(",")
    if _dnkey(rest) != f"ou=people,{base}".lower() or not rdn.strip().lower().startswith("uid="):
        return None
    return rdn.strip()[4:]


def _groups(x, base):
    """{cn: [member DNs]} of every groupOfNames under ou=groups."""
    out = {}
    for dn, a in ldif_entries(ldap_search(x, f"ou=groups,{base}", "(objectClass=groupOfNames)", ["cn", "member"], scope="one", limit=MAX_LIST)):
        cn = (a.get("cn") or [dn.split(",")[0].partition("=")[2]])[0]
        out[cn] = a.get("member", [])
    return out


def _dnkey(dn):
    return re.sub(r"\s*,\s*", ",", dn.strip()).lower()


def _is_member(members, dn):
    return _dnkey(dn) in {_dnkey(m) for m in members}


def _remove_member(x, base, group, members, dn):
    """Delete one member value; groupOfNames needs a member, so a group the person was alone in keeps the bind account (as cfg.ldap_init creates it)."""
    gdn = f"cn={group},ou=groups,{base}"
    if len([m for m in members if not _is_member([m], dn)]) == 0:
        ldapi(x, f"dn: {gdn}\nchangetype: modify\nreplace: member\nmember: cn=svc-bind,ou=system,{base}\n", f"group {group}")
    else:
        ldapi(x, f"dn: {gdn}\nchangetype: modify\ndelete: member\nmember: {dn}\n", f"group {group}")


def _last_org_admin(groups, base, dn):
    """True when `dn` is the only person in org-admin (removing it would leave the organization without an administrator)."""
    members = groups.get(ORG_ADMIN)
    if members is None or not _is_member(members, dn):
        return False
    return not [m for m in members if _member_uid(m, base) is not None and not _is_member([m], dn)]


def ldap_list(p, x):
    base = c.base_dn(p["domain"])
    groups = _groups(x, base)
    people_ldif = ldap_search(x, f"ou=people,{base}", "(objectClass=inetOrgPerson)", list(PEOPLE_ATTRS), scope="one", limit=MAX_LIST)
    people = []
    for dn, a in ldif_entries(people_ldif)[:MAX_LIST]:
        uid = (a.get("uid") or [None])[0]
        if uid is None:
            continue
        first = lambda k: (a.get(k) or [""])[0]   # noqa: E731
        people.append({"uid": uid, "mail": first("mail"), "display_name": first("displayname") or first("cn"), "given_name": first("givenname"),
                       "surname": first("sn"), "groups": sorted(g for g, m in groups.items() if _is_member(m, dn)),
                       "locked": bool(a.get("pwdaccountlockedtime"))})
    people.sort(key=lambda e: e["uid"])
    glist = [{"cn": g, "members": sorted(u for u in (_member_uid(m, base) for m in groups[g]) if u)} for g in sorted(groups)][:MAX_LIST]
    truncated = len(people) >= MAX_LIST or len(groups) >= MAX_LIST
    res = {"suffix": base, "people": people, "groups": glist, "truncated": truncated}
    while len(json.dumps(res)) > LIST_BUDGET:   # keep the result within what the agent relays: people first, then the longest member lists
        res["truncated"] = True
        if res["people"]:
            del res["people"][-max(1, len(res["people"]) // 10):]
            continue
        big = max(res["groups"], key=lambda g: len(g["members"]), default=None)
        if big is None or not big["members"]:
            res["groups"] = res["groups"][:len(res["groups"]) // 2]
            continue
        del big["members"][-max(1, len(big["members"]) // 10):]
    return res


def ldap_groups(p, x):
    base = c.base_dn(p["domain"])
    dn = _people_dn(p["uid"], base)
    if not exists(x, dn):
        raise Failed(f"person {p['uid']} does not exist")
    groups = _groups(x, base)
    unknown = sorted(g for g in (*p["add"], *p["remove"]) if g not in groups)
    if unknown:
        raise Failed("unknown group: " + ", ".join(unknown))
    if ORG_ADMIN in p["remove"] and _last_org_admin(groups, base, dn):
        raise Failed(f"{p['uid']} is the last member of {ORG_ADMIN}")
    added, removed = [], []
    for g in p["add"]:
        if not _is_member(groups[g], dn):
            ldapi(x, f"dn: cn={g},ou=groups,{base}\nchangetype: modify\nadd: member\nmember: {dn}\n", f"group {g}")
            added.append(g)
    for g in p["remove"]:
        if _is_member(groups[g], dn):
            _remove_member(x, base, g, groups[g], dn)
            removed.append(g)
    return {"uid": p["uid"], "added": added, "removed": removed}


def ldap_lock(p, x):
    base = c.base_dn(p["domain"])
    dn = _people_dn(p["uid"], base)
    found = ldif_entries(ldap_search(x, dn, "(objectClass=*)", ["pwdAccountLockedTime"], scope="base"))
    if not found:
        raise Failed(f"person {p['uid']} does not exist")
    cur = found[0][1].get("pwdaccountlockedtime", [])
    changed = False
    if p["locked"] and cur != [ADMIN_LOCK]:   # also turns a failure lockout (a timestamp) into the administrative lock
        ldapi(x, f"dn: {dn}\nchangetype: modify\nreplace: pwdAccountLockedTime\npwdAccountLockedTime: {ADMIN_LOCK}\n", "lock")
        changed = True
    elif not p["locked"] and cur:
        ldapi(x, f"dn: {dn}\nchangetype: modify\ndelete: pwdAccountLockedTime\n", "unlock")
        changed = True
    return {"uid": p["uid"], "locked": p["locked"], "changed": changed}


def ldap_delete(p, x):
    if p["uid"] == PROTECTED_UID:   # cfgspec refuses it too; the helper never trusts the spool
        raise Failed(f"{PROTECTED_UID} cannot be deleted")
    base = c.base_dn(p["domain"])
    dn = _people_dn(p["uid"], base)
    if not exists(x, dn):
        return {"uid": p["uid"], "deleted": False, "groups_removed": []}
    groups = _groups(x, base)
    if _last_org_admin(groups, base, dn):
        raise Failed(f"{p['uid']} is the last member of {ORG_ADMIN}")
    removed = []
    for g in sorted(groups):
        if _is_member(groups[g], dn):
            _remove_member(x, base, g, groups[g], dn)
            removed.append(g)
    ldapi(x, f"dn: {dn}\nchangetype: delete\n", "delete person")
    return {"uid": p["uid"], "deleted": True, "groups_removed": removed}


# ---------------------------------------------------------------- PostgreSQL
def pg_db(p, x):
    x.run([BIN["systemctl"], "enable", "--now", "postgresql"], what="systemctl enable postgresql")
    r, d, pw = p["role"], p["database"], p["password"]
    sql = (f"\\set ON_ERROR_STOP on\n"
           f"SELECT 'CREATE ROLE {r} LOGIN' WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{r}')\\gexec\n"
           f"ALTER ROLE {r} WITH LOGIN PASSWORD '{pw}';\n"
           f"SELECT 'CREATE DATABASE {d} OWNER {r}' WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = '{d}')\\gexec\n")
    x.run([BIN["runuser"], "-u", "postgres", "--", BIN["psql"], "-q", "-X", "-d", "postgres", "-f", "-"], input=sql, timeout=120, what="psql")
    return {"role": r, "database": d}


# ---------------------------------------------------------------- podman (as the service user)
def svc_env():
    u = pwd.getpwnam(SERVICE_USER)
    return {"PATH": "/usr/bin:/bin", "LANG": "C", "HOME": SERVICE_HOME, "XDG_RUNTIME_DIR": f"/run/user/{u.pw_uid}",
            "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{u.pw_uid}/bus"}


def as_svc(x, argv, **kw):
    env = svc_env()
    return x.run([BIN["runuser"], "-u", SERVICE_USER, "--", "/usr/bin/env", "-i", *[f"{k}={v}" for k, v in env.items()], *argv], **kw)


def podman_secret(p, x):
    # no `create --replace`: podman 4.9.3 (noble) fails it with "deleting secret: no secret data" when an earlier attempt left a broken entry
    as_svc(x, [BIN["podman"], "secret", "rm", p["name"]], check=False)
    as_svc(x, [BIN["podman"], "secret", "create", p["name"], "-"], input=p["value"], what="podman secret create")
    return {"name": p["name"]}


def volume_files(p, x):
    digest = p["image"].split("@", 1)[1].split(":", 1)[1]
    if not os.path.exists(os.path.join(VERIFIED_DIR, digest + ".json")):
        raise Failed("the image was not pulled and verified on this node (podman.pull_verified must run first)")
    vol = f"ou-{p['component']}-{p['volume']}"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as t:
        dirs = sorted({"/".join(f["path"].split("/")[:i]) for f in p["files"] for i in range(1, f["path"].count("/") + 1)})
        for dname in dirs:
            ti = tarfile.TarInfo(dname)
            ti.type, ti.mode, ti.mtime = tarfile.DIRTYPE, 0o750, int(time.time())
            t.addfile(ti)
        for f in p["files"]:
            data = f["content"].encode()
            ti = tarfile.TarInfo(f["path"])
            ti.size, ti.mode, ti.mtime = len(data), f["mode"], int(time.time())
            t.addfile(ti, io.BytesIO(data))
    as_svc(x, [BIN["podman"], "volume", "create", "--ignore", "--label", f"ou.component={p['component']}", vol], what="podman volume create")
    r = subprocess.run([BIN["runuser"], "-u", SERVICE_USER, "--", "/usr/bin/env", "-i", *[f"{k}={v}" for k, v in svc_env().items()],
                        # cgroupfs + --cgroups=disabled: this helper is a SYSTEM unit (ou-rb-cfg@), so the default systemd cgroup manager would
                        # ask the service user's systemd for a scope it cannot move this process into (crun: "create directory
                        # .../libpod-<id>.scope/container: No such file or directory", first real VM 2026-11-19). A one-shot copy container
                        # needs no cgroup; it stays in this unit's cgroup and its limits. The long-running units still run under the user manager.
                        BIN["podman"], "--cgroup-manager=cgroupfs", "run", "--cgroups=disabled", "--rm", "-i", "--pull=never", "--network=none",
                        "--user", "0", "--entrypoint", "/bin/sh",
                        "-v", f"{vol}:/d", p["image"], "-c", f"tar -xf - -C /d && chown -R {p['owner']} /d"],
                       input=buf.getvalue(), capture_output=True, timeout=300, cwd="/")
    if r.returncode != 0:
        raise Failed(f"writing into volume {vol} failed (rc {r.returncode}): {x.scrub(r.stderr.decode('utf-8', 'replace'))}")
    return {"volume": vol, "files": [f["path"] for f in p["files"]]}


# ---------------------------------------------------------------- nginx
NGINX_SITE = """# generated by ou-agent (cfg.nginx_site); do not edit
server {{
  listen 80;
  listen [::]:80;
  server_name {names};
  location /.well-known/acme-challenge/ {{ root {acme_root}; default_type text/plain; try_files $uri =404; }}
  location / {{ return 301 https://$host$request_uri; }}
}}
server {{
  listen 443 ssl;
  listen [::]:443 ssl;
  server_name {names};
  ssl_certificate {tls}/{cert}.crt;
  ssl_certificate_key {tls}/{cert}.key;
  ssl_protocols TLSv1.2 TLSv1.3;
  client_max_body_size {body};
  proxy_request_buffering off;
  proxy_buffering off;
  proxy_read_timeout 3600s;
  proxy_buffer_size 16k;
  proxy_buffers 8 16k;
{lockdown}{root_redirect}  location / {{
    proxy_pass {upstream};{upstream_tls}
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Port 443;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $ou_connection_upgrade;
  }}
}}
"""


# Administration happens in the Office Unbound console and portal (owner 2026-11-21: "make sure all apps dont have their own admin settings
# (should all be done via OUR portal)"). Each app's own administration surfaces are therefore not served on its public name: fixed rules per
# app, chosen by the closed `lockdown` parameter (the ICS sends a profile name, never nginx text). What each app still serves: the comments below.
LOCKDOWN = {
    # Keycloak 26: admin console (/admin/, /admin/master/console/, /admin/<realm>/console/) and the admin REST API (/admin/realms/...) under
    # /admin; the master realm is kcadmin's (its sign-in, tokens for admin-cli, its account console). Nothing of the deployment uses either
    # through the gateway: the realm is imported from the data volume, health checks use 127.0.0.1:8080/9000 on the identity VM, the portal uses
    # /realms/<realm>/ (sign-in, account REST). kcadmin stays for setup and recovery ON the identity VM (kcadm.sh --server http://127.0.0.1:8080).
    "keycloak": ("  # administration through the Office Unbound console: no Keycloak admin console/API and no master realm on this name\n"
                 "  location ^~ /admin { return 404; }\n"
                 "  location ^~ /realms/master/ { return 404; }\n"
                 "  location = /realms/master { return 404; }\n"),
    # OpenCloud: the Web admin-settings app (users, groups, roles, spaces, general) and the server APIs behind it: Graph writes on users,
    # groups (incl. members, appRoleAssignments) and education, and the settings service's role-assignment and bundle writes. Reads stay (the
    # share dialog searches users and groups); /graph/.../drives stays (space quotas are set by the ICS, mailadmin.py); /graph/v1.0/me stays.
    "opencloud": ("  # administration through the Office Unbound console: no OpenCloud admin-settings app, no user/group/role writes on this name\n"
                  "  location ^~ /admin-settings { return 404; }\n"
                  "  location ~ ^/api/v0/settings/(assignments-add|assignments-remove|bundle-save|bundles-add-setting|bundles-remove-setting)$ { return 403; }\n"
                  "  set $ou_admin_write \"\";\n"
                  "  if ($request_method !~ ^(GET|HEAD|OPTIONS)$) { set $ou_admin_write \"w\"; }\n"
                  "  if ($uri ~ \"^/graph/(v1\\.0|v1beta1)/(users|groups|education)(/|$)\") { set $ou_admin_write \"${ou_admin_write}a\"; }\n"
                  "  if ($ou_admin_write = \"wa\") { return 403; }\n"),
    # Collabora Online 26.04: admin console pages and bundle (/browser/<hash or dist>/admin/...), its websocket (/cool/adminws) and the
    # Prometheus metrics (/cool/getMetrics); admin_console.enable=false in the image entrypoint already refuses them, this keeps them off the
    # public name even if that setting changes. /hosting/discovery, /hosting/capabilities, /cool/<WOPISrc>/ws, /cool/clipboard stay.
    "collabora": ("  # administration through the Office Unbound console: no Collabora admin console or metrics on this name\n"
                  "  location ~ ^/(browser|loleaflet)/[^/]+/admin/ { return 404; }\n"
                  "  location ~ ^/(cool|lool)/(adminws|getMetrics)(/|$) { return 404; }\n"
                  # the conversion service (any file in, any format out) is not used through the public name (the office health check converts
                  # on the node itself); Collabora trusts the gateway as a private address, so without this it is a free converter for anyone
                  "  location ~ ^/(cool|lool)/convert-to(/|$) { return 404; }\n"),
    # grommunio: the admin API (/api/v1/) and admin web UI are separate packages (grommunio-admin-api/-web) that the groupware component does not
    # install; refused here as well so an added package never appears on the public mail name. Webmail, EWS, MAPI, DAV, ActiveSync stay.
    "groupware": ("  # administration through the Office Unbound console: no grommunio admin API or admin UI on this name\n"
                  "  location ^~ /api/v1/ { return 404; }\n"
                  "  location ^~ /admin { return 404; }\n"),
}


def nginx_site(p, x):
    for f in (p["tls_name"] + ".crt", p["tls_name"] + ".key"):
        if not os.path.exists(os.path.join(TLS_DIR, f)):
            raise Failed(f"missing {f}: cfg.tls must run first")
    atomic_write(NGINX_MAP, "# generated by ou-agent (cfg.nginx_site)\nmap $http_upgrade $ou_connection_upgrade {\n  default upgrade;\n  '' close;\n}\n", 0o644)
    path, link = os.path.join(NGINX_AVAIL, "ou-" + p["name"]), os.path.join(NGINX_ENABLED, "ou-" + p["name"])
    old = read(path)
    body = f"{p['max_body_mb']}m" if p["max_body_mb"] else "0"
    up_tls = ""
    up_ca = p.get("upstream_ca") or p["tls_name"]   # which CA verifies the upstream (the site may serve a public certificate)
    cafile = "ca.crt" if up_ca == "deployment" else up_ca + ".ca.crt"
    if p["upstream_name"]:   # another VM: TLS to it, its certificate verified against the deployment CA for exactly this name
        up_tls = (f"\n    proxy_ssl_verify on;\n    proxy_ssl_verify_depth 2;\n    proxy_ssl_trusted_certificate {TLS_DIR}/{cafile};\n"
                  f"    proxy_ssl_name {p['upstream_name']};\n    proxy_ssl_server_name on;\n    proxy_ssl_protocols TLSv1.2 TLSv1.3;")
    rr = f"  location = / {{ return 302 {p['root_redirect']}; }}\n" if p.get("root_redirect") else ""
    ld = LOCKDOWN[p["lockdown"]] if p.get("lockdown") else ""
    atomic_write(path, NGINX_SITE.format(names=" ".join(p["server_names"]), tls=TLS_DIR, cert=p["tls_name"], body=body, upstream=p["upstream"],
                                         upstream_tls=up_tls, acme_root=ACME_ROOT, root_redirect=rr, lockdown=ld), 0o644)
    if not os.path.islink(link):
        if os.path.lexists(link):
            os.unlink(link)
        os.symlink(path, link)
    if os.path.lexists(os.path.join(NGINX_ENABLED, "default")):
        os.unlink(os.path.join(NGINX_ENABLED, "default"))
    t = x.run([BIN["nginx"], "-t"], check=False)
    if t.returncode != 0:
        if old is None:
            os.unlink(link)
            os.unlink(path)
        else:
            atomic_write(path, old, 0o644)
        raise Failed("nginx refused the configuration: " + x.scrub(t.stderr))
    x.run([BIN["systemctl"], "enable", "--now", "nginx"], what="systemctl enable nginx")
    x.run([BIN["systemctl"], "reload", "nginx"], what="systemctl reload nginx")
    return {"site": "ou-" + p["name"], "server_names": p["server_names"]}


# ---------------------------------------------------------------- cfg.firewall
def firewall(p, x):
    lines = ["# generated by ou-agent (cfg.firewall): peer allowances between this deployment's VMs; do not edit",
             "flush set inet ou_guest cfg_allow4"]
    if p["rules"]:
        lines.append("add element inet ou_guest cfg_allow4 { " + ", ".join(f"{r['source']} . {r['proto']} . {r['port']}" for r in p["rules"]) + " }")
    text = "\n".join(lines) + "\n"
    os.makedirs(os.path.dirname(NFT_ALLOW), mode=0o755, exist_ok=True)
    tmp = NFT_ALLOW + ".new"
    atomic_write(tmp, text, 0o644)
    try:
        x.run([BIN["nft"], "-c", "-f", tmp], what="nft check (the first-boot ruleset must provide set cfg_allow4)")
        x.run([BIN["nft"], "-f", tmp], what="nft")
        os.replace(tmp, NFT_ALLOW)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return {"rules": len(p["rules"])}


# ---------------------------------------------------------------- cfg.gromox (groupware node)
# Ported from the lab scripts blueprints/lab/spike-groupware/{lab-configure,lab-ldap,gw-mta,lab-nginx,lab-apps,ou-zcore-lockdown}.sh and
# gw-ldap-sync.py (57 lab checks, docs/status/groupware-lab-results.md), for the noble packages ou-gromox 3.13-ou3+noble1 and grommunio web/dav/sync.
GX_ETC, GX_TLS = "/etc/gromox", "/etc/gromox/tls"
GX_USERS, GX_DOMAINS = "/var/lib/gromox/user", "/var/lib/gromox/domain"
GW_SITE = "ou-groupware"
# exmdb (the information store, hosted by gromox-http) listens on [::1]:5000 by default (exch/exmdb/parser.cpp), but its clients (zcore =
# webmail, midb, imap, delivery) dial the homeserver name "localhost" (lib/exmdb_client2.cpp, users.homeserver=0) through libHX's
# HX_inet_connect: AF_INET6 + AI_V4MAPPED. The golden image's /etc/hosts maps localhost to 127.0.0.1 only, so the name becomes
# ::ffff:127.0.0.1 and every store open fails ("exmdb_client: HX_inet_connect to [localhost]:5000: Connection refused"; webmail HTTP 500
# after sign-in). Listen on both loopbacks and allow both peers (an IPv4 peer is seen, and matched, in its RFC 4291 mapped form), so the
# store is reachable however "localhost" resolves.
GX_EXMDB_LISTEN = "[::1]:5000 127.0.0.1:5000"
GX_EXMDB_ALLOW = "::1 ::ffff:127.0.0.1"
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
PR_DISPLAY_TYPE_EX, PR_DISPLAY_NAME = 0x39050003, 0x3001001F
GX_SERVICES = ("gromox-event", "gromox-timer", "gromox-midb", "gromox-zcore", "gromox-http", "gromox-delivery", "gromox-delivery-queue", "gromox-imap")
GW_NEEDS = ("ou-gromox", "ou-gromox-php-mapi", "ou-grommunio-web", "ou-grommunio-dav", "ou-grommunio-sync", "mariadb-server", "postfix", "postfix-mysql",
            "sasl2-bin", "libsasl2-modules", "nginx", "ldap-utils")

GW_NGINX = """# generated by ou-agent (cfg.gromox); do not edit
upstream ou_fpm_web {{ server unix:/run/php-fpm/php-grommunio-web-fpm.sock; }}
upstream ou_fpm_sync {{ server unix:/run/php-fpm/php-grommunio-sync-fpm.sock; }}
upstream ou_fpm_dav {{ server unix:/run/php-fpm/php-grommunio-dav-fpm.sock; }}
server {{
  listen 443 ssl;
  listen 8447 ssl;
  server_name {names};
  ssl_certificate {tls}/server.crt;
  ssl_certificate_key {tls}/server.key;
  ssl_protocols TLSv1.2 TLSv1.3;
  client_max_body_size 100m;
  root /var/www/html;
  # MAPI/HTTP, EWS, OAB, Autodiscover: gromox-http on loopback
  location ~* ^/(mapi|EWS|OAB|autodiscover|Autodiscover|rpc|rpcwithcert)(/|$) {{
    proxy_pass http://127.0.0.1:10080;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header Connection "";
    proxy_set_header X-Forwarded-Proto https;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_read_timeout 300s;
  }}
  location /Microsoft-Server-ActiveSync {{
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME /usr/share/grommunio-sync/index.php;
    fastcgi_param REMOTE_USER "";
    fastcgi_param HTTP_PROXY "";
    fastcgi_param PHP_VALUE "memory_limit=500M\npost_max_size=102M\nupload_max_filesize=100M\nmax_execution_time=3660";
    fastcgi_read_timeout 3660;
    client_max_body_size 102m;
    fastcgi_pass ou_fpm_sync;
  }}
  rewrite ^/.well-known/caldav /dav/ redirect;
  rewrite ^/.well-known/carddav /dav/ redirect;
  location /dav {{
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME /usr/share/grommunio-dav/server.php;
    fastcgi_param REMOTE_USER "";
    fastcgi_param HTTP_PROXY "";
    fastcgi_read_timeout 360;
    fastcgi_pass ou_fpm_dav;
  }}
  # grommunio-web links /brand/brand.css last on every page (its documented branding hook; upstream nginx serves it from /run/grommunio-brand,
  # empty when absent): the Office Unbound skin written by cfg.gromox `brand`
  location = /brand/brand.css {{
    root {brand_root};
    default_type text/css;
    add_header Cache-Control "no-cache" always;
    add_header X-Content-Type-Options nosniff always;
    try_files $uri @ou_brand_none;
  }}
  location ^~ /brand/ {{
    root {brand_root};
    add_header Cache-Control "no-cache" always;
    add_header X-Content-Type-Options nosniff always;
    add_header Content-Security-Policy "default-src 'none'; style-src 'unsafe-inline'; sandbox" always;
    try_files $uri =404;
  }}
  location @ou_brand_none {{ default_type text/css; return 200 ""; }}
  location = / {{ return 301 "/web/"; }}
  location = /web {{ return 301 "/web/$is_args$args"; }}
  location /web/ {{
    alias /usr/share/grommunio-web/;
    index index.php;
    location ~ ^/web/(.+\\.php)$ {{
      include fastcgi_params;
      fastcgi_param REMOTE_USER "";
      fastcgi_param HTTP_PROXY "";
      fastcgi_param SCRIPT_FILENAME /usr/share/grommunio-web/$1;
      fastcgi_param PHP_VALUE "post_max_size=31M\nupload_max_filesize=30M\nmax_execution_time=3660\nsession.cookie_secure=on\nsession.save_path=/var/lib/grommunio-web/session";
      fastcgi_read_timeout 360s;
      fastcgi_pass ou_fpm_web;
    }}
  }}
}}
"""

GW_POOL = """; generated by ou-agent (cfg.gromox)
[{name}]
user = {user}
group = {user}
listen = /run/php-fpm/php-{name}-fpm.sock
listen.owner = {user}
listen.group = www-data
listen.mode = 0660
pm = dynamic
pm.max_children = 10
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
pm.max_requests = 500
request_terminate_timeout = {timeout}s
security.limit_extensions = .php
catch_workers_output = yes
"""

SUBMISSION = ("-o syslog_name=postfix/{svc} -o smtpd_tls_security_level=encrypt -o smtpd_tls_auth_only=yes -o smtpd_sasl_auth_enable=yes "
              "-o smtpd_client_restrictions=permit_sasl_authenticated,reject -o smtpd_relay_restrictions=permit_sasl_authenticated,reject "
              "-o smtpd_sender_login_maps=mysql:/etc/postfix/mysql-sender-login.cf "
              "-o smtpd_sender_restrictions=reject_sender_login_mismatch,reject_unlisted_sender "
              "-o smtpd_recipient_restrictions=permit_sasl_authenticated,reject -o milter_macro_daemon_name=ORIGINATING")

BRAND_ROOT = "/etc/ou-brand"                       # nginx root: /brand/brand.css -> /etc/ou-brand/brand/brand.css
# edits of the packages' own config.php (conffiles): no device provisioning, no developer mode, and the name the calendar/contacts server
# gives in its password prompt (Basic auth realm, shown by calendar apps and browsers; upstream "grommunio dav") is the product's
GW_PHP_EDITS = (("/etc/grommunio-sync/config.php", r"define\('PROVISIONING',\s*true\);", "define('PROVISIONING', false);"),
                ("/etc/grommunio-dav/config.php", r"define\('DEVELOPER_MODE',\s*true\);", "define('DEVELOPER_MODE', false);"),
                ("/etc/grommunio-dav/config.php", r"define\('SABRE_AUTH_REALM',\s*'[^'\\\n]*'\);", "define('SABRE_AUTH_REALM', 'Office Unbound');"))
GW_DASHBOARD = "/etc/grommunio-web/ou-dashboard.json"   # read by the oudashboard plugin of ou-grommunio-web (>= 5.2-ou3)

ZCORE_SOCKPERM = """#!/bin/sh
# generated by ou-agent (cfg.gromox). Security review 4 M1: zcore.sock offers mailbox logon without a password to anyone who can connect;
# re-applied after every gromox-zcore start (drop-in ou-sockperm.conf): only the php-fpm pool users (group gromox-zcore) reach it.
for i in $(seq 1 240); do [ -S /run/gromox/zcore.sock ] && break; sleep 0.25; done
chgrp gromox-zcore /run/gromox && chmod 0710 /run/gromox
chgrp gromox-zcore /run/gromox/zcore.sock && chmod 0660 /run/gromox/zcore.sock
"""


def _installed(x, pkg):
    return x.run([BIN["dpkg-query"], "-W", "-f=${Status}", pkg], check=False).stdout.strip() == "install ok installed"


def _sql(x, sql, db=None, what="mariadb"):
    argv = [BIN["mariadb"], "--batch", "--skip-column-names"] + ([db] if db else [])
    return x.run(argv, input=sql, timeout=120, what=what).stdout


def _gid(name):
    import grp
    return grp.getgrnam(name).gr_gid


def _uid(name):
    return pwd.getpwnam(name).pw_uid


def _cfgfile(path, body, mode=0o640, uid=0, gid=None):
    old = read(path)
    if old != body:
        atomic_write(path, body, mode, uid, _gid("gromoxcf") if gid is None else gid)
    return old != body


def _ldap_people(x, p, base, mail):
    """entryUUID, display name and groups of the directory entry with this mail address (read-only bind, LDAPS verified against the CA)."""
    pwfile = os.path.join(RESULT_DIR, "ldap-bind-" + secrets.token_hex(6))
    os.makedirs(RESULT_DIR, mode=0o755, exist_ok=True)
    fd = os.open(pwfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(p["bind_password"])
    try:
        env = dict(ROOT_ENV, LDAPTLS_CACERT=os.path.join(TLS_DIR, "ca.crt"), LDAPTLS_REQCERT="demand")
        r = x.run([BIN["ldapsearch"], "-LLL", "-o", "ldif-wrap=no", "-x", "-H", f"ldaps://{p['ldap_host']}", "-D", f"cn=svc-bind,ou=system,{base}",
                   "-y", pwfile, "-b", f"ou=people,{base}", f"(&(objectClass=inetOrgPerson)(mail={mail}))", "entryUUID", "displayName", "cn", "memberOf"],
                  env=env, timeout=60, what="ldapsearch (directory)")
    finally:
        os.unlink(pwfile)
    attrs = {}
    for ln in r.stdout.splitlines():
        k, sep, v = ln.partition(":")
        if not sep or k == "dn":
            continue
        if v.startswith(":"):
            v = base64.b64decode(v[1:].strip()).decode("utf-8", "replace")
        attrs.setdefault(k, []).append(v.strip())
    if not attrs:
        return None
    uuid = (attrs.get("entryUUID") or [""])[0].lower()
    if not UUID_RE.fullmatch(uuid):
        raise Failed("the directory entry has no valid entryUUID")
    name = (attrs.get("displayName") or attrs.get("cn") or [mail])[0]
    name = "".join(ch for ch in name if ch.isprintable())[:120] or mail
    return {"uuid": uuid, "name": name, "groups": {g.lower() for g in attrs.get("memberOf", [])}}


def _q(v):
    return "'" + str(v).replace("\\", "\\\\").replace("'", "''") + "'"


def _mailbox(x, p, base, did, mail):
    who = _ldap_people(x, p, base, mail)
    if who is None:
        return "skipped", "no directory entry with this address"
    if f"cn={p['group'].lower()},ou=groups,{base.lower()}" not in who["groups"]:
        return "skipped", f"not in group {p['group']}"
    row = _sql(x, f"SELECT id, HEX(externid) FROM users WHERE username = {_q(mail)};", "email").strip()
    md = os.path.join(GX_USERS, mail)
    state = "existing"
    if not row:
        _sql(x, "INSERT INTO users (username, password, domain_id, group_id, maildir, privilege_bits, address_status, lang, timezone, externid) "
                f"VALUES ({_q(mail)}, '!', {int(did)}, 0, {_q(md)}, 15, 0, 'en', 'UTC', {_q(who['uuid'])});\n"
                f"INSERT INTO user_properties (user_id, proptag, propval_str) SELECT id, {PR_DISPLAY_TYPE_EX}, '0' FROM users WHERE username = {_q(mail)};\n"
                f"INSERT INTO user_properties (user_id, proptag, propval_str) SELECT id, {PR_DISPLAY_NAME}, {_q(who['name'])} FROM users "
                f"WHERE username = {_q(mail)};\n", "email", what="mailbox row")
        state = "created"
    elif bytes.fromhex(row.split("\t")[1] or "").decode("ascii", "replace") != who["uuid"]:
        raise Failed(f"mailbox {mail} is linked to another directory entry; nothing changed")
    for sub in ("", "exmdb", "tmp", "tmp/imap.rfc822", "config", "cid"):
        os.makedirs(os.path.join(md, sub), mode=0o770, exist_ok=True)
    if not os.path.exists(os.path.join(md, "exmdb", "exchange.sqlite3")):
        x.run([BIN["mkprivate"], mail], timeout=300, what="gromox-mkprivate")
    if not os.path.exists(os.path.join(md, "exmdb", "midb.sqlite3")):
        x.run([BIN["mkmidb"], mail], timeout=300, what="gromox-mkmidb")
    x.run([BIN["chown"], "-R", "gromox:gromox", md], what="chown mailbox")
    return state, None


SELF_BEGIN, SELF_END = "# BEGIN office-unbound node name (managed by ou-agent cfg.gromox)", "# END office-unbound node name"


def _self_resolvable():
    """gromox resolves the node's own name at start (canonical_hostname; zcore exits with "getaddrinfo <name>: Name or service not known"
    otherwise). When the name does not resolve, map it to 127.0.1.1 (the Debian convention) in a managed block of /etc/hosts."""
    import socket
    name = socket.gethostname()
    if not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", name):
        raise Failed("the node's host name is not a valid name")
    try:
        socket.getaddrinfo(name, None)
        return False
    except socket.gaierror:
        pass
    cur = read(HOSTS) or ""
    keep, skip = [], False
    for ln in cur.splitlines():
        if ln == SELF_BEGIN:
            skip = True
            continue
        if ln == SELF_END:
            skip = False
            continue
        if not skip:
            keep.append(ln)
    atomic_write(HOSTS, "\n".join(keep).rstrip("\n") + f"\n{SELF_BEGIN}\n127.0.1.1 {name}\n{SELF_END}\n", 0o644)
    return True


def _brand(b):
    """Static files for nginx (world-readable: nothing secret) and the plugin's settings file (read by the web pool)."""
    d = os.path.join(BRAND_ROOT, "brand")
    if not b:
        for f in (os.path.join(d, "brand.css"), os.path.join(d, "ou-mark.svg"), os.path.join(d, "ou-fonts.css"), GW_DASHBOARD):
            if os.path.exists(f):
                os.unlink(f)
        return
    os.makedirs(d, mode=0o755, exist_ok=True)
    for q in (BRAND_ROOT, d):
        os.chmod(q, 0o755)
    atomic_write(os.path.join(d, "brand.css"), b["css"], 0o644)
    atomic_write(os.path.join(d, "ou-mark.svg"), b["mark_svg"], 0o644)
    fonts = os.path.join(d, "ou-fonts.css")   # IBM Plex as data: URIs (brand.css @imports it); absent = the system fonts
    if b.get("fonts_css"):
        atomic_write(fonts, b["fonts_css"], 0o644)
    elif os.path.exists(fonts):
        os.unlink(fonts)
    if b.get("portal_url"):
        os.makedirs(os.path.dirname(GW_DASHBOARD), mode=0o755, exist_ok=True)
        atomic_write(GW_DASHBOARD, json.dumps({"url": b["portal_url"], "label": "Dashboard"}) + "\n", 0o644)
    elif os.path.exists(GW_DASHBOARD):
        os.unlink(GW_DASHBOARD)


def _gx_files(p, host, pw, base):
    """The gromox configuration files cfg.gromox owns: name (under GX_ETC, 0640 root:gromoxcf) -> content."""
    return {
        "mysql_adaptor.cfg": f"# generated by ou-agent (cfg.gromox)\nmysql_username=gromox\nmysql_password={pw}\nmysql_dbname=email\nmysql_host=localhost\n"
                             f"schema_upgrade=host:{host}\n",
        "gromox.cfg": f"# generated by ou-agent (cfg.gromox)\nhost_id={host}\noxdisco_exonym={host}\nhttp_listen=127.0.0.1:10080\nhttp_listen_tls=\n"
                      "lda_listen=127.0.0.1:24\nlda_listen_tls=\nimap_listen=127.0.0.1:143\nimap_listen_tls=0.0.0.0:993\npop3_listen=\npop3_listen_tls=\n"
                      f"outgoing_smtp_url=smtp://127.0.0.1:25\nexmdb_listen={GX_EXMDB_LISTEN}\n",
        "exmdb_provider.cfg": f"# generated by ou-agent (cfg.gromox)\nexmdb_hosts_allow={GX_EXMDB_ALLOW}\n",
        "http.cfg": "# generated by ou-agent (cfg.gromox)\nhttp_support_tls=false\nhttp_auth_basic=true\n",
        "smtp.cfg": "# generated by ou-agent (cfg.gromox)\ncommand_protocol=both\n",
        "imap.cfg": f"# generated by ou-agent (cfg.gromox)\nimap_support_tls=true\nimap_certificate_path={GX_TLS}/server.crt\n"
                    f"imap_private_key_path={GX_TLS}/server.key\n",
        "ldap_adaptor.cfg": f"# generated by ou-agent (cfg.gromox): authentication against the deployment directory, read-only bind\n"
                            f"ldap_host=ldaps://{p['ldap_host']}\nldap_start_tls=false\nldap_bind_user=cn=svc-bind,ou=system,{base}\n"
                            f"ldap_bind_pass={p['bind_password']}\nldap_search_base=ou=people,{base}\nldap_mail_attr=mail\nldap_object_id=entryUUID\n"
                            "ldap_user_filter=(&(objectClass=inetOrgPerson)(mail=*))\nldap_user_displayname=displayName\n",
    }


def gromox(p, x):
    missing = [k for k in GW_NEEDS if not _installed(x, k)]
    if missing:
        raise Failed("not installed (pkg.install_pinned must run first): " + ", ".join(missing))
    dom, host, base = p["domain"], p["hostname"], c.base_dn(p["domain"])
    gxcf = _gid("gromoxcf")
    _self_resolvable()
    # --- TLS: the deployment certificate (cfg.tls) as a chain, the key readable by root and group gromoxcf only
    crt, key, ca_ = (read(os.path.join(TLS_DIR, f)) for f in (p["tls_name"] + ".crt", p["tls_name"] + ".key", "ca.crt"))
    if crt is None or key is None or ca_ is None:
        raise Failed("the deployment TLS material is missing: cfg.tls must run first")
    os.makedirs(GX_ETC, exist_ok=True)
    os.chown(GX_ETC, 0, gxcf)
    os.chmod(GX_ETC, 0o750)
    os.makedirs(GX_TLS, exist_ok=True)
    os.chown(GX_TLS, 0, gxcf)
    os.chmod(GX_TLS, 0o750)
    atomic_write(os.path.join(GX_TLS, "server.crt"), crt.rstrip("\n") + "\n" + ca_, 0o644, 0, gxcf)
    atomic_write(os.path.join(GX_TLS, "server.key"), key, 0o640, 0, gxcf)
    # --- MariaDB: database `email`, account gromox (socket for gromox, TCP 127.0.0.1 for the chrooted Postfix)
    x.run([BIN["systemctl"], "enable", "--now", "mariadb"], what="systemctl enable mariadb")
    pw = p["db_password"]
    _sql(x, "CREATE DATABASE IF NOT EXISTS email CHARACTER SET utf8mb4;\n"
            f"CREATE USER IF NOT EXISTS 'gromox'@'localhost' IDENTIFIED BY '{pw}';\nALTER USER 'gromox'@'localhost' IDENTIFIED BY '{pw}';\n"
            f"CREATE USER IF NOT EXISTS 'gromox'@'127.0.0.1' IDENTIFIED BY '{pw}';\nALTER USER 'gromox'@'127.0.0.1' IDENTIFIED BY '{pw}';\n"
            "GRANT ALL ON email.* TO 'gromox'@'localhost';\nGRANT ALL ON email.* TO 'gromox'@'127.0.0.1';\nFLUSH PRIVILEGES;\n", what="database setup")
    # --- gromox configuration
    changed = False
    for name, body in _gx_files(p, host, pw, base).items():
        changed |= _cfgfile(os.path.join(GX_ETC, name), body)
    if read(LDAP_CONF) is None:   # libldap (gromox, ldapsearch) verifies the directory against the system trust store, where cfg.tls put the CA
        atomic_write(LDAP_CONF, f"# generated by ou-agent (cfg.gromox)\nBASE {base}\nURI ldaps://{p['ldap_host']}\n"
                                "TLS_CACERT /etc/ssl/certs/ca-certificates.crt\nTLS_REQCERT demand\n", 0o644)
    if _sql(x, "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'email' AND table_name = 'users';").strip() == "0":
        x.run([BIN["dbop"], "-C"], timeout=300, what="gromox-dbop -C")
    # --- organisation, domain and its public store
    _sql(x, "INSERT IGNORE INTO orgs (id, name, description) VALUES (1, 'ou', 'Office Unbound');\n"
            "INSERT IGNORE INTO domains (org_id, domainname, homedir, max_user, title, end_day, domain_status) "
            f"VALUES (1, {_q(dom)}, {_q(os.path.join(GX_DOMAINS, dom))}, 0, {_q(dom)}, '2099-01-01', 0);\n", "email", what="domain")
    did = _sql(x, f"SELECT id FROM domains WHERE domainname = {_q(dom)};", "email").strip()
    if not did.isdigit():
        raise Failed("the mail domain could not be created")
    # gromox's state tree (lab-configure.sh): owned by gromox, incl. the delivery queue (delivery/delivery-queue exit without it) and timer.txt
    gu, gg = _uid("gromox"), _gid("gromox")
    for d in ("/var/lib/gromox", "/var/lib/gromox/queue", "/var/lib/gromox/queue/mess", "/var/lib/gromox/queue/save", "/var/lib/gromox/queue/cache",
              "/var/log/gromox", GX_USERS, GX_DOMAINS, os.path.join(GX_DOMAINS, dom), os.path.join(GX_DOMAINS, dom, "exmdb")):
        os.makedirs(d, mode=0o770, exist_ok=True)
        os.chown(d, gu, gg)
        os.chmod(d, 0o770)
    if not os.path.exists(os.path.join(GX_DOMAINS, dom, "exmdb", "exchange.sqlite3")):
        x.run([BIN["mkpublic"], dom], timeout=300, what="gromox-mkpublic")
    x.run([BIN["chown"], "-R", "gromox:gromox", GX_DOMAINS], what="chown domain")
    boxes = {"created": [], "existing": [], "skipped": []}
    for m in p["mailboxes"]:
        st, why = _mailbox(x, p, base, did, m)
        if st == "skipped":
            boxes["skipped"].append({"mailbox": m, "why": why})
        else:
            boxes[st].append(m)
    # --- Postfix: the domain delivers to gromox (LMTP), submission 587/465 with SASL (saslauthd -> PAM -> pam_gromox), no outbound relay yet
    if read("/etc/postfix/main.cf") is None:
        atomic_write("/etc/postfix/main.cf", read("/usr/share/postfix/main.cf.debian") or "", 0o644)
    pf = _gid("postfix")
    mapdb = f"user=gromox\npassword={pw}\ndbname=email\nhosts=127.0.0.1\n"
    atomic_write("/etc/postfix/mysql-vmbox.cf", mapdb + "query=SELECT username FROM users WHERE username='%s' AND address_status IN (0,4)\n", 0o640, 0, pf)
    atomic_write("/etc/postfix/mysql-sender-login.cf", mapdb + "query=SELECT username FROM users WHERE username='%s' AND address_status IN (0,4) "
                 "UNION SELECT mainname FROM aliases WHERE aliasname='%s'\n", 0o640, 0, pf)
    atomic_write("/etc/pam.d/smtp", "#%PAM-1.0\n# generated by ou-agent (cfg.gromox)\nauth    required pam_gromox.so\naccount required pam_permit.so\n", 0o644)
    # saslauthd keeps its default socket /run/saslauthd/mux (the noble unit waits for its PID file there); the submission services below are
    # not chrooted (5th master.cf column `n`), so Postfix reaches it directly as a member of group sasl
    atomic_write("/etc/default/saslauthd", '# generated by ou-agent (cfg.gromox)\nSTART=yes\nDESC="SASL Authentication Daemon"\nNAME="saslauthd"\n'
                 'MECHANISMS="pam"\nMECH_OPTIONS=""\nTHREADS=5\nOPTIONS="-r -c -m /run/saslauthd"\n', 0o644)
    atomic_write("/etc/postfix/sasl/smtpd.conf", "pwcheck_method: saslauthd\nsaslauthd_path: /run/saslauthd/mux\nmech_list: PLAIN LOGIN\n", 0o644)
    x.run([BIN["usermod"], "-aG", "sasl", "postfix"], what="usermod postfix")
    x.run([BIN["postconf"], "-e", f"myhostname={host}", "mydestination=localhost", f"virtual_mailbox_domains={dom}",
           "virtual_mailbox_maps=mysql:/etc/postfix/mysql-vmbox.cf", "virtual_transport=lmtp:[127.0.0.1]:24", "inet_interfaces=all",
           "inet_protocols=ipv4", "mynetworks=127.0.0.0/8", "relayhost=", "smtpd_banner=$myhostname ESMTP",
           "default_transport=error:outbound internet mail is not enabled for this deployment yet",
           "smtpd_relay_restrictions=permit_mynetworks,reject_unauth_destination",
           f"smtpd_tls_cert_file={GX_TLS}/server.crt", f"smtpd_tls_key_file={GX_TLS}/server.key", "smtpd_tls_security_level=may",
           "smtpd_tls_protocols=!SSLv2,!SSLv3,!TLSv1,!TLSv1.1", "smtpd_tls_mandatory_protocols=!SSLv2,!SSLv3,!TLSv1,!TLSv1.1",
           "smtpd_sasl_type=cyrus", "smtpd_sasl_path=smtpd", "cyrus_sasl_config_path=/etc/postfix/sasl", "smtpd_sasl_security_options=noanonymous",
           "smtpd_sasl_local_domain=", "smtpd_sasl_auth_enable=no"], what="postconf")
    for svc, extra in (("submission", ""), ("smtps", " -o smtpd_tls_wrappermode=yes")):
        line = f"{svc} inet n - n - - smtpd " + SUBMISSION.format(svc=svc) + extra
        x.run([BIN["postconf"], "-M", f"{svc}/inet={line}"], what="postconf -M")
    x.run([BIN["postfix"], "check"], what="postfix check")
    # --- zcore socket lockdown (security review 4 M1)
    if x.run([BIN["getent"], "group", "gromox-zcore"], check=False).returncode != 0:
        x.run([BIN["groupadd"], "-r", "gromox-zcore"], what="groupadd gromox-zcore")
    for u in ("groweb", "grosync", "grodav"):
        x.run([BIN["usermod"], "-aG", "gromox-zcore", u], what="usermod")
    atomic_write("/usr/local/sbin/ou-zcore-sockperm", ZCORE_SOCKPERM, 0o755)
    atomic_write("/etc/systemd/system/gromox-zcore.service.d/ou-sockperm.conf",
                 "[Service]\nExecStartPre=+/bin/rm -f /run/gromox/zcore.sock\nExecStartPost=+/usr/local/sbin/ou-zcore-sockperm\n", 0o644)
    # --- PHP-FPM pools (web, ActiveSync, CalDAV/CardDAV) with the MAPI extension; their sockets live in /run/php-fpm (tmpfs: recreated at boot)
    import glob
    atomic_write("/etc/tmpfiles.d/ou-php-fpm.conf", "# generated by ou-agent (cfg.gromox)\nd /run/php-fpm 0755 root root -\n", 0o644)
    os.makedirs("/run/php-fpm", mode=0o755, exist_ok=True)
    fpm = sorted(glob.glob("/etc/php/*/fpm/pool.d"))
    if len(fpm) != 1:
        raise Failed("expected exactly one PHP-FPM installation")
    phpv = fpm[0].split("/")[3]
    mapi = read(f"/etc/php/{phpv}/cli/conf.d/mapi.ini")
    if mapi is None:
        raise Failed("the php-mapi extension is not installed")
    atomic_write(f"/etc/php/{phpv}/mods-available/mapi.ini", mapi, 0o644)
    x.run([BIN["phpenmod"], "-v", phpv, "-s", "fpm", "mapi"], what="phpenmod mapi")
    for name, user, timeout in (("grommunio-web", "groweb", 360), ("grommunio-sync", "grosync", 3660), ("grommunio-dav", "grodav", 360)):
        atomic_write(os.path.join(fpm[0], name + ".conf"), GW_POOL.format(name=name, user=user, timeout=timeout), 0o644)
    for path, pat, rep in GW_PHP_EDITS:
        t = read(path)
        if t is not None and re.search(pat, t) and re.sub(pat, rep, t) != t:
            atomic_write(path, re.sub(pat, rep, t), 0o644)
    # --- webmail sign-in through Keycloak (webmail-sso-results.md): keycloak.json for grommunio-web, the realm's public key for gromox (zcore
    # verifies the token's RS256 signature with it); without `sso` webmail keeps its own login form (directory password)
    kc, pub = os.path.join(GX_ETC, "keycloak.json"), os.path.join(GX_ETC, "bearer_pubkey")
    if p.get("sso"):
        o = p["sso"]
        changed |= _cfgfile(kc, json.dumps({"realm": o["realm"], "auth-server-url": o["auth_url"], "ssl-required": "external",
                                            "resource": o["client_id"], "redirect-url": o["redirect_url"],
                                            "credentials": {"secret": o["client_secret"]}, "confidential-port": 0}, indent=1) + "\n", 0o640, 0, gxcf)
        changed |= _cfgfile(pub, o["bearer_pubkey"], 0o640, 0, gxcf)
        # the web pool (user groweb) reads keycloak.json; without the group the login page silently keeps its own password form
        x.run([BIN["usermod"], "-aG", "gromoxcf", "groweb"], what="usermod groweb")
    else:
        for f in (kc, pub):
            if os.path.exists(f):
                os.unlink(f)
                changed = True
    # --- the Office Unbound skin (/brand/brand.css + mark) and the webmail's Dashboard button target; without `brand` both are removed
    _brand(p.get("brand"))
    # --- nginx: mail.<domain> + autodiscover on 443 (clients) and 8447 (the edge), TLS with the deployment certificate
    path, link = os.path.join(NGINX_AVAIL, GW_SITE), os.path.join(NGINX_ENABLED, GW_SITE)
    old = read(path)
    atomic_write(path, GW_NGINX.format(names=f"{host} autodiscover.{dom}", tls=GX_TLS, brand_root=BRAND_ROOT), 0o644)
    if not os.path.islink(link):
        if os.path.lexists(link):
            os.unlink(link)
        os.symlink(path, link)
    if os.path.lexists(os.path.join(NGINX_ENABLED, "default")):
        os.unlink(os.path.join(NGINX_ENABLED, "default"))
    x.run([BIN["usermod"], "-aG", "gromoxcf", "www-data"], what="usermod www-data")   # nginx workers read nothing of gromox; the key is read by the master (root)
    t = x.run([BIN["nginx"], "-t"], check=False)
    if t.returncode != 0:
        if old is None:
            os.unlink(link)
            os.unlink(path)
        else:
            atomic_write(path, old, 0o644)
        raise Failed("nginx refused the configuration: " + x.scrub(t.stderr))
    # --- start everything (each reads its configuration at start)
    x.run([BIN["systemctl"], "daemon-reload"], what="systemctl daemon-reload")
    units = [*GX_SERVICES, "saslauthd", "postfix", "redis-server", f"php{phpv}-fpm", "nginx"]
    x.run([BIN["systemctl"], "enable", *units], what="systemctl enable")
    x.run([BIN["systemctl"], "restart", *units], timeout=300, what="systemctl restart")
    bad = [u for u in units if x.run([BIN["systemctl"], "is-active", u], check=False).stdout.strip() != "active"]
    if bad:
        raise Failed("not running after start: " + ", ".join(bad))
    return {"domain": dom, "hostname": host, "mailboxes": boxes, "services": len(units), "config_changed": changed}


# ---------------------------------------------------------------- cfg.nginx_default
NGINX_DEFAULT = "ou-00-default"
NGINX_DEFAULT_SITE = """# generated by ou-agent (cfg.nginx_default): requests for any other name or a bare IP address; do not edit
server {{
  listen 80 default_server;
  listen [::]:80 default_server;
  server_name _;
  {action}
}}
server {{
  listen 443 ssl default_server;
  listen [::]:443 ssl default_server;
  server_name _;
  ssl_certificate {tls}/{cert}.crt;
  ssl_certificate_key {tls}/{cert}.key;
  ssl_protocols TLSv1.2 TLSv1.3;
  {action}
}}
"""


def nginx_default(p, x):
    for f in (p["tls_name"] + ".crt", p["tls_name"] + ".key"):
        if not os.path.exists(os.path.join(TLS_DIR, f)):
            raise Failed(f"missing {f}: cfg.tls must run first")
    action = f"return 302 {p['redirect']};" if p["redirect"] else "return 444;"
    path, link = os.path.join(NGINX_AVAIL, NGINX_DEFAULT), os.path.join(NGINX_ENABLED, NGINX_DEFAULT)
    old = read(path)
    atomic_write(path, NGINX_DEFAULT_SITE.format(action=action, tls=TLS_DIR, cert=p["tls_name"]), 0o644)
    if not os.path.islink(link):
        if os.path.lexists(link):
            os.unlink(link)
        os.symlink(path, link)
    if os.path.lexists(os.path.join(NGINX_ENABLED, "default")):
        os.unlink(os.path.join(NGINX_ENABLED, "default"))
    t = x.run([BIN["nginx"], "-t"], check=False)
    if t.returncode != 0:
        if old is None:
            os.unlink(link)
            os.unlink(path)
        else:
            atomic_write(path, old, 0o644)
        raise Failed("nginx refused the configuration: " + x.scrub(t.stderr))
    x.run([BIN["systemctl"], "enable", "--now", "nginx"], what="systemctl enable nginx")
    x.run([BIN["systemctl"], "reload", "nginx"], what="systemctl reload nginx")
    return {"site": NGINX_DEFAULT, "redirect": p["redirect"]}


# ---------------------------------------------------------------- cfg.acme
# Publicly trusted certificates for the gateway (ADR-0018 section 11): certbot (Ubuntu package) with HTTP-01 from a webroot every nginx site
# serves on port 80; the certificate lineage is linked into TLS_DIR as <cert_name>.crt/.key so sites select it by tls_name. Renewal is certbot's
# own systemd timer (no ICS involved), with a deploy hook that reloads nginx. No contact e-mail is registered.
ACME_ROOT = "/var/lib/ou-acme/webroot"
ACME_DIRS = {"staging": "https://acme-staging-v02.api.letsencrypt.org/directory", "production": "https://acme-v02.api.letsencrypt.org/directory"}
LE_LIVE = "/etc/letsencrypt/live"
ACME_HOOK = "/etc/letsencrypt/renewal-hooks/deploy/ou-reload-nginx"


LE_ETC = "/etc/letsencrypt"
LE_ACCOUNTS = {"production": "accounts/acme-v02.api.letsencrypt.org/directory", "staging": "accounts/acme-staging-v02.api.letsencrypt.org/directory"}
LINEAGE_FILES = ("cert", "chain", "fullchain", "privkey")
RENEWAL_TEMPLATE = """# generated by ou-agent (cfg.acme reuse): a lineage restored from an earlier gateway; certbot renews it as its own
version = {version}
archive_dir = {etc}/archive/{name}
cert = {etc}/live/{name}/cert.pem
privkey = {etc}/live/{name}/privkey.pem
chain = {etc}/live/{name}/chain.pem
fullchain = {etc}/live/{name}/fullchain.pem

[renewalparams]
account = {account}
authenticator = webroot
webroot_path = {webroot},
server = {server}
key_type = ecdsa
elliptic_curve = secp256r1
[[webroot_map]]
{webroot_map}
"""


def _certbot_version(x):
    out = x.run([BIN["certbot"], "--version"], what="certbot --version").stdout or ""
    m = re.search(r"(\d+\.\d+\.\d+)", out)
    if not m:
        raise Failed("cannot read the certbot version")
    return m.group(1)


def acme_restore(p, x, etc=LE_ETC):
    """Install a captured lineage (cfgspec.check_acme_bundle) unless this gateway already has one of that name. Returns True if installed."""
    name, b = p["cert_name"], p["restore"]
    if os.path.lexists(os.path.join(etc, "live", name)) or os.path.lexists(os.path.join(etc, "renewal", name + ".conf")):
        return False
    acct = os.path.join(etc, LE_ACCOUNTS["production"], b["account_id"])
    os.makedirs(acct, mode=0o700, exist_ok=True)
    for k in ("meta", "regr", "private_key"):
        atomic_write(os.path.join(acct, k + ".json"), b["account"][k], 0o400 if k == "private_key" else 0o644)
    arch, live = os.path.join(etc, "archive", name), os.path.join(etc, "live", name)
    os.makedirs(arch, mode=0o700, exist_ok=True)
    os.makedirs(live, mode=0o755, exist_ok=True)
    for k in LINEAGE_FILES:
        atomic_write(os.path.join(arch, k + "1.pem"), b[k], 0o600 if k == "privkey" else 0o644)
        os.symlink(f"../../archive/{name}/{k}1.pem", os.path.join(live, k + ".pem"))
    wmap = "\n".join(f"{n} = {ACME_ROOT}" for n in p["names"])
    atomic_write(os.path.join(etc, "renewal", name + ".conf"),
                 RENEWAL_TEMPLATE.format(version=_certbot_version(x), etc=etc, name=name, account=b["account_id"], webroot=ACME_ROOT,
                                         server=ACME_DIRS["production"], webroot_map=wmap), 0o644)
    return True


def acme_export(name, etc=LE_ETC):
    """The lineage this gateway serves now (live files) and the production account it renews with (renewal configuration)."""
    conf = open(os.path.join(etc, "renewal", name + ".conf")).read()
    m = re.search(r"^account = ([0-9a-f]{32})$", conf, re.M)
    if not m or ACME_DIRS["production"] not in conf:
        raise Failed("the certificate's renewal configuration names no production account")
    acct = os.path.join(etc, LE_ACCOUNTS["production"], m.group(1))
    out = {"account_id": m.group(1), "account": {k: open(os.path.join(acct, k + ".json")).read() for k in ("meta", "regr", "private_key")}}
    for k in LINEAGE_FILES:
        out[k] = open(os.path.join(etc, "live", name, k + ".pem")).read()
    return out


def acme(p, x):
    if not _installed(x, "certbot"):
        raise Failed("not installed (pkg.install_pinned must run first): certbot")
    os.makedirs(ACME_ROOT, mode=0o755, exist_ok=True)
    atomic_write(ACME_HOOK, "#!/bin/sh\n# generated by ou-agent (cfg.acme): a renewed certificate is served at once\nexec /usr/bin/systemctl reload nginx\n", 0o755)
    name = p["cert_name"]
    restored = acme_restore(p, x) if p.get("restore") else False
    argv = [BIN["certbot"], "certonly", "--webroot", "-w", ACME_ROOT, "--cert-name", name, "--non-interactive", "--agree-tos",
            "--register-unsafely-without-email", "--server", ACME_DIRS[p["directory"]], "--keep-until-expiring", "--expand",
            "--key-type", "ecdsa", "--elliptic-curve", "secp256r1", "--deploy-hook", ACME_HOOK]
    for n in p["names"]:
        argv += ["-d", n]
    r = x.run(argv, timeout=600, check=False)
    if r.returncode != 0:
        raise Failed("certificate request failed: " + x.scrub((r.stderr or r.stdout or "")[-1500:]))
    live = os.path.join(LE_LIVE, name)
    os.makedirs(TLS_DIR, mode=0o755, exist_ok=True)
    for src, dst in (("fullchain.pem", name + ".crt"), ("privkey.pem", name + ".key")):
        link, target = os.path.join(TLS_DIR, dst), os.path.join(live, src)
        if os.path.islink(link) and os.readlink(link) == target:
            continue
        if os.path.lexists(link):
            os.unlink(link)
        os.symlink(target, link)
    out = x.run([BIN["openssl"], "x509", "-in", os.path.join(live, "cert.pem"), "-noout", "-enddate", "-issuer"], what="openssl x509").stdout
    x.run([BIN["systemctl"], "enable", "--now", "certbot.timer"], what="systemctl enable certbot.timer")
    x.run([BIN["systemctl"], "reload", "nginx"], what="systemctl reload nginx")
    res = {"cert_name": name, "names": p["names"], "directory": p["directory"], "certificate": out.strip(), "restored": restored}
    if p.get("export"):
        res["bundle"] = acme_export(name)
    return res


# ---------------------------------------------------------------- cfg.portal
PORTAL_ETC = "/etc/ou-portal"
PORTAL_PORT = 8090


def portal(p, x):
    if not _installed(x, "ou-portal"):
        raise Failed("not installed (pkg.install_pinned must run first): ou-portal")
    gid = _gid("ou-portal")
    os.makedirs(PORTAL_ETC, exist_ok=True)
    os.chown(PORTAL_ETC, 0, gid)
    os.chmod(PORTAL_ETC, 0o750)
    env = {"PORTAL_BASE_URL": p["base_url"], "PORTAL_OIDC_ISSUER": p["issuer"], "PORTAL_OIDC_CLIENT_ID": p["client_id"],
           "PORTAL_OIDC_CLIENT_SECRET_FILE": PORTAL_ETC + "/client-secret", "PORTAL_FILES_URL": p["files_url"] or p["base_url"],
           "PORTAL_MAIL_WEB_URL": p["mail_web_url"], "PORTAL_MAIL_HOST": p["mail_host"] or p["mail_domain"], "PORTAL_MAIL_DOMAIN": p["mail_domain"],
           "PORTAL_ORG_NAME": p["org_name"], "PORTAL_CA_BUNDLE": "/etc/ssl/certs/ca-certificates.crt"}
    key_file = os.path.join(PORTAL_ETC, "ics-tenant-key")
    admin = p.get("admin")
    if admin:   # the admin area: the ICS tenant-admin API of this deployment (the key goes to a file, never into the environment file)
        env.update({"PORTAL_ICS_URL": admin["ics_url"], "PORTAL_ICS_KEY_FILE": key_file,
                    "PORTAL_ICS_CA_BUNDLE": "/etc/ssl/certs/ca-certificates.crt", "PORTAL_ADMIN_ROLE": "org-admin"})
    text = "# generated by ou-agent (cfg.portal); no secret in this file\n" + "".join(f"{k}={v}\n" for k, v in env.items())
    changed = _cfgfile(os.path.join(PORTAL_ETC, "portal.env"), text, 0o640, 0, gid)
    changed |= _cfgfile(os.path.join(PORTAL_ETC, "client-secret"), p["client_secret"], 0o640, 0, gid)
    if admin:
        changed |= _cfgfile(key_file, admin["ics_key"], 0o640, 0, gid)
    elif os.path.lexists(key_file):   # admin area switched off: no credential is left behind
        os.unlink(key_file)
        changed = True
    x.run([BIN["systemctl"], "enable", "ou-portal"], what="systemctl enable ou-portal")
    x.run([BIN["systemctl"], "restart" if changed else "start", "ou-portal"], what="systemctl start ou-portal")
    if x.run([BIN["systemctl"], "is-active", "ou-portal"], check=False).stdout.strip() != "active":
        raise Failed("ou-portal is not running after start")
    return {"base_url": p["base_url"], "config_changed": changed, "admin_area": bool(admin)}


# ---------------------------------------------------------------- cfg.keycloak_realm (identity VM, agent >= 0.10.1)
# Keycloak imports import/realm-ou.json only when the realm does not exist yet (first start). A deployment upgraded in place gets the realm
# brought up to the ICS's current definition through Keycloak's admin API on 127.0.0.1 (never through the public name, whose site refuses
# the admin API): realm settings of a fixed list, clients (created or updated by clientId, incl. their secrets), the directory connection and
# its attribute mappers (by name), the declared user profile and the required actions. Additive: nothing is ever deleted.
KC_BASE, KC_MGMT, KC_ADMIN_USER = "http://127.0.0.1:8080", "http://127.0.0.1:9000", "kcadmin"
KC_REALM_KEYS = ("displayName", "loginTheme", "accountTheme", "emailTheme", "browserSecurityHeaders", "resetPasswordAllowed", "editUsernameAllowed",
                 "loginWithEmailAllowed", "registrationAllowed", "rememberMe", "verifyEmail", "sslRequired", "bruteForceProtected",
                 "permanentLockout", "failureFactor", "passwordPolicy", "otpPolicyType", "otpPolicyAlgorithm", "otpPolicyDigits", "otpPolicyPeriod")
KC_REQUIRED_ACTIONS = ("UPDATE_PASSWORD", "CONFIGURE_TOTP")
LDAP_PROVIDER = "org.keycloak.storage.UserStorageProvider"
LDAP_MAPPER = "org.keycloak.storage.ldap.mappers.LDAPStorageMapper"


def _kc(method, path, token=None, body=None, form=None, ok=(200, 201, 204)):
    import urllib.error
    import urllib.request
    data, headers = None, {"Accept": "application/json"}
    if form is not None:
        import urllib.parse
        data, headers["Content-Type"] = urllib.parse.urlencode(form).encode(), "application/x-www-form-urlencoded"
    elif body is not None:
        data, headers["Content-Type"] = json.dumps(body).encode(), "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(KC_BASE + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:   # noqa: S310 - fixed loopback URL
            raw = r.read()
            code = r.status
    except urllib.error.HTTPError as e:
        code, raw = e.code, b""
    except OSError as e:
        raise Failed(f"keycloak {method} {path.split('?')[0]}: {type(e).__name__}") from None
    if code not in ok:
        raise Failed(f"keycloak {method} {path.split('?')[0]} answered {code}")
    return json.loads(raw) if raw else None


def _kc_ready(deadline=240):
    import urllib.request
    t0 = time.monotonic()
    while time.monotonic() - t0 < deadline:
        try:
            with urllib.request.urlopen(KC_MGMT + "/health/ready", timeout=5) as r:   # noqa: S310 - fixed loopback URL
                if r.status == 200:
                    return
        except OSError:
            pass
        time.sleep(3)
    raise Failed("keycloak did not become ready on 127.0.0.1 within 240 s")


def keycloak_realm(p, x):
    want = json.loads(p["realm_json"])
    realm = want["realm"]
    _kc_ready()
    tok = _kc("POST", "/realms/master/protocol/openid-connect/token",
              form={"grant_type": "password", "client_id": "admin-cli", "username": KC_ADMIN_USER, "password": p["admin_password"]})["access_token"]
    base, done = f"/admin/realms/{realm}", {"realm": [], "clients_created": [], "clients_updated": [], "mappers_created": [], "mappers_updated": [],
                                             "ldap": False, "user_profile": False, "required_actions": []}
    cur = _kc("GET", base, tok)
    upd = {k: want[k] for k in KC_REALM_KEYS if k in want and cur.get(k) != want[k]}
    if upd:
        _kc("PUT", base, tok, {**upd, "realm": realm})
        done["realm"] = sorted(upd)
    for cl in want.get("clients", []):
        found = _kc("GET", f"{base}/clients?clientId={cl['clientId']}", tok) or []
        if not found:
            _kc("POST", f"{base}/clients", tok, cl)
            done["clients_created"].append(cl["clientId"])
        else:
            _kc("PUT", f"{base}/clients/{found[0]['id']}", tok, {**{k: v for k, v in cl.items() if k != "protocolMappers"}, "id": found[0]["id"]})
            done["clients_updated"].append(cl["clientId"])
    for wl in (want.get("components") or {}).get(LDAP_PROVIDER, []):
        have = [cmp for cmp in (_kc("GET", f"{base}/components?type={LDAP_PROVIDER}", tok) or []) if cmp.get("name") == wl["name"]]
        if not have:
            raise Failed(f"the realm has no directory connection named {wl['name']!r}; refusing to create one in place")
        h = have[0]
        _kc("PUT", f"{base}/components/{h['id']}", tok, {**h, "config": {**h.get("config", {}), **wl["config"]}})
        done["ldap"] = True
        existing = {m.get("name"): m for m in (_kc("GET", f"{base}/components?parent={h['id']}&type={LDAP_MAPPER}", tok) or [])}
        for m in (wl.get("subComponents") or {}).get(LDAP_MAPPER, []):
            if m["name"] in existing:
                e = existing[m["name"]]
                if any(e.get("config", {}).get(k) != v for k, v in m["config"].items()):
                    _kc("PUT", f"{base}/components/{e['id']}", tok, {**e, "config": {**e.get("config", {}), **m["config"]}})
                    done["mappers_updated"].append(m["name"])
            else:
                _kc("POST", f"{base}/components", tok, {"name": m["name"], "providerId": m["providerId"], "providerType": LDAP_MAPPER,
                                                        "parentId": h["id"], "config": m["config"]})
                done["mappers_created"].append(m["name"])
    up = (want.get("components") or {}).get("org.keycloak.userprofile.UserProfileProvider")
    if up:
        _kc("PUT", f"{base}/users/profile", tok, json.loads(up[0]["config"]["kc.user.profile.config"][0]))
        done["user_profile"] = True
    for ra in _kc("GET", f"{base}/authentication/required-actions", tok) or []:
        if ra.get("alias") in KC_REQUIRED_ACTIONS and not ra.get("enabled"):
            _kc("PUT", f"{base}/authentication/required-actions/{ra['alias']}", tok, {**ra, "enabled": True})
            done["required_actions"].append(ra["alias"])
    return done



# ---------------------------------------------------------------- cfg.agent_allow (every VM with cfg.*, agent >= 0.10.1)
# A component added to an existing VM (in-place change) needs its packages and image repositories on this VM's allowlists, which the guest
# bootstrap wrote at creation. Additive only: names are added, never removed; the apt sources, the registry, the signing key and the
# signature identity stay exactly as created, so a new repository is still pulled only when signed by the pinned key. The agent reads its
# configuration at start: it is restarted a few seconds after this runbook answered (transient timer, outside this unit).
AGENT_JSON, IMAGE_IDENTITY, IMAGE_POLICY = "/etc/ou-agent/agent.json", "/etc/ou-agent/image-identity.json", "/etc/ou-agent/image-policy.json"


def agent_allow(p, x):
    conf = json.loads(read(AGENT_JSON) or "{}")
    rb = conf.get("runbooks") or {}
    added = {"packages": [], "image_repos": []}
    if p["packages"]:
        if "pkg.install_pinned" not in rb:
            raise Failed("this VM was created without package installs; packages cannot be allowed in place")
        have = set(rb["pkg.install_pinned"].get("packages", []))
        added["packages"] = sorted(set(p["packages"]) - have)
        rb["pkg.install_pinned"]["packages"] = sorted(have | set(p["packages"]))
    ident = json.loads(read(IMAGE_IDENTITY) or "{}")
    if p["image_repos"]:
        if not ident:
            raise Failed("this VM pulls no signed images; image repositories cannot be allowed in place")
        for host, v in ident.items():
            new = sorted(set(p["image_repos"]) - set(v["repos"]))
            added["image_repos"] = sorted(set(added["image_repos"]) | set(new))
            v["repos"] = sorted(set(v["repos"]) | set(p["image_repos"]))
    if not added["packages"] and not added["image_repos"]:
        return {**added, "restart_scheduled": False}
    from . import runbooks as agent_runbooks
    agent_runbooks.validate_config(json.loads(json.dumps(conf)))   # the agent must still accept its configuration after the change
    if added["image_repos"]:
        atomic_write(IMAGE_IDENTITY, json.dumps(ident, sort_keys=True) + "\n", 0o644)
        pol = x.run([BIN["python3"], "/opt/ou-agent/deploy/render_image_policy.py", AGENT_JSON, "/etc/ou-agent/image-signing.pub", "policy"],
                    what="render image policy").stdout
        json.loads(pol)
        atomic_write(IMAGE_POLICY, pol, 0o644)
    if added["packages"]:
        atomic_write(AGENT_JSON, json.dumps(conf, indent=2, sort_keys=True) + "\n", 0o644)
    x.run([BIN["systemd-run"], "--quiet", "--collect", "--on-active=5", f"--unit=ou-agent-allow-restart-{secrets.token_hex(4)}",
           BIN["systemctl"], "try-restart", "ou-agent.service"], what="schedule agent restart")
    return {**added, "restart_scheduled": True}


DISPATCH = {"cfg.firewall": firewall, "cfg.hosts": hosts, "cfg.tls": tls, "cfg.ldap_init": ldap_init, "cfg.ldap_user": ldap_user, "cfg.ldap_list": ldap_list,
            "cfg.ldap_groups": ldap_groups, "cfg.ldap_lock": ldap_lock, "cfg.ldap_delete": ldap_delete, "cfg.pg_db": pg_db,
            "cfg.podman_secret": podman_secret, "cfg.volume_files": volume_files, "cfg.nginx_site": nginx_site, "cfg.gromox": gromox,
            "cfg.nginx_default": nginx_default, "cfg.portal": portal, "cfg.acme": acme,
            "cfg.keycloak_realm": keycloak_realm, "cfg.agent_allow": agent_allow}


def handle(req, cfg):
    action = req.get("action")
    cfg = {**cfg, "runbooks": c.with_implied(cfg.get("runbooks", {}))}   # the same allowlist the agent server advertises (cfgspec.IMPLIED)
    if action not in c.CFG_RUNBOOKS or action not in cfg["runbooks"]:
        raise Reject("not_allowed", "action not allowed for this helper")
    params = c.CHECKS[action](req.get("params"), cfg["runbooks"][action])
    return DISPATCH[action](params, Ctx(params))


SECRET_DIR = "/run/ou-rb-secret"   # root-owned 1770, group ou-agent (the same hardened directory as the PBX credential, review 5 H3)
AGENT_USER = "ou-agent"


def _secret_dir_fd(path=None):
    """The secret directory, OWNED BY ROOT (1770, group ou-agent); anything else there (agent-owned, a symlink, a file) is replaced. Used
    through a file descriptor only, so no path component is looked up twice."""
    path = path or SECRET_DIR
    gid = pwd.getpwnam(AGENT_USER).pw_gid
    try:
        st = os.lstat(path)
        ok = stat.S_ISDIR(st.st_mode) and st.st_uid == 0
    except FileNotFoundError:
        st, ok = None, None
    if ok is False:
        shutil.rmtree(path) if stat.S_ISDIR(st.st_mode) else os.unlink(path)
    if not ok:
        os.mkdir(path, 0o700)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    if os.fstat(fd).st_uid != 0:
        os.close(fd)
        raise Failed("the secret directory is not owned by root")
    os.fchown(fd, 0, gid)
    os.fchmod(fd, 0o1770)
    return fd


def write_secret_result(rid, payload: bytes, path=None):
    """<SECRET_DIR>/cfg-<rid>.json, 0600 owned by the agent, created O_EXCL|O_NOFOLLOW inside the root-owned directory; the agent unlinks it
    right after reading. Never the world-readable RESULT_DIR."""
    pw = pwd.getpwnam(AGENT_USER)
    name = f"cfg-{rid}.json"
    dfd = _secret_dir_fd(path)
    try:
        for f in os.listdir(dfd):   # leftovers of a crashed run never outlive the next secret result; entries are never followed
            try:
                st = os.stat(f, dir_fd=dfd, follow_symlinks=False)
                if f.startswith("cfg-") and (f == name or time.time() - st.st_mtime > 60) and not stat.S_ISDIR(st.st_mode):
                    os.unlink(f, dir_fd=dfd)
            except OSError:
                pass
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
        try:
            os.fchown(fd, pw.pw_uid, pw.pw_gid)
            os.fchmod(fd, 0o600)
            os.write(fd, payload)
        finally:
            os.close(fd)
    finally:
        os.close(dfd)


def main(argv):
    if len(argv) != 1 or not RID_RE.fullmatch(argv[0]):
        print("usage: cfghelper <rid>", file=sys.stderr)
        return 2
    rid = argv[0]
    result = {"rid": rid, "ts": int(time.time())}
    try:
        fd = os.open(os.path.join(SPOOL_DIR, rid + ".json"), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as f:
            req = json.loads(f.read(MAX_SPOOL))
        with open(CONFIG) as f:
            cfg = json.load(f)
        result["result"] = handle(req, cfg)
        if isinstance(result["result"], dict) and "bundle" in result["result"]:   # cfg.acme export: a private key never goes to RESULT_DIR
            write_secret_result(rid, json.dumps({"rid": rid, "bundle": result["result"].pop("bundle")}).encode())
            result["result"]["bundle_secret"] = True
    except Reject as r:
        result["rejected"] = {"code": r.code, "message": r.msg}
    except Failed as e:
        result["error"] = str(e)[:700]
    except Exception as e:  # noqa: BLE001  never echo an exception text: it may carry a parameter
        result["error"] = type(e).__name__
    os.makedirs(RESULT_DIR, mode=0o755, exist_ok=True)
    out = os.path.join(RESULT_DIR, rid + ".json")
    atomic_write(out, json.dumps(result), 0o644)
    for fn in os.listdir(RESULT_DIR):
        p = os.path.join(RESULT_DIR, fn)
        try:
            if fn.endswith(".json") and fn != rid + ".json" and time.time() - os.stat(p).st_mtime > 600:
                os.unlink(p)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
