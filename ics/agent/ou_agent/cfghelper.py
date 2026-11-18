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
BIN = {"openssl": "/usr/bin/openssl", "update-ca": "/usr/sbin/update-ca-certificates", "debconf-set": "/usr/bin/debconf-set-selections",
       "dpkg-reconfigure": "/usr/sbin/dpkg-reconfigure", "dpkg-query": "/usr/bin/dpkg-query", "ldapsearch": "/usr/bin/ldapsearch",
       "ldapmodify": "/usr/bin/ldapmodify", "systemctl": "/usr/bin/systemctl", "runuser": "/usr/sbin/runuser", "podman": "/usr/bin/podman",
       "psql": "/usr/bin/psql", "nginx": "/usr/sbin/nginx", "nft": "/usr/sbin/nft"}
ROOT_ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "DEBIAN_FRONTEND": "noninteractive"}
SECRET_KEYS = ("admin_password", "bind_password", "password", "value", "key_pem")


class Failed(Exception):
    """A step failed; the message is already scrubbed and short."""


class Ctx:
    def __init__(self, params):
        self.secrets = sorted({str(params[k]) for k in SECRET_KEYS if isinstance(params.get(k), str) and params.get(k)}, key=len, reverse=True)
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
    atomic_write(os.path.join(TLS_DIR, "ca.crt"), p["ca_pem"], 0o644)
    atomic_write(key, p["key_pem"], 0o600)
    atomic_write(crt, p["cert_pem"], 0o644)
    if _pubkey(x, "cert", crt) != _pubkey(x, "key", key):
        raise Failed("the certificate does not belong to the private key")
    x.run([BIN["openssl"], "verify", "-CAfile", os.path.join(TLS_DIR, "ca.crt"), crt], what="openssl verify")
    changed = read(CA_TRUST) != p["ca_pem"]
    if changed:
        atomic_write(CA_TRUST, p["ca_pem"], 0o644)
        x.run([BIN["update-ca"]], what="update-ca-certificates")
    return {"name": p["name"], "ca_trust_updated": changed}


# ---------------------------------------------------------------- OpenLDAP
def ssha(pw):
    salt = secrets.token_bytes(8)
    return "{SSHA}" + base64.b64encode(hashlib.sha1(pw.encode() + salt).digest() + salt).decode()


def ldapi(x, ldif, what, add=False):
    argv = [BIN["ldapmodify"], "-Q", "-Y", "EXTERNAL", "-H", "ldapi:///"] + (["-a"] if add else [])
    return x.run(argv, input=ldif, what=what)


def ldap_search(x, base, flt, attrs, scope="sub"):
    r = x.run([BIN["ldapsearch"], "-LLL", "-o", "ldif-wrap=no", "-Q", "-Y", "EXTERNAL", "-H", "ldapi:///", "-s", scope, "-b", base, flt, *attrs],
              check=False, what="ldapsearch")
    if r.returncode == 32:   # no such object
        return ""
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
    ldapi(x, f"dn: {db}\nchangetype: modify\nreplace: olcAccess\n"
             f"olcAccess: {{0}}to * by dn.exact=\"{root}\" manage by * break\n"
             f"olcAccess: {{1}}to attrs=userPassword by self write by anonymous auth by * none\n"
             f"olcAccess: {{2}}to attrs=pwdAccountLockedTime,pwdFailureTime,pwdChangedTime,pwdHistory by dn.exact=\"{bind_dn}\" read by * none\n"
             f"olcAccess: {{3}}to * by dn.exact=\"{bind_dn}\" read by self read by * none\n-\n"
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
                        BIN["podman"], "run", "--rm", "-i", "--pull=never", "--network=none", "--user", "0", "--entrypoint", "/bin/sh",
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
  return 301 https://$host$request_uri;
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
  location / {{
    proxy_pass {upstream};
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


def nginx_site(p, x):
    for f in (p["tls_name"] + ".crt", p["tls_name"] + ".key"):
        if not os.path.exists(os.path.join(TLS_DIR, f)):
            raise Failed(f"missing {f}: cfg.tls must run first")
    atomic_write(NGINX_MAP, "# generated by ou-agent (cfg.nginx_site)\nmap $http_upgrade $ou_connection_upgrade {\n  default upgrade;\n  '' close;\n}\n", 0o644)
    path, link = os.path.join(NGINX_AVAIL, "ou-" + p["name"]), os.path.join(NGINX_ENABLED, "ou-" + p["name"])
    old = read(path)
    body = f"{p['max_body_mb']}m" if p["max_body_mb"] else "0"
    atomic_write(path, NGINX_SITE.format(names=" ".join(p["server_names"]), tls=TLS_DIR, cert=p["tls_name"], body=body, upstream=p["upstream"]), 0o644)
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


DISPATCH = {"cfg.firewall": firewall, "cfg.hosts": hosts, "cfg.tls": tls, "cfg.ldap_init": ldap_init, "cfg.ldap_user": ldap_user, "cfg.pg_db": pg_db,
            "cfg.podman_secret": podman_secret, "cfg.volume_files": volume_files, "cfg.nginx_site": nginx_site}


def handle(req, cfg):
    action = req.get("action")
    if action not in c.CFG_RUNBOOKS or action not in cfg.get("runbooks", {}):
        raise Reject("not_allowed", "action not allowed for this helper")
    params = c.CHECKS[action](req.get("params"), cfg["runbooks"][action])
    return DISPATCH[action](params, Ctx(params))


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
