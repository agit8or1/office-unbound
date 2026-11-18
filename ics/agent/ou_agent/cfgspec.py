"""Typed, strictly validated parameters for the guest CONFIGURATION runbooks (family `cfg`, root helper ou-rb-cfg@). Pure functions, stdlib only.

These runbooks create the node-local state a component needs before its unit can start (docs/status/artifacts-core-results.md open item 5):
name resolution for the deployment's names, the deployment TLS material, the directory (OpenLDAP), a PostgreSQL role/database, podman
secrets, files inside a component's named volume and an edge (nginx) site. Each one is fixed code in cfghelper.py; the ICS sends VALUES only.

Secret values (passwords, private keys) travel in these params, so the cfg family spools its request 0600 (never the world-readable spool of the
other families) and its results never echo a parameter. Every string has a tight character class: no value can add a line to a generated file,
an LDIF record or an SQL statement. Used twice: by the agent before spooling and again by the helper, which never trusts the spool."""
import base64
import re

from .guestspec import DIGEST_RE, IPV4_RE, NAME_RE, REGISTRY_RE, REPO_RE, SECRET_RE, USER_RE, VOLNAME_RE, _exact, _int, _s
from .proto import Reject

CFG_RUNBOOKS = ("cfg.hosts", "cfg.tls", "cfg.ldap_init", "cfg.ldap_user", "cfg.pg_db", "cfg.podman_secret", "cfg.volume_files", "cfg.nginx_site")
FAMILY = "cfg"

FQDN_RE = re.compile(r"^(?=.{4,200}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")
PASSWORD_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")          # ICS-generated (secrets.token_urlsafe): safe in LDIF, SQL literals, env files
ORG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 .,&()-]{0,62}$")
LDAPNAME_RE = re.compile(r"^[a-z][a-z0-9.-]{0,30}[a-z0-9]$")   # uid, mail local part
GROUP_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,30}[A-Za-z0-9]$")   # group cn (the role groups are camelCase: opencloudAdmin)
PERSON_RE = re.compile(r"^[A-Za-z][A-Za-z .'-]{0,62}$")
DBNAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,30}$")
RELPATH_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}(/[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}){0,3}$")
PEM_RE = {"cert": re.compile(r"^-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=]{1,76}\n){4,200}-----END CERTIFICATE-----\n$"),
          "key": re.compile(r"^-----BEGIN (EC |RSA )?PRIVATE KEY-----\n([A-Za-z0-9+/=]{1,76}\n){2,200}-----END (EC |RSA )?PRIVATE KEY-----\n$")}
UPSTREAM_RE = re.compile(r"^http://(127\.0\.0\.1|(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}):[0-9]{2,5}$")
MAX_HOSTS, MAX_NAMES, MAX_GROUPS, MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES = 32, 16, 16, 16, 262144, 524288
FILE_MODES = (0o600, 0o640, 0o644)


def _password(v, what):
    if not isinstance(v, str) or not PASSWORD_RE.fullmatch(v):
        raise Reject("bad_params", f"{what} must be 16-128 characters of [A-Za-z0-9_-]")
    return v


def _list(v, what, n):
    if not isinstance(v, list) or len(v) > n:
        raise Reject("bad_params", f"{what}: list of at most {n}")
    return v


def _pem(v, kind):
    if not isinstance(v, str) or len(v) > 32768 or not PEM_RE[kind].fullmatch(v):
        raise Reject("bad_params", f"{kind} must be one PEM block")
    body = "".join(v.strip().splitlines()[1:-1])
    try:
        base64.b64decode(body, validate=True)
    except ValueError:
        raise Reject("bad_params", f"{kind}: invalid base64") from None
    return v


def check_hosts(p, cfg):
    _exact(p, ("entries",))
    out = []
    for e in _list(p["entries"], "entries", MAX_HOSTS):
        _exact(e, ("ip", "names"))
        names = [_s(n, FQDN_RE, "host name") for n in _list(e["names"], "names", MAX_NAMES)]
        if not names:
            raise Reject("bad_params", "an entry needs at least one name")
        out.append({"ip": _s(e["ip"], IPV4_RE, "address"), "names": names})
    if len({n for e in out for n in e["names"]}) != sum(len(e["names"]) for e in out):
        raise Reject("bad_params", "a name may appear only once")
    return {"entries": out}


def check_tls(p, cfg):
    _exact(p, ("name", "ca_pem", "cert_pem", "key_pem"))
    return {"name": _s(p["name"], NAME_RE, "name"), "ca_pem": _pem(p["ca_pem"], "cert"), "cert_pem": _pem(p["cert_pem"], "cert"),
            "key_pem": _pem(p["key_pem"], "key")}


def check_ldap_init(p, cfg):
    _exact(p, ("domain", "organization", "admin_password", "bind_password", "tls_name", "groups"))
    groups = [_s(g, GROUP_RE, "group") for g in _list(p["groups"], "groups", MAX_GROUPS)]
    if len(set(groups)) != len(groups):
        raise Reject("bad_params", "duplicate group")
    return {"domain": _s(p["domain"], FQDN_RE, "domain"), "organization": _s(p["organization"], ORG_RE, "organization"),
            "admin_password": _password(p["admin_password"], "admin_password"), "bind_password": _password(p["bind_password"], "bind_password"),
            "tls_name": _s(p["tls_name"], NAME_RE, "tls_name"), "groups": groups}


def check_ldap_user(p, cfg):
    _exact(p, ("domain", "uid", "given_name", "surname", "mail", "password", "groups"))
    groups = [_s(g, GROUP_RE, "group") for g in _list(p["groups"], "groups", MAX_GROUPS)]
    mail = p["mail"]
    if not isinstance(mail, str) or "@" not in mail:
        raise Reject("bad_params", "mail")
    local, _, dom = mail.partition("@")
    _s(local, LDAPNAME_RE, "mail local part")
    _s(dom, FQDN_RE, "mail domain")
    return {"domain": _s(p["domain"], FQDN_RE, "domain"), "uid": _s(p["uid"], LDAPNAME_RE, "uid"),
            "given_name": _s(p["given_name"], PERSON_RE, "given_name"), "surname": _s(p["surname"], PERSON_RE, "surname"), "mail": mail,
            "password": _password(p["password"], "password"), "groups": groups}


def check_pg_db(p, cfg):
    _exact(p, ("role", "database", "password"))
    return {"role": _s(p["role"], DBNAME_RE, "role"), "database": _s(p["database"], DBNAME_RE, "database"),
            "password": _password(p["password"], "password")}


def check_podman_secret(p, cfg):
    _exact(p, ("name", "value"))
    return {"name": _s(p["name"], SECRET_RE, "secret name"), "value": _password(p["value"], "value")}


def check_volume_files(p, cfg):
    _exact(p, ("component", "volume", "image", "owner", "files"))
    comp = _s(p["component"], NAME_RE, "component")
    vol = _s(p["volume"], VOLNAME_RE, "volume")
    img = p["image"]
    if not isinstance(img, str) or "@" not in img:
        raise Reject("bad_params", "image must be <registry>/<repo>@sha256:<digest>")
    name, _, digest = img.partition("@")
    reg, _, repo = name.partition("/")
    if ":" in repo or not REGISTRY_RE.fullmatch(reg) or not REPO_RE.fullmatch(repo) or not DIGEST_RE.fullmatch(digest):
        raise Reject("bad_params", "image must be <registry>/<repo>@sha256:<digest>")
    owner = _s(p["owner"], USER_RE, "owner")
    files, total, seen = [], 0, set()
    for f in _list(p["files"], "files", MAX_FILES):
        _exact(f, ("path", "mode", "content"))
        path = _s(f["path"], RELPATH_RE, "file path")
        if ".." in path.split("/") or path in seen:
            raise Reject("bad_params", "invalid or duplicate file path")
        seen.add(path)
        mode = _int(f["mode"], 0, 0o777, "mode")
        if mode not in FILE_MODES:
            raise Reject("bad_params", "mode must be 0600, 0640 or 0644")
        c = f["content"]
        if not isinstance(c, str) or len(c.encode()) > MAX_FILE_BYTES or "\x00" in c:
            raise Reject("bad_params", "file content: text up to %d bytes" % MAX_FILE_BYTES)
        total += len(c.encode())
        files.append({"path": path, "mode": mode, "content": c})
    if not files or total > MAX_TOTAL_BYTES:
        raise Reject("bad_params", "files: 1..%d entries, at most %d bytes in total" % (MAX_FILES, MAX_TOTAL_BYTES))
    return {"component": comp, "volume": vol, "image": img, "owner": owner, "files": files}


def check_nginx_site(p, cfg):
    _exact(p, ("name", "server_names", "upstream", "tls_name", "max_body_mb"))
    names = [_s(n, FQDN_RE, "server name") for n in _list(p["server_names"], "server_names", MAX_NAMES)]
    if not names:
        raise Reject("bad_params", "server_names: at least one")
    return {"name": _s(p["name"], NAME_RE, "name"), "server_names": names, "upstream": _s(p["upstream"], UPSTREAM_RE, "upstream"),
            "tls_name": _s(p["tls_name"], NAME_RE, "tls_name"), "max_body_mb": _int(p["max_body_mb"], 0, 102400, "max_body_mb")}


CHECKS = {"cfg.hosts": check_hosts, "cfg.tls": check_tls, "cfg.ldap_init": check_ldap_init, "cfg.ldap_user": check_ldap_user,
          "cfg.pg_db": check_pg_db, "cfg.podman_secret": check_podman_secret, "cfg.volume_files": check_volume_files,
          "cfg.nginx_site": check_nginx_site}


def validate_runbook_config(name, c):
    if c != {"enabled": True}:
        raise ValueError(f"{name} takes exactly {{\"enabled\": true}}")


def base_dn(domain):
    return ",".join(f"dc={x}" for x in domain.split("."))
