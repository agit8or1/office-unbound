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

CFG_RUNBOOKS = ("cfg.hosts", "cfg.tls", "cfg.ldap_init", "cfg.ldap_user", "cfg.pg_db", "cfg.podman_secret", "cfg.volume_files", "cfg.nginx_site",
                "cfg.firewall", "cfg.gromox", "cfg.nginx_default", "cfg.portal")
FAMILY = "cfg"

FQDN_RE = re.compile(r"^(?=.{4,200}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")
PASSWORD_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")          # ICS-generated (secrets.token_urlsafe): safe in LDIF, SQL literals, env files
ORG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 .,&()-]{0,62}$")
LDAPNAME_RE = re.compile(r"^[a-z][a-z0-9.-]{0,30}[a-z0-9]$")   # uid, mail local part
GROUP_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,30}[A-Za-z0-9]$")   # group cn (the role groups are camelCase: opencloudAdmin)
PERSON_RE = re.compile(r"^[A-Za-z][A-Za-z .'-]{0,62}$")
DBNAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,30}$")
RELPATH_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}(/[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}){0,3}$")
PEM_RE = {"pubkey": re.compile(r"^-----BEGIN PUBLIC KEY-----\n([A-Za-z0-9+/=]{1,76}\n){2,40}-----END PUBLIC KEY-----\n$"),
          "cert": re.compile(r"^-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=]{1,76}\n){4,200}-----END CERTIFICATE-----\n$"),
          "key": re.compile(r"^-----BEGIN (EC |RSA )?PRIVATE KEY-----\n([A-Za-z0-9+/=]{1,76}\n){2,200}-----END (EC |RSA )?PRIVATE KEY-----\n$")}
# plain HTTP only to this VM's loopback; anything on another host is HTTPS, verified against the deployment CA under `upstream_name`
UPSTREAM_RE = re.compile(r"^(http://127\.0\.0\.1|https://(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}):[0-9]{2,5}$")
MAX_RULES = 64
MAX_MAILBOXES = 32
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
    _exact(p, ("name", "server_names", "upstream", "upstream_name", "tls_name", "max_body_mb"), ("name", "server_names", "upstream", "tls_name", "max_body_mb"))
    names = [_s(n, FQDN_RE, "server name") for n in _list(p["server_names"], "server_names", MAX_NAMES)]
    if not names:
        raise Reject("bad_params", "server_names: at least one")
    up = _s(p["upstream"], UPSTREAM_RE, "upstream (http://127.0.0.1:<port> or https://<ipv4>:<port>)")
    upn = p.get("upstream_name")
    if up.startswith("https://") != (upn is not None):
        raise Reject("bad_params", "upstream_name (the name the upstream certificate must carry) is required for, and only for, an https upstream")
    return {"name": _s(p["name"], NAME_RE, "name"), "server_names": names, "upstream": up,
            "upstream_name": _s(upn, FQDN_RE, "upstream_name") if upn is not None else None,
            "tls_name": _s(p["tls_name"], NAME_RE, "tls_name"), "max_body_mb": _int(p["max_body_mb"], 0, 102400, "max_body_mb")}


def check_firewall(p, cfg):
    """Peer allowances: exact (source address, protocol, port) triples; replaces the previous set (an empty list closes them all)."""
    _exact(p, ("rules",))
    out = []
    for r in _list(p["rules"], "rules", MAX_RULES):
        _exact(r, ("source", "proto", "port"))
        if r["proto"] not in ("tcp", "udp"):
            raise Reject("bad_params", "proto must be tcp or udp")
        out.append({"source": _s(r["source"], IPV4_RE, "source address"), "proto": r["proto"], "port": _int(r["port"], 1, 65535, "port")})
    if len({(r["source"], r["proto"], r["port"]) for r in out}) != len(out):
        raise Reject("bad_params", "duplicate rule")
    return {"rules": sorted(out, key=lambda r: (r["source"], r["proto"], r["port"]))}


def _mail(v, domain, what):
    if not isinstance(v, str) or v.count("@") != 1:
        raise Reject("bad_params", f"{what} must be local@domain")
    local, _, dom = v.partition("@")
    _s(local, LDAPNAME_RE, f"{what} local part")
    if dom != domain:
        raise Reject("bad_params", f"{what} must be an address of the deployment's mail domain")
    return v


HTTPS_ROOT_RE = re.compile(r"^https://(([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})/$")
CLIENT_RE = re.compile(r"^[a-z][a-z0-9-]{1,40}$")


def _https_host(v, what, path=""):
    """https://<fqdn><path> exactly (no port, query or other path)."""
    if not isinstance(v, str) or not v.startswith("https://") or not v.endswith(path) or len(v) > 260:
        raise Reject("bad_params", f"{what} must be https://<name>{path}")
    host = v[len("https://"):len(v) - len(path)] if path else v[len("https://"):]
    _s(host, FQDN_RE, what)
    return v


def check_sso(p):
    """Webmail sign-in through Keycloak (grommunio-web keycloak.json + gromox bearer_pubkey): the realm's issuer base, the webmail client and the
    realm's public signing key the ICS generated."""
    _exact(p, ("auth_url", "realm", "client_id", "client_secret", "redirect_url", "bearer_pubkey"))
    if not isinstance(p["auth_url"], str) or not HTTPS_ROOT_RE.fullmatch(p["auth_url"]):
        raise Reject("bad_params", "sso.auth_url must be https://<name>/")
    return {"auth_url": p["auth_url"], "realm": _s(p["realm"], CLIENT_RE, "sso.realm"),
            "client_id": _s(p["client_id"], CLIENT_RE, "sso.client_id"), "client_secret": _password(p["client_secret"], "sso.client_secret"),
            "redirect_url": _https_host(p["redirect_url"], "sso.redirect_url", "/web"), "bearer_pubkey": _pem(p["bearer_pubkey"], "pubkey")}


def check_gromox(p, cfg):
    """The groupware node (gromox + Postfix + MariaDB + grommunio web/sync/dav behind nginx): mail domain, the VM's mail host name, the
    deployment TLS material (cfg.tls), the database password, the read-only directory bind (cfg.ldap_init's svc-bind) and the entitlement
    group. `mailboxes` are directory addresses whose mailbox is created when the directory entry exists and is in the group."""
    _exact(p, ("domain", "hostname", "tls_name", "db_password", "ldap_host", "bind_password", "group", "mailboxes", "sso"),
           ("domain", "hostname", "tls_name", "db_password", "ldap_host", "bind_password", "group", "mailboxes"))
    domain = _s(p["domain"], FQDN_RE, "domain")
    host = _s(p["hostname"], FQDN_RE, "hostname")      # the mail host may be any name (name settings), the directory is the deployment's own
    ldap_host = _s(p["ldap_host"], FQDN_RE, "ldap_host")
    if not ldap_host.endswith("." + domain):
        raise Reject("bad_params", "ldap_host must be a name inside the mail domain")
    boxes = [_mail(m, domain, "mailbox") for m in _list(p["mailboxes"], "mailboxes", MAX_MAILBOXES)]
    if len(set(boxes)) != len(boxes):
        raise Reject("bad_params", "duplicate mailbox")
    return {"domain": domain, "hostname": host, "tls_name": _s(p["tls_name"], NAME_RE, "tls_name"),
            "db_password": _password(p["db_password"], "db_password"), "ldap_host": ldap_host,
            "bind_password": _password(p["bind_password"], "bind_password"), "group": _s(p["group"], GROUP_RE, "group"), "mailboxes": boxes,
            **({"sso": check_sso(p["sso"])} if p.get("sso") is not None else {})}


def check_nginx_default(p, cfg):
    """What a request for any other name (a bare IP address, an unknown host) gets: a redirect to one https URL (the portal), or nothing."""
    _exact(p, ("redirect", "tls_name"))
    r = p["redirect"]
    return {"redirect": _https_host(r, "redirect", "/") if r is not None else None, "tls_name": _s(p["tls_name"], NAME_RE, "tls_name")}


def check_portal(p, cfg):
    """The user portal (package ou-portal): its public URL, the Keycloak issuer and client, the apps it links to. Plain HTTP on 127.0.0.1:8090
    behind the TLS proxy; the client secret goes to a file, never into the environment file."""
    _exact(p, ("base_url", "issuer", "client_id", "client_secret", "files_url", "mail_web_url", "mail_host", "mail_domain", "org_name"))
    base = _https_host(p["base_url"], "base_url")
    iss = p["issuer"]
    if not isinstance(iss, str) or "/realms/" not in iss:
        raise Reject("bad_params", "issuer must be https://<name>/realms/<realm>")
    host, _, realm = iss.partition("/realms/")
    _https_host(host, "issuer")
    _s(realm, CLIENT_RE, "issuer realm")
    files = _https_host(p["files_url"], "files_url") if p["files_url"] else ""
    web = _https_host(p["mail_web_url"], "mail_web_url", "/web/") if p["mail_web_url"] else ""
    return {"base_url": base, "issuer": iss, "client_id": _s(p["client_id"], CLIENT_RE, "client_id"),
            "client_secret": _password(p["client_secret"], "client_secret"), "files_url": files, "mail_web_url": web,
            "mail_host": _s(p["mail_host"], FQDN_RE, "mail_host") if p["mail_host"] else "", "mail_domain": _s(p["mail_domain"], FQDN_RE, "mail_domain"),
            "org_name": _s(p["org_name"], ORG_RE, "org_name")}


CHECKS = {"cfg.firewall": check_firewall, "cfg.gromox": check_gromox, "cfg.hosts": check_hosts, "cfg.tls": check_tls, "cfg.ldap_init": check_ldap_init, "cfg.ldap_user": check_ldap_user,
          "cfg.pg_db": check_pg_db, "cfg.podman_secret": check_podman_secret, "cfg.volume_files": check_volume_files,
          "cfg.nginx_site": check_nginx_site, "cfg.nginx_default": check_nginx_default, "cfg.portal": check_portal}


def validate_runbook_config(name, c):
    if c != {"enabled": True}:
        raise ValueError(f"{name} takes exactly {{\"enabled\": true}}")


def base_dn(domain):
    return ",".join(f"dc={x}" for x in domain.split("."))
