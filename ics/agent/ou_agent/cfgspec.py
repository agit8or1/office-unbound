"""Typed, strictly validated parameters for the guest CONFIGURATION runbooks (family `cfg`, root helper ou-rb-cfg@). Pure functions, stdlib only.

These runbooks create the node-local state a component needs before its unit can start (docs/status/artifacts-core-results.md open item 5):
name resolution for the deployment's names, the deployment TLS material, the directory (OpenLDAP), a PostgreSQL role/database, podman
secrets, files inside a component's named volume and an edge (nginx) site. Each one is fixed code in cfghelper.py; the ICS sends VALUES only.

Secret values (passwords, private keys) travel in these params, so the cfg family spools its request 0600 (never the world-readable spool of the
other families) and its results never echo a parameter. Every string has a tight character class: no value can add a line to a generated file,
an LDIF record or an SQL statement. Used twice: by the agent before spooling and again by the helper, which never trusts the spool."""
import base64
import json
import re

from .guestspec import DIGEST_RE, IPV4_RE, NAME_RE, REGISTRY_RE, REPO_RE, SECRET_RE, USER_RE, VOLNAME_RE, _exact, _int, _s
from .proto import Reject

CFG_RUNBOOKS = ("cfg.hosts", "cfg.tls", "cfg.ldap_init", "cfg.ldap_user", "cfg.ldap_list", "cfg.ldap_groups", "cfg.ldap_lock", "cfg.ldap_delete",
                "cfg.pg_db", "cfg.podman_secret", "cfg.volume_files", "cfg.nginx_site",
                "cfg.firewall", "cfg.gromox", "cfg.nginx_default", "cfg.portal", "cfg.acme", "cfg.keycloak_realm", "cfg.agent_allow")
IMPLIED = {"cfg.keycloak_realm": "cfg.ldap_list", "cfg.agent_allow": "cfg.hosts"}   # enabled wherever the marker is (runbooks.validate_config): the identity VM


def with_implied(runbooks: dict) -> dict:
    """The allowlist with the runbooks its role implies (IMPLIED). The agent server and the root cfghelper must agree: the server
    advertised cfg.agent_allow from this while the helper read the file raw and refused it (officeunbound8, job 7c750171)."""
    out = dict(runbooks)
    for implied, marker in IMPLIED.items():
        if marker in out and implied not in out:
            out[implied] = {"enabled": True}
    return out
FAMILY = "cfg"

FQDN_RE = re.compile(r"^(?=.{4,200}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")
PASSWORD_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")          # ICS-generated (secrets.token_urlsafe): safe in LDIF, SQL literals, env files
# a PERSON's directory password (cfg.ldap_user), set by an administrator (owner 2026-11-20: "change password to 8 char min"); the same safe
# character set, minimum 8. Machine secrets keep PASSWORD_RE.
USER_PASSWORD_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
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


def _user_password(v):
    if not isinstance(v, str) or not USER_PASSWORD_RE.fullmatch(v):
        raise Reject("bad_params", "password: 8-128 characters, letters, digits, - and _")
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
    """Optional `writer_password` (feature "writer"): the sign-in service's own account cn=svc-idp, the only one that may change people's
    passwords and their self-editable profile attributes (LDAP_SELF_ATTRS); the shared read account svc-bind stays read-only."""
    _exact(p, ("domain", "organization", "admin_password", "bind_password", "tls_name", "groups", "writer_password"),
           ("domain", "organization", "admin_password", "bind_password", "tls_name", "groups"))
    groups = [_s(g, GROUP_RE, "group") for g in _list(p["groups"], "groups", MAX_GROUPS)]
    if len(set(groups)) != len(groups):
        raise Reject("bad_params", "duplicate group")
    return {"domain": _s(p["domain"], FQDN_RE, "domain"), "organization": _s(p["organization"], ORG_RE, "organization"),
            "admin_password": _password(p["admin_password"], "admin_password"), "bind_password": _password(p["bind_password"], "bind_password"),
            "tls_name": _s(p["tls_name"], NAME_RE, "tls_name"), "groups": groups,
            "writer_password": _password(p["writer_password"], "writer_password") if p.get("writer_password") is not None else None}


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
            "password": _user_password(p["password"]), "groups": groups}


PROTECTED_UID = "ou-admin"   # the deployment's own administrator (cfg.ldap_delete refuses it)


def _groups(v, what):
    groups = [_s(g, GROUP_RE, "group") for g in _list(v, what, MAX_GROUPS)]
    if len(set(groups)) != len(groups):
        raise Reject("bad_params", f"duplicate group in {what}")
    return groups


def check_ldap_list(p, cfg):
    _exact(p, ("domain",))
    return {"domain": _s(p["domain"], FQDN_RE, "domain")}


def check_ldap_groups(p, cfg):
    _exact(p, ("domain", "uid", "add", "remove"))
    add, remove = _groups(p["add"], "add"), _groups(p["remove"], "remove")
    if set(add) & set(remove):
        raise Reject("bad_params", "a group may not be both added and removed")
    return {"domain": _s(p["domain"], FQDN_RE, "domain"), "uid": _s(p["uid"], LDAPNAME_RE, "uid"), "add": add, "remove": remove}


def check_ldap_lock(p, cfg):
    _exact(p, ("domain", "uid", "locked"))
    if not isinstance(p["locked"], bool):
        raise Reject("bad_params", "locked must be true or false")
    return {"domain": _s(p["domain"], FQDN_RE, "domain"), "uid": _s(p["uid"], LDAPNAME_RE, "uid"), "locked": p["locked"]}


def check_ldap_delete(p, cfg):
    _exact(p, ("domain", "uid"))
    uid = _s(p["uid"], LDAPNAME_RE, "uid")
    if uid == PROTECTED_UID:
        raise Reject("bad_params", f"{PROTECTED_UID} (the deployment's administrator) cannot be deleted")
    return {"domain": _s(p["domain"], FQDN_RE, "domain"), "uid": uid}


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
    _exact(p, ("name", "server_names", "upstream", "upstream_name", "tls_name", "max_body_mb", "upstream_ca", "root_redirect", "lockdown"),
           ("name", "server_names", "upstream", "tls_name", "max_body_mb"))
    names = [_s(n, FQDN_RE, "server name") for n in _list(p["server_names"], "server_names", MAX_NAMES)]
    if not names:
        raise Reject("bad_params", "server_names: at least one")
    up = _s(p["upstream"], UPSTREAM_RE, "upstream (http://127.0.0.1:<port> or https://<ipv4>:<port>)")
    upn = p.get("upstream_name")
    if up.startswith("https://") != (upn is not None):
        raise Reject("bad_params", "upstream_name (the name the upstream certificate must carry) is required for, and only for, an https upstream")
    return {"name": _s(p["name"], NAME_RE, "name"), "server_names": names, "upstream": up,
            "upstream_name": _s(upn, FQDN_RE, "upstream_name") if upn is not None else None,
            "tls_name": _s(p["tls_name"], NAME_RE, "tls_name"), "max_body_mb": _int(p["max_body_mb"], 0, 102400, "max_body_mb"),
            **({"upstream_ca": _s(p["upstream_ca"], NAME_RE, "upstream_ca")} if p.get("upstream_ca") else {}),
            **({"root_redirect": _https_host(p["root_redirect"], "root_redirect", "/")} if p.get("root_redirect") else {}),
            **({"lockdown": _lockdown(p["lockdown"])} if p.get("lockdown") is not None else {})}


# which app's own administration surfaces the site refuses (fixed rules in cfghelper.LOCKDOWN; the ICS names a profile, never sends nginx text)
LOCKDOWN_PROFILES = ("keycloak", "opencloud", "collabora", "groupware")


def _lockdown(v):
    if v not in LOCKDOWN_PROFILES:
        raise Reject("bad_params", "lockdown must be one of " + ", ".join(LOCKDOWN_PROFILES))
    return v


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


MAX_BRAND_CSS, MAX_BRAND_SVG, MAX_BRAND_FONTS = 65536, 16384, 262144
FONTS_CSS_RE = re.compile(r"(?:\s*/\*[^*]*\*/\s*)?(?:@font-face \{ font-family: \"[A-Za-z ]{1,40}\"; src: url\(\"data:font/woff2;base64,[A-Za-z0-9+/]+=*\"\) "
                          r"format\(\"woff2\"\); font-weight: [1-9]00; font-style: (?:normal|italic); font-display: swap; \}\n){1,8}")
SVG_BAD_RE = re.compile(r"<\s*(script|foreignobject|iframe|object|embed|style)|\bon[a-z]+\s*=|javascript:|data:|<!|href\s*=\s*[\"']?(?!#)", re.I)


def _text(v, what, n):
    if not isinstance(v, str) or not v or len(v.encode()) > n or re.search(r"[\x00-\x08\x0b-\x1f\x7f]", v):
        raise Reject("bad_params", f"{what}: text up to {n} bytes without control characters")
    return v


def check_brand(p):
    """The Office Unbound skin of the webmail (ics/ics/deploy/brand.py): /brand/brand.css (grommunio-web's own branding hook), the mark it
    references (/brand/ou-mark.svg: a plain SVG, served with a sandboxing CSP), the portal the oudashboard plugin's button returns to and
    (FEATURES brand_fonts) /brand/ou-fonts.css: @font-face rules with embedded woff2 data only, nothing else (FONTS_CSS_RE)."""
    _exact(p, ("css", "mark_svg", "portal_url", "fonts_css"), ("css", "mark_svg"))
    svg = _text(p["mark_svg"], "brand.mark_svg", MAX_BRAND_SVG)
    if not re.fullmatch(r"\s*<svg\b[^>]*>[\s\S]*</svg>\s*", svg) or SVG_BAD_RE.search(svg):
        raise Reject("bad_params", "brand.mark_svg must be one plain <svg> element (no script, handlers, foreign content or external references)")
    out = {"css": _text(p["css"], "brand.css", MAX_BRAND_CSS), "mark_svg": svg,
           **({"portal_url": _https_host(p["portal_url"], "brand.portal_url", "/")} if p.get("portal_url") is not None else {})}
    if p.get("fonts_css") is not None:
        fc = _text(p["fonts_css"], "brand.fonts_css", MAX_BRAND_FONTS)
        if not FONTS_CSS_RE.fullmatch(fc):
            raise Reject("bad_params", "brand.fonts_css must be @font-face rules with embedded woff2 data only")
        out["fonts_css"] = fc
    return out


def check_gromox(p, cfg):
    """The groupware node (gromox + Postfix + MariaDB + grommunio web/sync/dav behind nginx): mail domain, the VM's mail host name, the
    deployment TLS material (cfg.tls), the database password, the read-only directory bind (cfg.ldap_init's svc-bind) and the entitlement
    group. `mailboxes` are directory addresses whose mailbox is created when the directory entry exists and is in the group."""
    _exact(p, ("domain", "hostname", "tls_name", "db_password", "ldap_host", "bind_password", "group", "mailboxes", "sso", "brand"),
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
            **({"sso": check_sso(p["sso"])} if p.get("sso") is not None else {}),
            **({"brand": check_brand(p["brand"])} if p.get("brand") is not None else {})}


def check_nginx_default(p, cfg):
    """What a request for any other name (a bare IP address, an unknown host) gets: a redirect to one https URL (the portal), or nothing."""
    _exact(p, ("redirect", "tls_name"))
    r = p["redirect"]
    return {"redirect": _https_host(r, "redirect", "/") if r is not None else None, "tls_name": _s(p["tls_name"], NAME_RE, "tls_name")}


MAX_ACME_NAMES = 20


CERT_PEM_RE = re.compile(r"(?:-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]{100,8000}-----END CERTIFICATE-----\n){1,4}")
KEY_PEM_RE = re.compile(r"-----BEGIN PRIVATE KEY-----\n[A-Za-z0-9+/=\n]{100,4000}-----END PRIVATE KEY-----\n")
ACCOUNT_ID_RE = re.compile(r"^[0-9a-f]{32}$")
ACCOUNT_FILES = ("meta", "regr", "private_key")
MAX_ACCOUNT_JSON = 16384


def _json_obj(v, what):
    t = _text(v, what, MAX_ACCOUNT_JSON)
    try:
        o = json.loads(t)
    except ValueError:
        raise Reject("bad_params", f"{what}: JSON object") from None
    if not isinstance(o, dict):
        raise Reject("bad_params", f"{what}: JSON object")
    return t


def check_acme_bundle(b):
    """A certificate lineage captured from a gateway (feature `reuse`): the production ACME account (three certbot JSON files, data only) and
    the current certificate files. Only DATA crosses: the agent writes the renewal configuration and the live links itself, so no certbot
    option or hook (which certbot runs as root) can come from outside."""
    _exact(b, ("account_id", "account", "cert", "chain", "fullchain", "privkey"))
    acct = b["account"]
    _exact(acct, ACCOUNT_FILES)
    out = {"account_id": _s(b["account_id"], ACCOUNT_ID_RE, "account_id"), "account": {k: _json_obj(acct[k], f"account.{k}") for k in ACCOUNT_FILES}}
    for k in ("cert", "chain", "fullchain"):
        out[k] = _s(b[k], CERT_PEM_RE, k)
    out["privkey"] = _s(b["privkey"], KEY_PEM_RE, "privkey")
    if not out["fullchain"].startswith(out["cert"]):
        raise Reject("bad_params", "fullchain must start with cert")
    return out


def check_acme(p, cfg):
    """Publicly trusted certificate for exactly these names (HTTP-01 through the VM's own port 80), staging or production Let's Encrypt.
    Feature `reuse` (production only): `restore` installs a lineage captured from an earlier gateway before certbot runs (certbot then keeps it
    while it is not due for renewal: no new order); `export` returns the lineage the gateway serves afterwards."""
    _exact(p, ("names", "directory", "cert_name", "export", "restore"), ("names", "directory", "cert_name"))
    names = [_s(n, FQDN_RE, "name") for n in _list(p["names"], "names", MAX_ACME_NAMES)]
    if not names or len(set(names)) != len(names):
        raise Reject("bad_params", "names: one or more distinct names")
    if p["directory"] not in ("staging", "production"):
        raise Reject("bad_params", "directory must be staging or production")
    out = {"names": names, "directory": p["directory"], "cert_name": _s(p["cert_name"], NAME_RE, "cert_name")}
    if p.get("export") is not None:
        if not isinstance(p["export"], bool):
            raise Reject("bad_params", "export must be true or false")
        out["export"] = p["export"]
    if p.get("restore") is not None:
        out["restore"] = check_acme_bundle(p["restore"])
    if (out.get("export") or "restore" in out) and out["directory"] != "production":
        raise Reject("bad_params", "certificate reuse is for production certificates only")
    return out


# the portal's credential for the ICS tenant-admin API of ITS deployment (configure.portal_key): tdk_<deployment id>.<secret>
PORTAL_ICS_KEY_RE = re.compile(r"^tdk_[0-9a-f]{32}\.[A-Za-z0-9_-]{43}$")
PORTAL_KEYS = ("base_url", "issuer", "client_id", "client_secret", "files_url", "mail_web_url", "mail_host", "mail_domain", "org_name")
FEATURES = {"cfg.portal": ["admin"], "cfg.gromox": ["brand_fonts"], "cfg.acme": ["reuse"], "cfg.ldap_init": ["writer"]}   # optional parameters this agent understands, reported in its capabilities (the ICS sends them only then)


def check_portal_admin(a):
    """The admin area's link to the ICS: the ICS base URL (https://<name>, never an address) and the deployment's portal credential."""
    if not isinstance(a, dict):
        raise Reject("bad_params", "admin must be an object or null")
    _exact(a, ("ics_url", "ics_key"))
    if not isinstance(a["ics_key"], str) or not PORTAL_ICS_KEY_RE.fullmatch(a["ics_key"]):
        raise Reject("bad_params", "admin.ics_key has the wrong form")
    return {"ics_url": _https_host(a["ics_url"], "admin.ics_url"), "ics_key": a["ics_key"]}


def check_portal(p, cfg):
    """The user portal (package ou-portal): its public URL, the Keycloak issuer and client, the apps it links to. Plain HTTP on 127.0.0.1:8090
    behind the TLS proxy; the client secret goes to a file, never into the environment file. Optional `admin` (agents that report the feature, FEATURES): the ICS
    tenant-admin API the portal's admin area calls; absent or null = no admin area."""
    _exact(p, (*PORTAL_KEYS, "admin"), PORTAL_KEYS)
    admin = check_portal_admin(p["admin"]) if p.get("admin") is not None else None
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
            "org_name": _s(p["org_name"], ORG_RE, "org_name"), **({"admin": admin} if admin else {})}


CHECKS = {"cfg.firewall": check_firewall, "cfg.gromox": check_gromox, "cfg.hosts": check_hosts, "cfg.tls": check_tls, "cfg.ldap_init": check_ldap_init, "cfg.ldap_user": check_ldap_user,
          "cfg.ldap_list": check_ldap_list, "cfg.ldap_groups": check_ldap_groups, "cfg.ldap_lock": check_ldap_lock, "cfg.ldap_delete": check_ldap_delete,
          "cfg.pg_db": check_pg_db, "cfg.podman_secret": check_podman_secret, "cfg.volume_files": check_volume_files,
          "cfg.nginx_site": check_nginx_site, "cfg.nginx_default": check_nginx_default, "cfg.portal": check_portal,
          "cfg.acme": check_acme}


MAX_REALM_JSON = 1 << 20
REALM_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,30}$")


def check_keycloak_realm(p, cfg):
    """The realm as the ICS defines it now (the same JSON as import/realm-<realm>.json) and the Keycloak bootstrap admin password; applied
    through Keycloak's admin API on 127.0.0.1 (cfghelper.keycloak_realm). Closed shape; the JSON is parsed here, never evaluated."""
    _exact(p, ("realm_json", "admin_password"))
    rj = p["realm_json"]
    if not isinstance(rj, str) or not 2 <= len(rj) <= MAX_REALM_JSON:
        raise Reject("bad_params", "realm_json: a JSON document of at most 1 MiB")
    try:
        r = json.loads(rj)
    except ValueError:
        raise Reject("bad_params", "realm_json is not JSON") from None
    if not isinstance(r, dict) or not isinstance(r.get("realm"), str) or not REALM_NAME_RE.fullmatch(r["realm"]) or r["realm"] == "master":
        raise Reject("bad_params", "realm_json: realm name missing or not allowed")
    if not isinstance(r.get("clients", []), list) or not all(isinstance(x, dict) and isinstance(x.get("clientId"), str) for x in r.get("clients", [])):
        raise Reject("bad_params", "realm_json: clients must carry a clientId")
    return {"realm_json": rj, "admin_password": _password(p["admin_password"], "admin_password")}


CHECKS["cfg.keycloak_realm"] = check_keycloak_realm

MAX_ALLOW = 64
ALLOW_PKG_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]{1,62}$")
ALLOW_REPO_RE = re.compile(r"^ou/[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*){0,2}$")   # = render_image_policy's identity rule


def check_agent_allow(p, cfg):
    """The package names and signed image repositories (ou/...) this VM's plan needs: added to the agent's allowlists, never removed."""
    _exact(p, ("packages", "image_repos"))
    out = {}
    for k, rx in (("packages", ALLOW_PKG_RE), ("image_repos", ALLOW_REPO_RE)):
        v = p[k]
        if not isinstance(v, list) or len(v) > MAX_ALLOW or not all(isinstance(x, str) and rx.fullmatch(x) for x in v):
            raise Reject("bad_params", f"{k}: up to {MAX_ALLOW} names")
        out[k] = sorted(set(v))
    return out


CHECKS["cfg.agent_allow"] = check_agent_allow


def validate_runbook_config(name, c):
    if c != {"enabled": True}:
        raise ValueError(f"{name} takes exactly {{\"enabled\": true}}")


def base_dn(domain):
    return ",".join(f"dc={x}" for x in domain.split("."))
