"""Guest configuration at execution time (docs/status/artifacts-core-results.md open item 5): the node-local state a component needs before its
unit starts, expressed as the node agent's typed `cfg.*` runbooks (agent/ou_agent/cfgspec.py).

Why at execution time and not in the plan: the plan is a pure, hashed document (plan.py) and must never contain a secret; the guests' addresses are
known only after they called back. So the plan's `comp.install` step lists the install runbooks, and `expand()` inserts the configuration runbooks
right before the component's unit is deployed, with values from:
  * deployment secrets: random per deployment, vault-encrypted in `deployment_secrets`, wiped with the deployment (`wipe()`);
  * the deployment CA: an ECDSA P-256 CA per deployment whose NameConstraints permit only the deployment's own domain, so trusting it on a client
    cannot vouch for any other name; leaf certificates are issued for exactly the names that resolve to the VM;
  * the plan's DNS records and the enrolled nodes' addresses (name resolution inside the deployment: no public DNS is touched).

Secrets travel only inside the signed, TLS-pinned agent request; `agentcall` audits cfg runbooks without their values (`redact()`)."""
import datetime
import json
import secrets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy import text

from .catalog import default_dir as catalog_dir

REALM = "ou"
LDAP_GROUPS = ("opencloudAdmin", "opencloudSpaceAdmin", "opencloudUser", "opencloudGuest", "mail-users", "org-admin")
ORG_ADMIN_GROUP = "org-admin"  # LDAP group -> realm role (role-ldap-mapper): the portal's admin area
KEYCLOAK_UID = "10130:10130"   # the non-root user of the Keycloak image (blueprints/build/oci/idfiles)
SECRET_PARAM_KEYS = ("admin_password", "bind_password", "password", "value", "key_pem", "db_password", "client_secret")
CONFIGURED = ("identity", "edge", "files", "office", "groupware", "portal")   # components whose node-local state the engine creates today
MAIL_GROUP = "mail-users"      # directory group whose members get a mailbox (cfg.ldap_init creates it; ou-admin is a member)
OPENCLOUD_UID = "10140:10140"  # the non-root user of the OpenCloud image (blueprints/build/oci/idfiles)
DOCS_UID = "10001:10001"       # the non-root user of the Office Unbound Docs image (blueprints/build/collabora/oci)
# the loopback port each web-facing component's service listens on (catalog ports with exposure local), by DNS host name
LOCAL_PORT = {"auth": ("identity", 8080), "cloud": ("files", 9200), "office": ("office", 9980), "portal": ("portal", 8090)}
PORTAL_CLIENT, WEBMAIL_CLIENT = "ou-portal", "ou-webmail"


class ConfigError(Exception):
    pass


# ---------------------------------------------------------------- secrets
def _ctx(dep_id: str, name: str) -> str:
    return f"deployment_secrets:{dep_id}:{name}"


def secret(rt, dep_id: str, name: str, make=None) -> str:
    """Get-or-create a per-deployment secret. Concurrent creators converge on the first stored value."""
    with rt.session() as db:
        row = db.execute(text("SELECT value_enc FROM deployment_secrets WHERE deployment_id = :d AND name = :n"), {"d": dep_id, "n": name}).first()
        if row is None:
            val = (make or (lambda: secrets.token_urlsafe(32)))()
            db.execute(text("INSERT INTO deployment_secrets (deployment_id, name, value_enc) VALUES (:d, :n, :v) ON CONFLICT DO NOTHING"),
                       {"d": dep_id, "n": name, "v": rt.vault.encrypt(val.encode(), _ctx(dep_id, name))})
            db.commit()
            row = db.execute(text("SELECT value_enc FROM deployment_secrets WHERE deployment_id = :d AND name = :n"), {"d": dep_id, "n": name}).first()
    return rt.vault.decrypt(row.value_enc, _ctx(dep_id, name)).decode()


def wipe(db, dep_id: str) -> int:
    return db.execute(text("DELETE FROM deployment_secrets WHERE deployment_id = :d"), {"d": dep_id}).rowcount


# ---------------------------------------------------------------- deployment CA
def _new_ca(domains: "str | list[str]", slug: str) -> str:
    domains = [domains] if isinstance(domains, str) else list(domains)
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Office Unbound"),
                      x509.NameAttribute(NameOID.COMMON_NAME, f"Office Unbound deployment CA {slug}")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.NameConstraints(permitted_subtrees=[x509.DNSName(d) for d in domains], excluded_subtrees=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    return json.dumps({"key": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(),
                       "cert": cert.public_bytes(serialization.Encoding.PEM).decode()})


def ca(rt, dep_id: str, domain: "str | list[str]", slug: str, tenant: str | None = None) -> dict:
    """The CA of one scope (the deployment, or one tenant: each tenant has its own CA, so a tenant's users who trust theirs trust no other
    tenant's names). Name constraints: the scope's domain plus any host set to a full name outside it (name settings)."""
    return json.loads(secret(rt, dep_id, sname(tenant, "deployment-ca"), lambda: _new_ca(domain, slug if tenant is None else f"{slug}/{tenant}")))


def scope_ca(ctx, tenant: str | None) -> dict:
    return ca(ctx.rt, ctx.deployment_id, ca_domains(ctx.plan, tenant), ctx.slug, tenant)


def leaf(ca_: dict, names: list[str]) -> tuple[str, str]:
    """(cert_pem, key_pem) for exactly these DNS names, signed by the deployment CA. A fresh key per configuration run (never stored)."""
    ca_key = serialization.load_pem_private_key(ca_["key"].encode(), password=None)
    ca_cert = x509.load_pem_x509_certificate(ca_["cert"].encode())
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
            .issuer_name(ca_cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=397))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False,
                                         key_agreement=True, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM).decode(),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode())


# ---------------------------------------------------------------- names and scopes
# A scope is the deployment (tenant None) or one tenant (multi-tenant: t01, t02, ...). The plan's `names` section (plan.py name settings) holds
# each scope's domain and the full name of every catalog host; plans made before it fall back to <label>.<domain>.
def tenant_of(plan: dict, vm: str) -> str | None:
    return next((v.get("tenant") for v in plan.get("vms", []) if v["name"] == vm), None)


def scope(plan: dict, tenant: str | None) -> dict:
    n = (plan.get("names") or {}).get(tenant or "")
    if n is not None:
        return n
    d = plan["input"]["domain"]
    return {"domain": f"{tenant}.{d}" if tenant else d, "hosts": {}}


def scopes(plan: dict) -> list[str | None]:
    ts = sorted({v.get("tenant") for v in plan.get("vms", []) if v.get("tenant")})
    return [None, *ts]


def fq(plan: dict, tenant: str | None, label: str) -> str:
    s = scope(plan, tenant)
    return s["hosts"].get(label) or f"{label}.{s['domain']}"


def sname(tenant: str | None, name: str) -> str:
    """Secret name in its scope: a tenant's directory, Keycloak, mail and CA secrets are never shared with another tenant."""
    return name if tenant is None else f"{tenant}.{name}"


def tls_name(tenant: str | None) -> str:
    return "deployment" if tenant is None else f"deployment-{tenant}"


def ca_domains(plan: dict, tenant: str | None) -> list[str]:
    s = scope(plan, tenant)
    dom = s["domain"]
    extra = {h for h in s["hosts"].values() if h != dom and not h.endswith("." + dom)}
    return [dom, *sorted(extra)]


def domain_of(plan: dict, vm: str) -> str:
    return scope(plan, tenant_of(plan, vm))["domain"]


def vm_of(plan: dict, component: str, tenant=None) -> str | None:
    for v in plan.get("vms", []):
        if component in (v.get("components") or []) and v.get("tenant") == tenant:
            return v["name"]
    return None


def name_scope(plan: dict, name: str) -> str | None:
    """Which scope a DNS name belongs to (its host settings, else the longest matching domain)."""
    best, blen = None, -1
    for t in scopes(plan):
        s = scope(plan, t)
        if name in s["hosts"].values():
            return t
        if (name == s["domain"] or name.endswith("." + s["domain"])) and len(s["domain"]) > blen:
            best, blen = t, len(s["domain"])
    return best


def names_by_vm(plan: dict, _domain: str | None = None, tenant: "str | None | type[...]" = ...) -> dict[str, list[str]]:
    """{vm: [fqdn, ...]} from the plan's A records (`vm:<name>` values) plus the directory's internal name on each identity VM. With `tenant`
    given: only that scope's names (the shared edge holds one certificate per scope)."""
    out: dict[str, list[str]] = {}
    for r in plan.get("dns", []):
        if r["type"] == "A" and str(r["value"]).startswith("vm:") and (tenant is ... or name_scope(plan, r["name"]) == tenant):
            out.setdefault(r["value"][3:], []).append(r["name"])
    for r in plan.get("dns", []):   # CNAMEs inside the deployment resolve locally to their target's VM
        if r["type"] == "CNAME" and (tenant is ... or name_scope(plan, r["name"]) == tenant):
            tgt = r["value"].rstrip(".")
            for vm, ns in out.items():
                if tgt in ns and r["name"] not in ns:
                    ns.append(r["name"])
    for t in scopes(plan):
        idvm = vm_of(plan, "identity", t)
        if idvm and (tenant is ... or tenant == t):
            out.setdefault(idvm, []).append(f"ldap.{scope(plan, t)['domain']}")
    return {vm: sorted(set(ns)) for vm, ns in sorted(out.items())}


def hosts_entries(ctx, names: dict[str, list[str]]) -> list[dict]:
    """A VM whose agent has not enrolled yet is left out (its names are added when a later component configures); the caller's own VM is
    always enrolled (its install step depends on that)."""
    by_ip: dict[str, list[str]] = {}
    for vm, ns in names.items():
        try:
            ip = ctx.env.agent.address(vm)
        except Exception:  # noqa: BLE001
            continue
        by_ip.setdefault(ip, []).extend(ns)
    return [{"ip": ip, "names": sorted(set(ns))} for ip, ns in sorted(by_ip.items())]


def firewall_runbook(ctx, vm: str) -> dict:
    """The plan's VM-to-VM firewall rules for `vm` (from = another VM of the deployment) as exact source addresses. Every peer is enrolled by now
    (each install step depends on all enrollments); a missing address is an error, never a wider rule."""
    names = {v["name"] for v in ctx.plan.get("vms", [])}
    rules = []
    for f in ctx.plan.get("firewall", []):
        if f["vm"] == vm and f["from"] in names:
            try:
                src = ctx.env.agent.address(f["from"])
            except Exception as e:  # noqa: BLE001
                raise ConfigError(f"the address of {f['from']} is unknown (not enrolled): {e}") from None
            rules.append({"source": src, "proto": f["proto"], "port": f["port"]})
    uniq = {(r["source"], r["proto"], r["port"]): r for r in rules}
    return {"runbook": "cfg.firewall", "params": {"rules": [uniq[k] for k in sorted(uniq)]}}


def hosted_names(plan: dict, vm: str, domain: str | None = None) -> list[str]:
    """Web names whose SERVICE runs on `vm` (cloud -> the files VM), whatever VM their A record points at (the edge): the TLS proxy on `vm` serves them."""
    comps = next((v.get("components") or [] for v in plan.get("vms", []) if v["name"] == vm), [])
    t = tenant_of(plan, vm)
    return sorted(fq(plan, t, h) for h, (c, _) in LOCAL_PORT.items() if c in comps)


def _tls(ctx, vm: str, domain: str | None = None, names: dict | None = None) -> dict:
    """The VM's own certificate ("deployment"), from its scope's CA, for exactly the names of its scope that resolve to it."""
    t = tenant_of(ctx.plan, vm)
    mine = names_by_vm(ctx.plan, tenant=t)
    want = sorted(set(mine.get(vm, [])) | set(hosted_names(ctx.plan, vm))) or [f"{vm}.{scope(ctx.plan, t)['domain']}"]
    return _tls_for(ctx, t, want, "deployment")


def _tls_for(ctx, tenant: str | None, names: list[str], name: str) -> dict:
    ca_ = scope_ca(ctx, tenant)
    cert, key = leaf(ca_, names)
    return {"runbook": "cfg.tls", "params": {"name": name, "ca_pem": ca_["cert"], "cert_pem": cert, "key_pem": key}}


# ---------------------------------------------------------------- components
def _rsa_key() -> str:
    from cryptography.hazmat.primitives.asymmetric import rsa
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()


def realm_key(rt, dep: str, tenant: str | None = None) -> str:
    """The realm's RS256 signing key, made by the ICS so the groupware can be given the matching public key up front (gromox verifies webmail
    tokens against exactly one key: docs/status/webmail-sso-results.md)."""
    return secret(rt, dep, sname(tenant, "realm-signing-key"), _rsa_key)


def realm_public_key(key_pem: str) -> str:
    k = serialization.load_pem_private_key(key_pem.encode(), password=None)
    return k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def _self_signed(key_pem: str, cn: str) -> str:
    k = serialization.load_pem_private_key(key_pem.encode(), password=None)
    now = datetime.datetime.now(datetime.timezone.utc)
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=3650)).sign(k, hashes.SHA256()))
    return c.public_bytes(serialization.Encoding.PEM).decode()


def _mapper(name: str, typ: str, config: dict) -> dict:
    return {"name": name, "protocol": "openid-connect", "protocolMapper": typ, "consentRequired": False, "config": config}


_CLAIMS = {"id.token.claim": "true", "access.token.claim": "true", "userinfo.token.claim": "true", "introspection.token.claim": "true"}


def sso_clients(portal: str, mail: str | None, portal_secret: str, webmail_secret: str | None) -> list[dict]:
    """Keycloak clients of the user portal (BFF: confidential + PKCE) and of webmail (confidential, no PKCE: grommunio-web sends none), as the
    lab proved them (portal/deploy/kc-portal-client.py, blueprints/lab/spike-groupware/kc-webmail-client.py)."""
    out = [{
        "clientId": PORTAL_CLIENT, "name": "Office Unbound user portal", "enabled": True, "protocol": "openid-connect",
        "publicClient": False, "clientAuthenticatorType": "client-secret", "secret": portal_secret,
        "standardFlowEnabled": True, "implicitFlowEnabled": False, "directAccessGrantsEnabled": False, "serviceAccountsEnabled": False,
        "fullScopeAllowed": True, "rootUrl": f"https://{portal}", "baseUrl": f"https://{portal}/",
        "redirectUris": [f"https://{portal}/auth/callback"], "webOrigins": [],
        "attributes": {"pkce.code.challenge.method": "S256", "post.logout.redirect.uris": f"https://{portal}/",
                       "display.on.consent.screen": "false", "backchannel.logout.session.required": "true"},
        "defaultClientScopes": ["web-origins", "profile", "roles", "basic", "email"],
        "optionalClientScopes": ["address", "phone", "offline_access", "microprofile-jwt"],
        "protocolMappers": [
            _mapper("roles-flat", "oidc-usermodel-realm-role-mapper", {"claim.name": "roles", "multivalued": "true", "jsonType.label": "String", **_CLAIMS}),
            # OpenCloud resolves the user by this claim: the portal calls it with the user's token
            _mapper("uuid", "oidc-usermodel-attribute-mapper", {"user.attribute": "uuid", "claim.name": "uuid", "jsonType.label": "String", **_CLAIMS})]}]
    if mail and webmail_secret:
        out.append({
            "clientId": WEBMAIL_CLIENT, "name": "Office Unbound webmail", "enabled": True, "protocol": "openid-connect",
            "publicClient": False, "clientAuthenticatorType": "client-secret", "secret": webmail_secret,
            "standardFlowEnabled": True, "implicitFlowEnabled": False, "directAccessGrantsEnabled": False, "serviceAccountsEnabled": False,
            "fullScopeAllowed": False, "rootUrl": f"https://{mail}", "baseUrl": f"https://{mail}/web/",
            "redirectUris": [f"https://{mail}/web"], "webOrigins": [],
            "attributes": {"post.logout.redirect.uris": f"https://{mail}/web/", "display.on.consent.screen": "false", "pkce.code.challenge.method": ""},
            "defaultClientScopes": ["web-origins", "profile", "basic", "email"], "optionalClientScopes": [],
            # webmail introspects the access token with its own credentials: it must be in the audience (fullScope off)
            "protocolMappers": [_mapper("aud-ou-webmail", "oidc-audience-mapper", {"included.client.audience": WEBMAIL_CLIENT, "id.token.claim": "false",
                                                                                 "access.token.claim": "true", "introspection.token.claim": "true"})]})
    return out


def realm_json(domain: str, bind_password: str, auth: str | None = None, files: str | None = None, clients: list[dict] | None = None,
               signing_key: str | None = None) -> str:
    base = ",".join(f"dc={x}" for x in domain.split("."))
    raw = (catalog_dir() / "templates" / "identity" / "realm.json").read_text()
    auth, files = auth or f"auth.{domain}", files or f"cloud.{domain}"

    def walk(v):
        if isinstance(v, dict):
            return {k: walk(x) for k, x in v.items()}
        if isinstance(v, list):
            return [walk(x) for x in v]
        if isinstance(v, str):
            return (v.replace("@BASE_DN@", base).replace("@AUTH_HOST@", auth).replace("@FILES_HOST@", files).replace("@DOMAIN@", domain)
                    .replace("@REALM@", REALM).replace("@LDAP_BIND_PASSWORD@", bind_password))
        return v
    r = walk(json.loads(raw))
    r["clients"] = [*r["clients"], *(clients or [])]
    if signing_key:
        r.setdefault("components", {})["org.keycloak.keys.KeyProvider"] = [
            {"name": "ou-rs256", "providerId": "rsa", "subComponents": {},
             "config": {"priority": ["200"], "enabled": ["true"], "active": ["true"], "algorithm": ["RS256"], "privateKey": [signing_key],
                        "certificate": [_self_signed(signing_key, REALM)]}},
            # what Keycloak generates itself when the import brings no key provider
            {"name": "hmac-generated-hs512", "providerId": "hmac-generated", "subComponents": {}, "config": {"priority": ["100"], "algorithm": ["HS512"]}},
            {"name": "aes-generated", "providerId": "aes-generated", "subComponents": {}, "config": {"priority": ["100"]}},
            {"name": "rsa-enc-generated", "providerId": "rsa-enc-generated", "subComponents": {}, "config": {"priority": ["100"], "algorithm": ["RSA-OAEP"]}}]
    return json.dumps(r, indent=2) + "\n"


def _image(ctx, vm: str, component: str) -> str:
    for c in ctx.plan.get("containers", []):
        if c["vm"] == vm and c["component"] == component:
            return f"{c['image']}@{c['digest']}"
    raise ConfigError(f"no {component} image on {vm} in the plan")


def _sec(ctx, tenant: str | None, name: str) -> str:
    return secret(ctx.rt, ctx.deployment_id, sname(tenant, name))


def identity_runbooks(ctx, vm: str) -> list[dict]:
    t = tenant_of(ctx.plan, vm)
    domain = scope(ctx.plan, t)["domain"]
    names = names_by_vm(ctx.plan)
    bind_pw = _sec(ctx, t, "ldap-bind-password")
    img = _image(ctx, vm, "identity")
    ca_pem = scope_ca(ctx, t)["cert"]
    has_mail = vm_of(ctx.plan, "groupware", t) is not None
    clients = sso_clients(fq(ctx.plan, t, "portal"), fq(ctx.plan, t, "mail") if has_mail else None, _sec(ctx, t, "portal-client-secret"),
                          _sec(ctx, t, "webmail-client-secret") if has_mail else None)
    realm = realm_json(domain, bind_pw, fq(ctx.plan, t, "auth"), fq(ctx.plan, t, "cloud"), clients, realm_key(ctx.rt, ctx.deployment_id, t))
    return [
        {"runbook": "cfg.hosts", "params": {"entries": hosts_entries(ctx, names)}},
        firewall_runbook(ctx, vm),
        _tls(ctx, vm),
        {"runbook": "cfg.ldap_init", "params": {"domain": domain, "organization": "Office Unbound", "admin_password": _sec(ctx, t, "ldap-admin-password"),
                                                "bind_password": bind_pw, "tls_name": "deployment", "groups": list(LDAP_GROUPS)}},
        {"runbook": "cfg.ldap_user", "params": {"domain": domain, "uid": "ou-admin", "given_name": "Office Unbound", "surname": "Administrator",
                                                "mail": f"ou-admin@{domain}", "password": _sec(ctx, t, "admin-password"),
                                                "groups": ["opencloudAdmin", MAIL_GROUP, ORG_ADMIN_GROUP]}},
        {"runbook": "cfg.pg_db", "params": {"role": "keycloak", "database": "keycloak", "password": _sec(ctx, t, "kc-db-password")}},
        {"runbook": "cfg.podman_secret", "params": {"name": "kc-db-password", "value": _sec(ctx, t, "kc-db-password")}},
        {"runbook": "cfg.podman_secret", "params": {"name": "kc-admin-password", "value": _sec(ctx, t, "kc-admin-password")}},
        {"runbook": "cfg.volume_files", "params": {"component": "identity", "volume": "tls", "image": img, "owner": KEYCLOAK_UID,
                                                   "files": [{"path": "ca.crt", "mode": 0o644, "content": ca_pem}]}},
        {"runbook": "cfg.volume_files", "params": {"component": "identity", "volume": "data", "image": img, "owner": KEYCLOAK_UID,
                                                   "files": [{"path": f"import/realm-{REALM}.json", "mode": 0o600, "content": realm}]}},
    ]


def _site(name: str, fqdn: str, upstream: str, upstream_name: str | None = None, tls: str = "deployment") -> dict:
    p = {"name": name, "server_names": [fqdn], "upstream": upstream, "tls_name": tls, "max_body_mb": 0 if name.split("-")[0] == "cloud" else 100}
    if upstream_name:
        p["upstream_name"] = upstream_name
    return {"runbook": "cfg.nginx_site", "params": p}


def edge_runbooks(ctx, vm: str) -> list[dict]:
    """One site per web name: to the service's loopback port when it runs on this VM, otherwise over verified HTTPS to the TLS proxy of its VM.
    A tenant's edge serves its tenant; the shared edge of a multi-tenant deployment serves every tenant, each with its own certificate from its
    own CA. Requests for any other name (a bare IP address) go to the portal when the edge serves exactly one, otherwise they are refused."""
    plan = ctx.plan
    t_vm = tenant_of(plan, vm)
    out = [{"runbook": "cfg.hosts", "params": {"entries": hosts_entries(ctx, names_by_vm(plan))}}, firewall_runbook(ctx, vm), _tls(ctx, vm)]
    serve = [t_vm] if t_vm is not None else scopes(plan)
    portals = []
    for t in serve:
        tn = "deployment"
        if t != t_vm:
            mine = names_by_vm(plan, tenant=t).get(vm, [])
            if not mine:
                continue
            tn = tls_name(t)
            out.append(_tls_for(ctx, t, mine, tn))
        for label, (comp, port) in LOCAL_PORT.items():
            svc = vm_of(plan, comp, t)
            if svc is None:
                continue
            host = fq(plan, t, label)
            site = label if t is None else f"{label}-{t}"
            if svc == vm:
                out.append(_site(site, host, f"http://127.0.0.1:{port}", tls=tn))
            else:
                try:
                    ip = ctx.env.agent.address(svc)
                except Exception as e:  # noqa: BLE001
                    raise ConfigError(f"the address of {svc} is unknown (not enrolled): {e}") from None
                out.append(_site(site, host, f"https://{ip}:443", host, tls=tn))
            if label == "portal":
                portals.append(host)
    out.append({"runbook": "cfg.nginx_default", "params": {"redirect": f"https://{portals[0]}/" if len(portals) == 1 else None, "tls_name": "deployment"}})
    return out


def _local_sites(ctx, vm: str, domain: str | None, hosts: tuple[str, ...]) -> list[dict]:
    """The same-VM TLS proxy for services the edge reaches over HTTPS; none when the edge runs on this VM (it proxies to loopback itself)."""
    t = tenant_of(ctx.plan, vm)
    if vm_of(ctx.plan, "edge", t) == vm or vm_of(ctx.plan, "edge", None) == vm:
        return []
    return [_site(h, fq(ctx.plan, t, h), f"http://127.0.0.1:{LOCAL_PORT[h][1]}") for h in hosts]


def _template(rel: str, **values) -> str:
    t = (catalog_dir() / "templates" / rel).read_text()
    for k, v in values.items():
        t = t.replace(f"@{k}@", v)
    return t


def files_runbooks(ctx, vm: str) -> list[dict]:
    t = tenant_of(ctx.plan, vm)
    domain = scope(ctx.plan, t)["domain"]
    img = _image(ctx, vm, "files")
    ca_pem = scope_ca(ctx, t)["cert"]
    base = ",".join(f"dc={x}" for x in domain.split("."))
    hosts = dict(FILES_HOST=fq(ctx.plan, t, "cloud"), IDP_HOST=fq(ctx.plan, t, "auth"), OFFICE_HOST=fq(ctx.plan, t, "office"), REALM=REALM,
                 LDAP_HOST=f"ldap.{domain}", BASE_DN=base)
    return [
        {"runbook": "cfg.hosts", "params": {"entries": hosts_entries(ctx, names_by_vm(ctx.plan))}},
        firewall_runbook(ctx, vm),
        _tls(ctx, vm),
        {"runbook": "cfg.podman_secret", "params": {"name": "ldap-bind-password", "value": _sec(ctx, t, "ldap-bind-password")}},
        {"runbook": "cfg.podman_secret", "params": {"name": "oc-admin-password", "value": _sec(ctx, t, "oc-admin-password")}},
        {"runbook": "cfg.volume_files", "params": {"component": "files", "volume": "tls", "image": img, "owner": OPENCLOUD_UID,
                                                   "files": [{"path": "ca.crt", "mode": 0o644, "content": ca_pem}]}},
        {"runbook": "cfg.volume_files", "params": {"component": "files", "volume": "config", "image": img, "owner": OPENCLOUD_UID,
                                                   "files": [{"path": "ou.env", "mode": 0o640, "content": _template("files/opencloud.env", **hosts)},
                                                             {"path": "csp.yaml", "mode": 0o644, "content": _template("files/csp.yaml", **hosts)}]}},
        {"runbook": "cfg.volume_files", "params": {"component": "files", "volume": "data", "image": img, "owner": OPENCLOUD_UID,
                                                   "files": [{"path": "ou-volume", "mode": 0o644, "content": "Office Unbound files data volume\n"}]}},
        *_local_sites(ctx, vm, domain, ("cloud",)),
    ]


def office_runbooks(ctx, vm: str) -> list[dict]:
    t = tenant_of(ctx.plan, vm)
    img = _image(ctx, vm, "office")
    ca_pem = scope_ca(ctx, t)["cert"]
    return [
        {"runbook": "cfg.volume_files", "params": {"component": "office", "volume": "tls", "image": img, "owner": DOCS_UID,
                                                   "files": [{"path": "ca.crt", "mode": 0o644, "content": ca_pem}]}},
        {"runbook": "cfg.volume_files", "params": {"component": "office", "volume": "work", "image": img, "owner": DOCS_UID,
                                                   "files": [{"path": "ou-volume", "mode": 0o644, "content": "Office Unbound Docs work volume\n"}]}},
        *_local_sites(ctx, vm, None, ("office",)),
    ]


def groupware_runbooks(ctx, vm: str) -> list[dict]:
    """The groupware node: gromox (mail store, IMAP, EWS/MAPI, delivery) + Postfix + MariaDB + grommunio web/ActiveSync/DAV behind nginx, users
    authenticated against the scope's directory (read-only bind), mailboxes for the administrator, webmail signing in through Keycloak (SSO;
    the realm key the ICS made is the one gromox verifies). Lab proof: docs/status/groupware-deploy-results.md, webmail-sso-results.md."""
    t = tenant_of(ctx.plan, vm)
    domain = scope(ctx.plan, t)["domain"]
    mail = fq(ctx.plan, t, "mail")
    sso = {"auth_url": f"https://{fq(ctx.plan, t, 'auth')}/", "realm": REALM, "client_id": WEBMAIL_CLIENT,
           "client_secret": _sec(ctx, t, "webmail-client-secret"), "redirect_url": f"https://{mail}/web",
           "bearer_pubkey": realm_public_key(realm_key(ctx.rt, ctx.deployment_id, t))}
    return [
        {"runbook": "cfg.hosts", "params": {"entries": hosts_entries(ctx, names_by_vm(ctx.plan))}},
        firewall_runbook(ctx, vm),
        _tls(ctx, vm),
        {"runbook": "cfg.gromox", "params": {"domain": domain, "hostname": mail, "tls_name": "deployment",
                                             "db_password": _sec(ctx, t, "gw-db-password"), "ldap_host": f"ldap.{domain}",
                                             "bind_password": _sec(ctx, t, "ldap-bind-password"), "group": MAIL_GROUP,
                                             "mailboxes": [f"ou-admin@{domain}"], "sso": sso}},
    ]


def portal_runbooks(ctx, vm: str) -> list[dict]:
    """The user portal of the VM's scope: one Keycloak sign-in for mail, calendar, contacts, files and documents (portal/)."""
    t = tenant_of(ctx.plan, vm)
    domain = scope(ctx.plan, t)["domain"]
    has_mail = vm_of(ctx.plan, "groupware", t) is not None
    has_files = vm_of(ctx.plan, "files", t) is not None
    mail = fq(ctx.plan, t, "mail")
    return [
        {"runbook": "cfg.portal", "params": {
            "base_url": f"https://{fq(ctx.plan, t, 'portal')}", "issuer": f"https://{fq(ctx.plan, t, 'auth')}/realms/{REALM}",
            "client_id": PORTAL_CLIENT, "client_secret": _sec(ctx, t, "portal-client-secret"),
            "files_url": f"https://{fq(ctx.plan, t, 'cloud')}" if has_files else "",
            "mail_web_url": f"https://{mail}/web/" if has_mail else "", "mail_host": mail if has_mail else "", "mail_domain": domain,
            "org_name": domain}},
        *_local_sites(ctx, vm, domain, ("portal",)),
    ]


BUILDERS = {"identity": identity_runbooks, "edge": edge_runbooks, "files": files_runbooks, "office": office_runbooks, "groupware": groupware_runbooks,
            "portal": portal_runbooks}


def expand(ctx, vm: str, component: str, runbooks: list[dict]) -> list[dict]:
    """The plan's install runbooks with the component's configuration inserted: before its first unit deployment (the unit reads the state), or
    after the packages when it deploys no unit (edge = nginx)."""
    b = BUILDERS.get(component)
    if b is None:
        return list(runbooks)
    cfg = b(ctx, vm)
    i = next((n for n, r in enumerate(runbooks) if r["runbook"] == "podman.deploy_unit"), len(runbooks))
    return list(runbooks[:i]) + cfg + list(runbooks[i:])


def redact(runbook: str, params: dict) -> dict:
    """What the audit log may record of a cfg runbook: no secret value, no file content."""
    if not runbook.startswith("cfg."):
        return params
    out = {}
    for k, v in params.items():
        if k in SECRET_PARAM_KEYS:
            out[k] = "[redacted]"
        elif k == "files":
            out[k] = [{"path": f.get("path"), "mode": f.get("mode"), "bytes": len(str(f.get("content", "")).encode())} for f in v]
        elif k == "ca_pem" or k == "cert_pem":
            out[k] = "[certificate]"
        elif isinstance(v, dict):   # nested settings (cfg.gromox sso): same rules
            out[k] = redact(runbook, v)
        else:
            out[k] = v
    return out
