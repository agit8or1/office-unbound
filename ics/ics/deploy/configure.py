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
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy import text

from . import brand
from .catalog import default_dir as catalog_dir

REALM = "ou"
LDAP_GROUPS = ("opencloudAdmin", "opencloudSpaceAdmin", "opencloudUser", "opencloudGuest", "mail-users", "org-admin")
ORG_ADMIN_GROUP = "org-admin"  # LDAP group -> realm role (role-ldap-mapper): the portal's admin area
KEYCLOAK_UID = "10130:10130"   # the non-root user of the Keycloak image (blueprints/build/oci/idfiles)
SECRET_PARAM_KEYS = ("admin_password", "bind_password", "writer_password", "password", "value", "key_pem", "db_password", "client_secret", "ics_key")
CONFIGURED = ("identity", "edge", "files", "office", "groupware", "portal", "chat")   # components whose node-local state the engine creates today
MAIL_GROUP = "mail-users"      # directory group whose members get a mailbox (cfg.ldap_init creates it; ou-admin is a member)
OPENCLOUD_UID = "10140:10140"  # the non-root user of the OpenCloud image (blueprints/build/oci/idfiles)
DOCS_UID = "10001:10001"       # the non-root user of the Office Unbound Docs image (blueprints/build/collabora/oci)
# the loopback port each web-facing component's service listens on (catalog ports with exposure local), by DNS host name
LOCAL_PORT = {"auth": ("identity", 8080), "cloud": ("files", 9200), "office": ("office", 9980), "portal": ("portal", 8090),
              # team chat: one VM-local web front (Element Web's nginx) serves Element and routes the Matrix and MAS names (templates/chat/front.conf)
              "chat": ("chat", 8070), "matrix": ("chat", 8070), "mas": ("chat", 8070)}
PORTAL_CLIENT, WEBMAIL_CLIENT, MATRIX_CLIENT = "ou-portal", "ou-webmail", "ou-matrix"
SYNAPSE_UID, MAS_UID, ELEMENT_UID = "10020:10020", "10120:10120", "10030:10030"   # non-root users of the chat images (blueprints/build/collab, blueprints/build/oci/mas)
# web names whose service has its own TLS front on another VM (the groupware's nginx: webmail, ActiveSync, EWS, MAPI, DAV, Autodiscover): the
# gateway serves them with ITS certificate (the public one once issued) and proxies over verified HTTPS, like any other web name
EDGE_HTTPS = {"mail": "groupware", "autodiscover": "groupware"}


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
    return name if tenant is None else f"{tenant}-{name}"   # deployment_secrets.name CHECK: ^[a-z][a-z0-9-]{1,40}$


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


def edge_served_names(plan: dict, vm: str, tenant: str | None) -> list[str]:
    """Every name of scope `tenant` that the edge on `vm` serves (exactly the sites edge_runbooks makes): the web names of the scope's services
    (whatever VM their A record points at) plus the EDGE_HTTPS names whose groupware runs on another VM. The gateway's certificate for that
    scope must cover all of them, also before (or without) a public certificate. Empty when `vm` runs no edge."""
    comps = next((v.get("components") or [] for v in plan.get("vms", []) if v["name"] == vm), [])
    if "edge" not in comps:
        return []
    out = {fq(plan, tenant, label) for label, (comp, _) in LOCAL_PORT.items() if vm_of(plan, comp, tenant)}
    for label, comp in EDGE_HTTPS.items():
        svc = vm_of(plan, comp, tenant)
        if svc is not None and svc != vm:
            out.add(fq(plan, tenant, label))
    return sorted(out)


def _tls(ctx, vm: str, domain: str | None = None, names: dict | None = None) -> dict:
    """The VM's own certificate ("deployment"), from its scope's CA, for exactly the names of its scope that resolve to it or that its edge serves."""
    t = tenant_of(ctx.plan, vm)
    mine = names_by_vm(ctx.plan, tenant=t)
    want = sorted(set(mine.get(vm, [])) | set(hosted_names(ctx.plan, vm)) | set(edge_served_names(ctx.plan, vm, t))) \
        or [f"{vm}.{scope(ctx.plan, t)['domain']}"]
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


def _proof_key() -> str:
    """An RSA key in the format Collabora's own tooling makes (`ssh-keygen -t rsa -m PEM`: PKCS#1 "RSA PRIVATE KEY"); coolwsd loads it with
    Poco's RSAKey (wsd/ProofKey.cpp) and signs every WOPI request with it (X-WOPI-Proof/X-WOPI-TimeStamp)."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()).decode()


def office_proof_key(rt, dep: str, tenant: str | None = None) -> str:
    """The WOPI proof key of the scope's office (2026-11-21: without one coolwsd sent no proof headers and OpenCloud's collaboration service
    refused every WOPI call, "ProofKeys verification failed: Invalid timestamp", documents blank). Made once per deployment (per tenant), never
    shared between deployments and never baked into the image; OpenCloud learns the public half from the discovery XML."""
    return secret(rt, dep, sname(tenant, "office-proof-key"), _proof_key)


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


def matrix_client(mas: str, secret_: str, provider_id: str) -> dict:
    """Keycloak client of the chat sign-in service (MAS as upstream OIDC client: confidential, PKCE S256), with Keycloak's back-channel logout to
    MAS so a Keycloak logout (and the ICS disabling a person) ends their Matrix sessions (docs/status/collaboration-lab-results.md, C05)."""
    return {
        "clientId": MATRIX_CLIENT, "name": "Office Unbound chat", "enabled": True, "protocol": "openid-connect",
        "publicClient": False, "clientAuthenticatorType": "client-secret", "secret": secret_,
        "standardFlowEnabled": True, "implicitFlowEnabled": False, "directAccessGrantsEnabled": False, "serviceAccountsEnabled": False,
        "fullScopeAllowed": False, "rootUrl": f"https://{mas}", "baseUrl": f"https://{mas}/",
        "redirectUris": [f"https://{mas}/upstream/callback/{provider_id}"], "webOrigins": [],
        "attributes": {"pkce.code.challenge.method": "S256", "display.on.consent.screen": "false", "post.logout.redirect.uris": f"https://{mas}/",
                       "backchannel.logout.url": f"https://{mas}/upstream/backchannel-logout/{provider_id}",
                       "backchannel.logout.session.required": "true", "backchannel.logout.revoke.offline.tokens": "true"},
        "defaultClientScopes": ["web-origins", "profile", "basic", "email"], "optionalClientScopes": []}


# What people may change about themselves (portal account page, Keycloak account API): user-profile attribute -> LDAP attribute. The directory
# lets only the sign-in service's own account svc-idp write exactly these (agent cfghelper.LDAP_SELF_ATTRS, plus cn kept equal to the full
# name); username and e-mail (= the mailbox) stay administrator-only.
SELF_PROFILE = {"firstName": "givenName", "lastName": "sn", "displayName": "displayName", "phone": "telephoneNumber", "mobile": "mobile"}
_NAME_VALIDATORS = {"length": {"max": 100}, "person-name-prohibited-characters": {}}


def _profile_attr(name, display, ldap_required=False, validators=None, user_edit=True):
    a = {"name": name, "displayName": display, "permissions": {"view": ["admin", "user"], "edit": ["admin", "user"] if user_edit else ["admin"]},
         "validations": validators or {}, "multivalued": False}
    if ldap_required:
        a["required"] = {"roles": ["admin", "user"]}
    return a


def self_service_profile(r: dict, base: str, writer_password: str) -> None:
    """Keycloak writes to the directory as svc-idp (password changes through the LDAP password-modify operation, so the directory hashes and
    applies its password policy) and offers the declared profile: unmanaged attributes are off, nothing else can be set by a user."""
    comps = r["components"]
    ldap = comps["org.keycloak.storage.UserStorageProvider"][0]
    cfg = ldap["config"]
    cfg.update(editMode=["WRITABLE"], bindDn=[f"cn=svc-idp,ou=system,{base}"], bindCredential=[writer_password], usePasswordModifyExtendedOp=["true"],
               validatePasswordPolicy=["false"], trustEmail=cfg.get("trustEmail", ["true"]))
    mappers = ldap["subComponents"]["org.keycloak.storage.ldap.mappers.LDAPStorageMapper"]
    for m in mappers:
        if m["name"] in ("first name", "last name"):
            m["config"]["read.only"] = ["false"]
    for model, attr in (("displayName", "displayName"), ("phone", "telephoneNumber"), ("mobile", "mobile")):
        mappers.append({"name": model, "providerId": "user-attribute-ldap-mapper", "subComponents": {},
                        "config": {"ldap.attribute": [attr], "user.model.attribute": [model], "read.only": ["false"], "always.read.value.from.ldap": ["true"],
                                   "is.mandatory.in.ldap": ["false"], "is.binary.attribute": ["false"]}})
    mappers.append({"name": "full name to cn", "providerId": "full-name-ldap-mapper", "subComponents": {},
                    "config": {"ldap.full.name.attribute": ["cn"], "read.only": ["false"], "write.only": ["true"]}})
    phone = {"length": {"max": 32}, "pattern": {"pattern": "^[+0-9 ()./-]*$", "error-message": "Use digits, spaces and + ( ) - . / only."}}
    prof = {"attributes": [
        _profile_attr("username", "${username}", True, {"length": {"min": 1, "max": 255}}, user_edit=False),
        _profile_attr("email", "${email}", False, {"email": {}, "length": {"max": 255}}, user_edit=False),
        _profile_attr("firstName", "${firstName}", True, _NAME_VALIDATORS),
        _profile_attr("lastName", "${lastName}", True, _NAME_VALIDATORS),
        _profile_attr("displayName", "Display name", False, {"length": {"max": 128}}),
        _profile_attr("phone", "Phone", False, phone),
        _profile_attr("mobile", "Mobile", False, phone)], "groups": []}   # no unmanagedAttributePolicy: unmanaged attributes stay disabled
    comps["org.keycloak.userprofile.UserProfileProvider"] = [{"providerId": "declarative-user-profile", "subComponents": {},
                                                              "config": {"kc.user.profile.config": [json.dumps(prof)]}}]


def realm_json(domain: str, bind_password: str, auth: str | None = None, files: str | None = None, clients: list[dict] | None = None,
               signing_key: str | None = None, frame_ancestors: list[str] | None = None, writer_password: str | None = None) -> str:
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
    if writer_password:
        self_service_profile(r, base, writer_password)
    if frame_ancestors:
        # Keycloak's default allows framing by itself only; a CSP frame-ancestors list replaces X-Frame-Options (empty = header not sent)
        r["browserSecurityHeaders"] = {**r.get("browserSecurityHeaders", {}), "xFrameOptions": "",
                                       "contentSecurityPolicy": "frame-src 'self'; frame-ancestors 'self' " + " ".join(frame_ancestors) + "; object-src 'none';"}
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


def portal_url(plan: dict, tenant: str | None) -> str | None:
    """https://<portal>/ of the scope, the target of every app's "Dashboard" link and the origin of the live organisation branding
    (brand.py); None when the scope has no portal."""
    return f"https://{fq(plan, tenant, 'portal')}/" if vm_of(plan, "portal", tenant) else None


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
    frame = None
    if vm_of(ctx.plan, "chat", t) is not None:
        clients.append(matrix_client(fq(ctx.plan, t, "mas"), _sec(ctx, t, "matrix-client-secret"), mas_provider_id(ctx.rt, ctx.deployment_id, t)))
        # chat signs in inside the portal's chat bubble: the sign-in pages may be framed by the chat and portal names only
        frame = [f"https://{fq(ctx.plan, t, 'chat')}", f"https://{fq(ctx.plan, t, 'mas')}"] + ([portal_url(ctx.plan, t).rstrip("/")] if portal_url(ctx.plan, t) else [])
    # the identity VM's agent creates the sign-in service's writer account (feature "writer"); an older agent keeps the directory read-only
    writer_pw = _sec(ctx, t, "ldap-writer-password") if "writer" in agent_features(ctx, vm, "cfg.ldap_init") else None
    realm = realm_json(domain, bind_pw, fq(ctx.plan, t, "auth"), fq(ctx.plan, t, "cloud"), clients, realm_key(ctx.rt, ctx.deployment_id, t),
                       frame_ancestors=frame, writer_password=writer_pw)
    return [
        {"runbook": "cfg.hosts", "params": {"entries": hosts_entries(ctx, names)}},
        firewall_runbook(ctx, vm),
        _tls(ctx, vm),
        {"runbook": "cfg.ldap_init", "params": {"domain": domain, "organization": "Office Unbound", "admin_password": _sec(ctx, t, "ldap-admin-password"),
                                                "bind_password": bind_pw, "tls_name": "deployment", "groups": list(LDAP_GROUPS),
                                                **({"writer_password": writer_pw} if writer_pw else {})}},
        # ou-admin is the only OpenCloud Admin (hidden built-in account, recovery through the Graph API); the web UI has no admin-settings app
        {"runbook": "cfg.ldap_user", "params": {"domain": domain, "uid": "ou-admin", "given_name": "Office Unbound", "surname": "Administrator",
                                                "mail": f"ou-admin@{domain}", "password": _sec(ctx, t, "admin-password"),
                                                "groups": ["opencloudAdmin", MAIL_GROUP, ORG_ADMIN_GROUP]}},
        {"runbook": "cfg.pg_db", "params": {"role": "keycloak", "database": "keycloak", "password": _sec(ctx, t, "kc-db-password")}},
        {"runbook": "cfg.podman_secret", "params": {"name": "kc-db-password", "value": _sec(ctx, t, "kc-db-password")}},
        {"runbook": "cfg.podman_secret", "params": {"name": "kc-admin-password", "value": _sec(ctx, t, "kc-admin-password")}},
        {"runbook": "cfg.volume_files", "params": {"component": "identity", "volume": "tls", "image": img, "owner": KEYCLOAK_UID,
                                                   "files": [{"path": "ca.crt", "mode": 0o644, "content": ca_pem},
                                                             {"path": "trust.crt", "mode": 0o644, "content": office_trust(ca_pem)}]}},
        {"runbook": "cfg.volume_files", "params": {"component": "identity", "volume": "data", "image": img, "owner": KEYCLOAK_UID,
                                                   "files": [{"path": f"import/realm-{REALM}.json", "mode": 0o600, "content": realm}]}},
        # the Office Unbound sign-in and account theme (realm loginTheme/accountTheme "ou"), mounted read-only at /opt/keycloak/themes
        {"runbook": "cfg.volume_files", "params": {"component": "identity", "volume": "themes", "image": img, "owner": KEYCLOAK_UID,
                                                   "files": brand.keycloak_theme(portal_url(ctx.plan, t))}},
    ] + ([{"runbook": "cfg.keycloak_realm", "after_unit": True, "params": {"realm_json": realm, "admin_password": _sec(ctx, t, "kc-admin-password")}}]
         # Keycloak imports the realm file only when the realm is new; this brings an existing realm (in-place upgrade) to the same definition
         if agent_has(ctx, vm, "cfg.keycloak_realm") else [])


# the app behind each web name whose OWN administration surfaces its site refuses (agent cfghelper.LOCKDOWN): administration happens in the
# Office Unbound console and portal (owner 2026-11-21); the portal has no separate admin surface of its own (its admin area IS ours)
LOCKDOWN = {"auth": "keycloak", "cloud": "opencloud", "office": "collabora", "mail": "groupware", "autodiscover": "groupware"}


def _site(name: str, fqdn: str, upstream: str, upstream_name: str | None = None, tls: str = "deployment", upstream_ca: str | None = None,
          root_redirect: str | None = None) -> dict:
    label = name.split("-")[0]
    p = {"name": name, "server_names": [fqdn], "upstream": upstream, "tls_name": tls, "max_body_mb": 0 if label == "cloud" else 100}
    if label in LOCKDOWN:
        p["lockdown"] = LOCKDOWN[label]
    if upstream_name:
        p["upstream_name"] = upstream_name
    if upstream_ca:
        p["upstream_ca"] = upstream_ca
    if root_redirect:
        p["root_redirect"] = root_redirect
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
    from .. import gateway
    public = gateway.public_for(ctx.rt, ctx.slug) if ctx.rt is not None else None   # publicly trusted certificate on this gateway (cfg.acme)
    for t in serve:
        tn = "deployment"
        if t != t_vm:
            mine = sorted(set(names_by_vm(plan, tenant=t).get(vm, [])) | set(edge_served_names(plan, vm, t)))
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
            # the sign-in host's front page is Keycloak's admin redirect: send people to their portal instead
            rr = f"https://{fq(plan, t, 'portal')}/" if label == "auth" and vm_of(plan, "portal", t) else None
            stls, sca = (public["cert_name"], tn) if (public and t == t_vm and host in public.get("names", [])) else (tn, None)
            if svc == vm:
                out.append(_site(site, host, f"http://127.0.0.1:{port}", tls=stls, upstream_ca=sca, root_redirect=rr))
            else:
                try:
                    ip = ctx.env.agent.address(svc)
                except Exception as e:  # noqa: BLE001
                    raise ConfigError(f"the address of {svc} is unknown (not enrolled): {e}") from None
                out.append(_site(site, host, f"https://{ip}:443", host, tls=stls, upstream_ca=sca, root_redirect=rr))
            if label == "portal":
                portals.append(host)
        for label, comp in EDGE_HTTPS.items():
            svc = vm_of(plan, comp, t)
            if svc is None or svc == vm:
                continue   # on the gateway's own VM the groupware's nginx serves the name itself
            host = fq(plan, t, label)
            site = label if t is None else f"{label}-{t}"
            stls, sca = (public["cert_name"], tn) if (public and t == t_vm and host in public.get("names", [])) else (tn, None)
            try:
                ip = ctx.env.agent.address(svc)
            except Exception as e:  # noqa: BLE001
                raise ConfigError(f"the address of {svc} is unknown (not enrolled): {e}") from None
            out.append(_site(site, host, f"https://{ip}:443", host, tls=stls, upstream_ca=sca))
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
    portal = portal_url(ctx.plan, t)
    hosts = dict(FILES_HOST=fq(ctx.plan, t, "cloud"), IDP_HOST=fq(ctx.plan, t, "auth"), OFFICE_HOST=fq(ctx.plan, t, "office"), REALM=REALM,
                 LDAP_HOST=f"ldap.{domain}", BASE_DN=base, PORTAL_ORIGIN=(portal or f"https://{fq(ctx.plan, t, 'cloud')}/"))
    return [
        {"runbook": "cfg.hosts", "params": {"entries": hosts_entries(ctx, names_by_vm(ctx.plan))}},
        firewall_runbook(ctx, vm),
        _tls(ctx, vm),
        {"runbook": "cfg.podman_secret", "params": {"name": "ldap-bind-password", "value": _sec(ctx, t, "ldap-bind-password")}},
        {"runbook": "cfg.podman_secret", "params": {"name": "oc-admin-password", "value": _sec(ctx, t, "oc-admin-password")}},
        {"runbook": "cfg.volume_files", "params": {"component": "files", "volume": "tls", "image": img, "owner": OPENCLOUD_UID,
                                                   "files": [{"path": "ca.crt", "mode": 0o644, "content": ca_pem},
                                                             {"path": "trust.crt", "mode": 0o644, "content": office_trust(ca_pem)}]}},
        {"runbook": "cfg.volume_files", "params": {"component": "files", "volume": "config", "image": img, "owner": OPENCLOUD_UID,
                                                   "files": [{"path": "ou.env", "mode": 0o640, "content": _template("files/opencloud.env", **hosts)},
                                                             {"path": "csp.yaml", "mode": 0o644, "content": _template("files/csp.yaml", **hosts)},
                                                             *brand.opencloud_files(portal)]}},
        {"runbook": "cfg.volume_files", "params": {"component": "files", "volume": "data", "image": img, "owner": OPENCLOUD_UID,
                                                   "files": [{"path": "ou-volume", "mode": 0o644, "content": "Office Unbound files data volume\n"}]}},
        *_local_sites(ctx, vm, domain, ("cloud",)),
    ]


# Let's Encrypt's roots (the ICS host's own trust store, Ubuntu ca-certificates): the names behind the gateway serve the public certificate once
# gateway.certificates.issue ran, so a service that fetches from another name of the deployment must trust both (same files as gateway.LE_ROOTS)
PUBLIC_ROOTS = ("/etc/ssl/certs/ISRG_Root_X1.pem", "/etc/ssl/certs/ISRG_Root_X2.pem")


def office_trust(ca_pem: str, roots: tuple[str, ...] = PUBLIC_ROOTS) -> str:
    """trust.crt of the containers that call other names of the deployment (Collabora WOPI fetch, OpenCloud's collaboration service and OIDC,
    Keycloak): the deployment CA plus the public roots, so those calls work before AND after gateway.certificates.issue switches the names to the
    public certificate (2026-11-21: OpenCloud trusted only ca.crt via SSL_CERT_FILE, its WOPI service answered 500, documents stayed blank)."""
    out = ca_pem.rstrip("\n") + "\n"
    for r in roots:
        with open(r) as f:
            pem = f.read()
        if "-----BEGIN CERTIFICATE-----" not in pem:
            raise ValueError(f"{r} is not a PEM certificate")
        out += pem.rstrip("\n") + "\n"
    return out


def office_runbooks(ctx, vm: str) -> list[dict]:
    t = tenant_of(ctx.plan, vm)
    img = _image(ctx, vm, "office")
    ca_pem = scope_ca(ctx, t)["cert"]
    # proof_key: the image links /etc/coolwsd/proof_key to /opt/ou-tls/proof_key (the rootfs is read-only); written before the unit's first start
    return [
        {"runbook": "cfg.volume_files", "params": {"component": "office", "volume": "tls", "image": img, "owner": DOCS_UID,
                                                   "files": [{"path": "ca.crt", "mode": 0o644, "content": ca_pem},
                                                             {"path": "trust.crt", "mode": 0o644, "content": office_trust(ca_pem)},
                                                             {"path": "proof_key", "mode": 0o600,
                                                              "content": office_proof_key(ctx.rt, ctx.deployment_id, t)}]}},
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
    extra = []
    if t is None and ctx.rt is not None:   # accounts an administrator set (deploy/accounts.py) get their mailbox too
        from . import accounts
        extra = [f"{u}@{domain}" for u in accounts.accounts_for(ctx.rt, ctx.slug) if u != "ou-admin"]
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
                                             "mailboxes": [f"ou-admin@{domain}", *extra], "sso": sso,
                                             "brand": brand.grommunio_brand(portal_url(ctx.plan, t), fonts=brand.GW_FONTS_FEATURE in
                                                                            agent_features(ctx, vm, "cfg.gromox"))}},
    ]


PORTAL_ICS_KEY = "portal-ics-key"   # deployment secret: the portal's credential for the ICS tenant-admin API (tenant_admin/deployment.py)


def portal_key(rt, dep_id: str) -> str:
    """`tdk_<deployment id>.<secret>`: names the deployment (the ICS looks the secret up by it) and proves the caller is its portal. The secret
    is a per-deployment secret like the portal's client secret (vault-encrypted, wiped with the deployment)."""
    return f"tdk_{uuid.UUID(str(dep_id)).hex}.{secret(rt, dep_id, PORTAL_ICS_KEY)}"


def _caps(ctx, vm: str) -> dict:
    if ctx.rt is None:
        return {}
    with ctx.rt.session() as db:
        return db.execute(text("SELECT n.capabilities FROM deployment_resources r JOIN nodes n ON n.id::text = r.provider_ref->>'agent_node_id' "
                               "WHERE r.deployment_id = :d AND r.kind = 'vm' AND r.logical_name = :n AND r.state <> 'removed'"),
                          {"d": ctx.deployment_id, "n": vm}).scalar() or {}


def agent_has(ctx, vm: str, runbook: str) -> bool:
    """Whether the VM's agent offers `runbook` (its capabilities as last reported: at enrollment, refreshed after an in-place agent upgrade)."""
    return runbook in _caps(ctx, vm)


def agent_features(ctx, vm: str, runbook: str) -> list[str]:
    """What the VM's agent reported for `runbook` at enrollment (ou_agent cfgspec.FEATURES). An older agent reports none: the closed schema of
    its runbook would refuse a parameter it does not know, so the ICS never sends one."""
    f = (_caps(ctx, vm).get(runbook) or {}).get("features") or []
    return [x for x in f if isinstance(x, str)]


def portal_agent_features(ctx, vm: str) -> list[str]:
    """cfg.portal features of the portal VM's agent (agent_features)."""
    return agent_features(ctx, vm, "cfg.portal")


def portal_admin(ctx, vm: str) -> dict | None:
    """The portal's admin area wiring: the ICS URL deployed VMs use (Settings -> Network & domains: the console's public name) and the
    deployment's portal key. The ICS trusts the realm's tokens through the key it made itself (realm_key), so nothing is configured by hand.
    Only for the deployment's own scope (the directory people API, deploy/accounts.py, serves that scope only); None = no admin area."""
    if ctx.rt is None or tenant_of(ctx.plan, vm) is not None or vm_of(ctx.plan, "identity", None) is None:
        return None
    from .. import netsettings
    with ctx.rt.session() as db:
        url = netsettings.ics_url_for_vms(db)
    if not url or "admin" not in portal_agent_features(ctx, vm):
        return None
    return {"ics_url": url, "ics_key": portal_key(ctx.rt, ctx.deployment_id)}


def portal_runbooks(ctx, vm: str) -> list[dict]:
    """The user portal of the VM's scope: one Keycloak sign-in for mail, calendar, contacts, files and documents (portal/), and for the
    deployment's administrators (realm role org-admin) the admin area when the ICS URL is set and the agent supports it (portal_admin)."""
    t = tenant_of(ctx.plan, vm)
    domain = scope(ctx.plan, t)["domain"]
    has_mail = vm_of(ctx.plan, "groupware", t) is not None
    has_files = vm_of(ctx.plan, "files", t) is not None
    mail = fq(ctx.plan, t, "mail")
    params = {
        "base_url": f"https://{fq(ctx.plan, t, 'portal')}", "issuer": f"https://{fq(ctx.plan, t, 'auth')}/realms/{REALM}",
        "client_id": PORTAL_CLIENT, "client_secret": _sec(ctx, t, "portal-client-secret"),
        "files_url": f"https://{fq(ctx.plan, t, 'cloud')}" if has_files else "",
        "mail_web_url": f"https://{mail}/web/" if has_mail else "", "mail_host": mail if has_mail else "", "mail_domain": domain,
        "org_name": domain}
    admin = portal_admin(ctx, vm)
    if admin:
        params["admin"] = admin
    return [
        {"runbook": "cfg.portal", "params": params},
        *_local_sites(ctx, vm, domain, ("portal",)),
    ]


_ULID = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"   # Crockford base32 (MAS ids are ULIDs)


def _ulid() -> str:
    import time
    n = (int(time.time() * 1000) << 80) | secrets.randbits(80)
    return "".join(_ULID[(n >> (5 * i)) & 31] for i in reversed(range(26)))


def mas_provider_id(rt, dep: str, tenant: str | None = None) -> str:
    """The id of the Keycloak provider in MAS (a ULID, part of the callback and back-channel logout URLs): made once per deployment/scope."""
    return secret(rt, dep, sname(tenant, "mas-provider-id"), _ulid)


def _synapse_signing_key() -> str:
    """Synapse's server signing key file: `ed25519 <key id> <unpadded base64 seed>` (what `generate_signing_key` writes)."""
    import base64
    from cryptography.hazmat.primitives.asymmetric import ed25519
    seed = ed25519.Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    return f"ed25519 a_{secrets.token_hex(2)} {base64.b64encode(seed).decode().rstrip('=')}\n"


def _hex32() -> str:
    return secrets.token_hex(32)


def chat_runbooks(ctx, vm: str) -> list[dict]:
    """Team chat of the VM's scope: Synapse (own PostgreSQL), MAS signing people in through the scope's Keycloak only, and Element Web, behind
    this VM's TLS proxy. Every secret (database passwords, MAS-Synapse shared secret, MAS encryption and signing keys, Synapse signing key) is
    made by the ICS and kept in its vault, so a rebuild with the same deployment keeps the server identity. Lab proof of the topology:
    docs/status/collaboration-lab-results.md (C01-C05); configuration: templates/chat."""
    t = tenant_of(ctx.plan, vm)
    domain = scope(ctx.plan, t)["domain"]
    ca_pem = scope_ca(ctx, t)["cert"]
    matrix, chat, mas = fq(ctx.plan, t, "matrix"), fq(ctx.plan, t, "chat"), fq(ctx.plan, t, "mas")
    server_name = matrix   # no .well-known delegation on the customer's apex (often their website): Matrix ids are @user:matrix.<domain>
    mas_secret, syn_pw, mas_pw = _sec(ctx, t, "mas-synapse-secret"), _sec(ctx, t, "synapse-db-password"), _sec(ctx, t, "mas-db-password")
    mas_key = secret(ctx.rt, ctx.deployment_id, sname(t, "mas-signing-key"), _rsa_key)
    hs = _template("chat/homeserver.yaml", SERVER_NAME=server_name, MATRIX_HOST=matrix, DB_PASSWORD=syn_pw, MAS_SECRET=mas_secret,
                   MACAROON=_sec(ctx, t, "synapse-macaroon"), FORM_SECRET=_sec(ctx, t, "synapse-form-secret"))
    masc = _template("chat/mas.yaml", MAS_HOST=mas, DB_PASSWORD=mas_pw, SERVER_NAME=server_name, MAS_SECRET=mas_secret,
                     ENCRYPTION=secret(ctx.rt, ctx.deployment_id, sname(t, "mas-encryption"), _hex32), KID="ou-rsa",
                     SIGNING_KEY="\n".join("        " + ln for ln in mas_key.strip().splitlines()), DOMAIN=domain,
                     PROVIDER_ID=mas_provider_id(ctx.rt, ctx.deployment_id, t), AUTH_HOST=fq(ctx.plan, t, "auth"), REALM=REALM,
                     CLIENT_ID=MATRIX_CLIENT, CLIENT_SECRET=_sec(ctx, t, "matrix-client-secret"))
    portal = portal_url(ctx.plan, t)
    hosts = dict(CHAT_HOST=chat, MATRIX_HOST=matrix, MAS_HOST=mas, SERVER_NAME=server_name,
                 FRAME_ANCESTORS=f"https://{chat}" + (f" {portal.rstrip('/')}" if portal else ""))
    img = _image(ctx, vm, "chat")
    return [
        {"runbook": "cfg.hosts", "params": {"entries": hosts_entries(ctx, names_by_vm(ctx.plan))}},
        firewall_runbook(ctx, vm),
        _tls(ctx, vm),
        {"runbook": "cfg.pg_db", "params": {"role": "synapse", "database": "synapse", "password": syn_pw}},
        {"runbook": "cfg.pg_db", "params": {"role": "mas", "database": "mas", "password": mas_pw}},
        {"runbook": "cfg.volume_files", "params": {"component": "chat", "volume": "config", "image": img, "owner": SYNAPSE_UID,
                                                   "files": [{"path": "homeserver.yaml", "mode": 0o600, "content": hs},
                                                             {"path": "signing.key", "mode": 0o600,
                                                              "content": secret(ctx.rt, ctx.deployment_id, sname(t, "synapse-signing-key"), _synapse_signing_key)}]}},
        {"runbook": "cfg.volume_files", "params": {"component": "chat", "volume": "media", "image": img, "owner": SYNAPSE_UID,
                                                   "files": [{"path": "media/ou-volume", "mode": 0o644, "content": "Office Unbound chat media volume\n"}]}},
        {"runbook": "cfg.volume_files", "params": {"component": "chat", "volume": "masconfig", "image": img, "owner": MAS_UID,
                                                   "files": [{"path": "config.yaml", "mode": 0o600, "content": masc},
                                                             {"path": "trust.crt", "mode": 0o644, "content": office_trust(ca_pem)}]}},
        {"runbook": "cfg.volume_files", "params": {"component": "chat", "volume": "front", "image": img, "owner": ELEMENT_UID,
                                                   "files": [{"path": "nginx.conf", "mode": 0o644, "content": _template("chat/front.conf", **hosts)},
                                                             {"path": "config.json", "mode": 0o644, "content": element_config(hosts, portal)}]}},
        *_local_sites(ctx, vm, domain, ("chat", "matrix", "mas")),
    ]


def element_config(hosts: dict, portal: str | None = None) -> str:
    """Element's config.json: the template plus the suite's custom themes (brand.element_themes), the light one by default. Element applies
    a custom theme only with its system-theme setting off, so the default follows the suite, not the browser; each user can pick
    "Office Unbound Dark" (or Element's own themes) under Settings, Appearance. `branding` (brand.element_branding): the navy backdrop of
    the sign-in and identity pages instead of Element's photo, the mark, a footer link back to the portal."""
    c = json.loads(_template("chat/element.json", **hosts))
    c["branding"] = brand.element_branding(portal)
    c["default_theme"] = f"custom-{brand.ELEMENT_THEME}"
    c["setting_defaults"] = {**c.get("setting_defaults", {}), "custom_themes": brand.element_themes(), "use_system_theme": False}
    return json.dumps(c, indent=2) + "\n"


def node_runbooks(ctx, vm: str) -> list[dict]:
    """NODE_REFRESH: an existing VM's name resolution and VM-to-VM firewall brought to the current plan (a component was added elsewhere)."""
    return [{"runbook": "cfg.hosts", "params": {"entries": hosts_entries(ctx, names_by_vm(ctx.plan))}}, firewall_runbook(ctx, vm)]


NODE_REFRESH = "@node"
BUILDERS = {NODE_REFRESH: node_runbooks, "identity": identity_runbooks, "edge": edge_runbooks, "files": files_runbooks, "office": office_runbooks, "groupware": groupware_runbooks,
            "portal": portal_runbooks, "chat": chat_runbooks}


def expand(ctx, vm: str, component: str, runbooks: list[dict]) -> list[dict]:
    """The plan's install runbooks with the component's configuration inserted: before its first unit deployment (the unit reads the state), or
    after the packages when it deploys no unit (edge = nginx)."""
    b = BUILDERS.get(component)
    if b is None:
        return list(runbooks)
    cfg = b(ctx, vm)
    late = [{k: v for k, v in r.items() if k != "after_unit"} for r in cfg if r.get("after_unit")]   # needs the running service (realm reconcile)
    cfg = [r for r in cfg if not r.get("after_unit")]
    i = next((n for n, r in enumerate(runbooks) if r["runbook"] == "podman.deploy_unit"), len(runbooks))
    # every image of the component is pulled and verified BEFORE its configuration: cfg.volume_files names one of them (chat: element-web, the
    # first container by name) and the agent refuses a volume for an image it has not verified (officeunbound8 job 1a635703, 2026-11-24)
    pulls = [r for r in runbooks[i:] if r["runbook"] == "podman.pull_verified"]
    rest = [r for r in runbooks[i:] if r["runbook"] != "podman.pull_verified"]
    return list(runbooks[:i]) + pulls + cfg + rest + late


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
        elif k in ("css", "mark_svg", "fonts_css"):   # cfg.gromox brand: generated skin, no secret; logged by size only
            out[k] = f"[{len(str(v).encode())} bytes]"
        elif k == "realm_json":
            out[k] = f"[realm, {len(str(v).encode())} bytes]"
        elif k == "ca_pem" or k == "cert_pem":
            out[k] = "[certificate]"
        elif k == "restore" and runbook == "cfg.acme":   # a captured certificate lineage: carries the private key and the ACME account key
            out[k] = "[certificate bundle]"
        elif isinstance(v, dict):   # nested settings (cfg.gromox sso): same rules
            out[k] = redact(runbook, v)
        else:
            out[k] = v
    return out
