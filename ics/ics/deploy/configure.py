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
LDAP_GROUPS = ("opencloudAdmin", "opencloudSpaceAdmin", "opencloudUser", "opencloudGuest", "mail-users")
KEYCLOAK_UID = "10130:10130"   # the non-root user of the Keycloak image (blueprints/build/oci/idfiles)
SECRET_PARAM_KEYS = ("admin_password", "bind_password", "password", "value", "key_pem")
CONFIGURED = ("identity", "edge")   # components whose node-local state the engine creates today (files/office/groupware: still notices)


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
def _new_ca(domain: str, slug: str) -> str:
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
            .add_extension(x509.NameConstraints(permitted_subtrees=[x509.DNSName(domain)], excluded_subtrees=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    return json.dumps({"key": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(),
                       "cert": cert.public_bytes(serialization.Encoding.PEM).decode()})


def ca(rt, dep_id: str, domain: str, slug: str) -> dict:
    return json.loads(secret(rt, dep_id, "deployment-ca", lambda: _new_ca(domain, slug)))


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


# ---------------------------------------------------------------- names
def domain_of(plan: dict, vm: str) -> str:
    tenant = next((v.get("tenant") for v in plan.get("vms", []) if v["name"] == vm), None)
    d = plan["input"]["domain"]
    return f"{tenant}.{d}" if tenant else d


def vm_of(plan: dict, component: str, tenant=None) -> str | None:
    for v in plan.get("vms", []):
        if component in (v.get("components") or []) and v.get("tenant") == tenant:
            return v["name"]
    return None


def names_by_vm(plan: dict, domain: str) -> dict[str, list[str]]:
    """{vm: [fqdn, ...]} from the plan's A records (`vm:<name>` values) plus the directory's internal name on the identity VM."""
    out: dict[str, list[str]] = {}
    for r in plan.get("dns", []):
        if r["type"] == "A" and str(r["value"]).startswith("vm:") and (r["name"] == domain or r["name"].endswith("." + domain)):
            out.setdefault(r["value"][3:], []).append(r["name"])
    for r in plan.get("dns", []):   # CNAMEs inside the deployment resolve locally to their target's VM
        if r["type"] == "CNAME":
            tgt = r["value"].rstrip(".")
            for vm, ns in out.items():
                if tgt in ns and r["name"] not in ns:
                    ns.append(r["name"])
    idvm = vm_of(plan, "identity")
    if idvm:
        out.setdefault(idvm, []).append(f"ldap.{domain}")
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


def _tls(ctx, vm: str, domain: str, names: dict) -> dict:
    ca_ = ca(ctx.rt, ctx.deployment_id, ctx.plan["input"]["domain"], ctx.slug)
    mine = names.get(vm) or [f"{vm}.{domain}"]
    cert, key = leaf(ca_, mine)
    return {"runbook": "cfg.tls", "params": {"name": "deployment", "ca_pem": ca_["cert"], "cert_pem": cert, "key_pem": key}}


# ---------------------------------------------------------------- components
def realm_json(domain: str, bind_password: str) -> str:
    base = ",".join(f"dc={x}" for x in domain.split("."))
    raw = (catalog_dir() / "templates" / "identity" / "realm.json").read_text()

    def walk(v):
        if isinstance(v, dict):
            return {k: walk(x) for k, x in v.items()}
        if isinstance(v, list):
            return [walk(x) for x in v]
        if isinstance(v, str):
            return (v.replace("@BASE_DN@", base).replace("@DOMAIN@", domain).replace("@REALM@", REALM)
                    .replace("@LDAP_BIND_PASSWORD@", bind_password))
        return v
    return json.dumps(walk(json.loads(raw)), indent=2) + "\n"


def _image(ctx, vm: str, component: str) -> str:
    for c in ctx.plan.get("containers", []):
        if c["vm"] == vm and c["component"] == component:
            return f"{c['image']}@{c['digest']}"
    raise ConfigError(f"no {component} image on {vm} in the plan")


def identity_runbooks(ctx, vm: str) -> list[dict]:
    dep, rt = ctx.deployment_id, ctx.rt
    domain = domain_of(ctx.plan, vm)
    names = names_by_vm(ctx.plan, domain)
    bind_pw = secret(rt, dep, "ldap-bind-password")
    img = _image(ctx, vm, "identity")
    ca_pem = ca(rt, dep, ctx.plan["input"]["domain"], ctx.slug)["cert"]
    return [
        {"runbook": "cfg.hosts", "params": {"entries": hosts_entries(ctx, names)}},
        firewall_runbook(ctx, vm),
        _tls(ctx, vm, domain, names),
        {"runbook": "cfg.ldap_init", "params": {"domain": domain, "organization": "Office Unbound", "admin_password": secret(rt, dep, "ldap-admin-password"),
                                                "bind_password": bind_pw, "tls_name": "deployment", "groups": list(LDAP_GROUPS)}},
        {"runbook": "cfg.ldap_user", "params": {"domain": domain, "uid": "ou-admin", "given_name": "Office Unbound", "surname": "Administrator",
                                                "mail": f"ou-admin@{domain}", "password": secret(rt, dep, "admin-password"),
                                                "groups": ["opencloudAdmin", "mail-users"]}},
        {"runbook": "cfg.pg_db", "params": {"role": "keycloak", "database": "keycloak", "password": secret(rt, dep, "kc-db-password")}},
        {"runbook": "cfg.podman_secret", "params": {"name": "kc-db-password", "value": secret(rt, dep, "kc-db-password")}},
        {"runbook": "cfg.podman_secret", "params": {"name": "kc-admin-password", "value": secret(rt, dep, "kc-admin-password")}},
        {"runbook": "cfg.volume_files", "params": {"component": "identity", "volume": "tls", "image": img, "owner": KEYCLOAK_UID,
                                                   "files": [{"path": "ca.crt", "mode": 0o644, "content": ca_pem}]}},
        {"runbook": "cfg.volume_files", "params": {"component": "identity", "volume": "data", "image": img, "owner": KEYCLOAK_UID,
                                                   "files": [{"path": f"import/realm-{REALM}.json", "mode": 0o600, "content": realm_json(domain, bind_pw)}]}},
    ]


def edge_runbooks(ctx, vm: str) -> list[dict]:
    domain = domain_of(ctx.plan, vm)
    names = names_by_vm(ctx.plan, domain)
    out = [{"runbook": "cfg.hosts", "params": {"entries": hosts_entries(ctx, names)}}, _tls(ctx, vm, domain, names)]
    if vm_of(ctx.plan, "identity", None) == vm:
        out.append({"runbook": "cfg.nginx_site", "params": {"name": "auth", "server_names": [f"auth.{domain}"], "upstream": "http://127.0.0.1:8080",
                                                            "tls_name": "deployment", "max_body_mb": 16}})
    return out


BUILDERS = {"identity": identity_runbooks, "edge": edge_runbooks}


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
        else:
            out[k] = v
    return out
