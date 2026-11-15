"""Typed actions that manage infrastructure endpoints as settings: register (extended), update, remove, disable, enable.

All of them are plans (hash-bound, approved by risk, executed by the job runner, audited). Credentials have two roles:
`inventory` (read-only PVEAuditor token; the endpoint's token_id/token_secret) and optional `provision` (pool-scoped token).
Secrets are never selected for display; the plan digest binds the endpoint's current trust anchors so an edit approved against
one configuration cannot execute against another.
"""
from __future__ import annotations

import dataclasses
import re
from typing import Literal, Self
from urllib.parse import urlparse
from uuid import UUID

from cryptography import x509
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from sqlalchemy import text
from sqlalchemy.orm import Session

from . import audit
from .providers.proxmox import EndpointScope, probe_connection, provision_aad
from .proxmox import ProxmoxError, normalize_fingerprint
from .runtime import Runtime

TOKEN_ID_RE = r"^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+![A-Za-z0-9._-]+$"
SECRET_RE = r"[A-Za-z0-9_-]{8,200}"
_POOL = r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$"
_STORAGE = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$"
_NODE = r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$"
_NET = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}(/([1-9]\d{0,3}))?$"


def norm_secret(v):
    raw = v.get_secret_value() if isinstance(v, SecretStr) else v
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise ValueError("secret must be a string")
    raw = raw.strip()
    if not re.fullmatch(SECRET_RE, raw):
        raise ValueError("token secret must be 8-200 characters of [A-Za-z0-9_-] (no whitespace or other characters)")
    return raw


def _list(rx: str, label: str, v):
    if v is None:
        return v
    if len(v) > 50 or any(not re.match(rx, x) for x in v):
        raise ValueError(f"{label} entries must be plain names (max 50)")
    return sorted(set(v))


class Defaults(BaseModel):
    """Operator-chosen deployment defaults saved with the endpoint (consumed by the plan generator; none of it is executed directly)."""
    model_config = ConfigDict(extra="forbid")
    storage: str | None = Field(default=None, pattern=_STORAGE)
    bridge: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$")
    vlan: int | None = Field(default=None, ge=1, le=4094)
    ip_mode: Literal["dhcp", "static"] | None = None
    dns_servers: list[str] | None = Field(default=None, max_length=4)
    search_domain: str | None = Field(default=None, pattern=r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
    backup_storage: str | None = Field(default=None, pattern=_STORAGE)
    approved_os_images: list[str] | None = Field(default=None, max_length=20)
    resource_policy: Literal["conservative", "balanced", "dense"] | None = None

    @field_validator("dns_servers")
    @classmethod
    def _dns(cls, v):
        import ipaddress
        for x in v or []:
            ipaddress.ip_address(x)
        return v

    @field_validator("approved_os_images")
    @classmethod
    def _img(cls, v):
        if v and any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}", x) for x in v):
            raise ValueError("approved_os_images entries must be plain image names")
        return v


class ScopeLists(BaseModel):
    """Scope allowlists. Networks are `bridge` (any VLAN) or `bridge/vlan` (that VLAN only)."""
    allowed_pools: list[str] | None = None
    allowed_nodes: list[str] | None = Field(default=None, description="cluster nodes ICS may create/change/migrate guests on (deny by default)")
    allowed_storage: list[str] | None = None
    allowed_networks: list[str] | None = None
    allowed_templates: list[int] | None = Field(default=None, description="template vmids permitted outside the allowed pools")
    allow_cicustom: bool | None = None
    protected_vmids: list[int] | None = Field(default=None, description="guests that can never be mutated (in addition to the ICS's own VM)")
    defaults: Defaults | None = None

    @field_validator("protected_vmids")
    @classmethod
    def _pv(cls, v):
        if v is not None and (len(v) > 100 or any(not 1 <= x <= 999_999_999 for x in v)):
            raise ValueError("protected_vmids must be vmids (max 100)")
        return sorted(set(v)) if v is not None else v

    @field_validator("allowed_nodes")
    @classmethod
    def _nd(cls, v):
        return _list(_NODE, "allowed_nodes", v)

    @field_validator("allowed_pools")
    @classmethod
    def _p(cls, v):
        return _list(_POOL, "allowed_pools", v)

    @field_validator("allowed_storage")
    @classmethod
    def _s(cls, v):
        return _list(_STORAGE, "allowed_storage", v)

    @field_validator("allowed_networks")
    @classmethod
    def _n(cls, v):
        return _list(_NET, "allowed_networks", v)

    @field_validator("allowed_templates")
    @classmethod
    def _t(cls, v):
        if v is not None and (len(v) > 50 or any(not 100 <= x <= 999_999_999 for x in v)):
            raise ValueError("allowed_templates must be vmids (max 50)")
        return sorted(set(v)) if v is not None else v


def _check_ca(v: str | None) -> str | None:
    if v is None:
        return v
    try:
        certs = x509.load_pem_x509_certificates(v.encode())
    except Exception:  # noqa: BLE001
        raise ValueError("ca_pem must contain valid PEM certificate(s)") from None
    if not certs:
        raise ValueError("ca_pem must contain a PEM certificate")
    return v


def _check_url(v: str) -> str:
    u = urlparse(v)
    if u.scheme != "https" or not u.hostname or u.username or u.password or u.path not in ("", "/") or u.query or u.fragment:
        raise ValueError("base_url must be https://host[:port] with no credentials/path")
    return f"https://{u.netloc}"


class EndpointUpdate(ScopeLists):
    """Partial edit. Omitted = unchanged. Changing base_url, TLS trust, any credential or any scope list is HIGH risk (2 approvers)
    and forces a successful re-probe before anything is persisted; renaming (display_name) or enabled-only edits are `normal`."""
    model_config = ConfigDict(extra="forbid")
    endpoint_id: UUID
    display_name: str | None = Field(default=None, max_length=80, pattern=r"^[^\x00-\x1f]*$")
    base_url: str | None = None
    ca_pem: str | None = Field(default=None, max_length=100_000)
    fingerprint_sha256: str | None = None
    token_id: str | None = Field(default=None, pattern=TOKEN_ID_RE)
    token_secret: SecretStr | None = None
    provision_token_id: str | None = Field(default=None, pattern=TOKEN_ID_RE)
    provision_token_secret: SecretStr | None = None
    remove_provision: bool = False
    enabled: bool | None = None

    @field_validator("token_secret", "provision_token_secret", mode="before")
    @classmethod
    def _sec(cls, v):
        return norm_secret(v)

    @field_validator("base_url")
    @classmethod
    def _u(cls, v):
        return _check_url(v) if v is not None else v

    @field_validator("ca_pem")
    @classmethod
    def _c(cls, v):
        return _check_ca(v)

    @field_validator("fingerprint_sha256")
    @classmethod
    def _f(cls, v):
        return normalize_fingerprint(v) if v is not None else v

    @model_validator(mode="after")
    def _shape(self) -> Self:
        if self.ca_pem is not None and self.fingerprint_sha256 is not None:
            raise ValueError("provide exactly one TLS trust anchor (ca_pem or fingerprint_sha256)")
        if (self.token_id is None) != (self.token_secret is None) and self.token_id is not None:
            raise ValueError("token_id needs token_secret")
        if self.provision_token_id is not None and self.provision_token_secret is None:
            raise ValueError("provision_token_id needs provision_token_secret")
        if self.remove_provision and (self.provision_token_id or self.provision_token_secret):
            raise ValueError("remove_provision conflicts with new provision credentials")
        return self

    def changed(self) -> set[str]:
        out = set()
        for k in self.model_fields_set - {"endpoint_id"}:
            v = getattr(self, k)
            if (k == "remove_provision" and v) or (k != "remove_provision" and v is not None):
                out.add(k)
        return out


def update_risk(p: EndpointUpdate) -> str:
    return "normal" if p.changed() <= {"display_name", "enabled"} else "high"


class EndpointRemove(BaseModel):
    model_config = ConfigDict(extra="forbid")
    endpoint_id: UUID
    confirm_name: str = Field(max_length=63, description="must equal the endpoint's current name")
    force_detach: bool = Field(default=False, description="remove although deployments reference it (they are detached); separately visible to approvers")


class EndpointToggle(BaseModel):
    model_config = ConfigDict(extra="forbid")
    endpoint_id: UUID


# ---- helpers ---------------------------------------------------------------------------------------------------

def endpoint_refs(db: Session, endpoint_id) -> int:
    """Live deployments (deployment engine table `deployments`, endpoint_id FK) that use the endpoint; destroyed ones do not count."""
    return db.execute(text("SELECT count(*) FROM deployments WHERE endpoint_id = :e AND status <> 'destroyed'"),
                      {"e": str(endpoint_id)}).scalar() or 0


def probe_dict(res) -> dict:
    d = dataclasses.asdict(res)
    return audit.sanitize(d)


def _ep(db: Session, eid):
    return db.execute(text("SELECT * FROM endpoints WHERE id = :i"), {"i": str(eid)}).first()


def _scope(pools, storage, nets, templates, cic, protected=(), nodes=()) -> EndpointScope:
    return EndpointScope(tuple(pools or ()), tuple(storage or ()), tuple(nets or ()), tuple(templates or ()), bool(cic), tuple(protected or ()),
                         tuple(nodes or ()))


def _require_ok(res, want_provision: bool) -> None:
    inv = res.credentials.get("inventory", {})
    if not res.tls.get("ok") or not inv.get("authenticated"):
        raise ProxmoxError((res.errors or ["probe failed"])[0])
    if want_provision and not res.credentials.get("provision", {}).get("authenticated"):
        raise ProxmoxError(next((e for e in res.errors if e.startswith("provision")), "provision credential rejected"))


# ---- plan-time prechecks (called by create_plan) -----------------------------------------------------------------

def precheck(db: Session, rt: Runtime, action: str, p) -> dict:
    from .actions import PlanError, _guard  # late: actions imports this module
    ep = _ep(db, p.endpoint_id)
    if ep is None:
        raise PlanError(404, "endpoint not found")
    if ep.detached_at is not None:
        raise PlanError(409, "endpoint is removed (detached)")
    extra: dict = {"endpoint_name": ep.name}
    if action == "endpoint.update":
        if not p.changed():
            raise PlanError(422, "no changes requested")
        if p.base_url:
            extra["resolved_ips"] = _guard(rt, urlparse(p.base_url).hostname)
        extra["changes"] = sorted(p.changed())
        if p.remove_provision and not ep.provision_token_id:
            raise PlanError(409, "endpoint has no provision credential")
        prov = (ep.provision_token_id and not p.remove_provision) or p.provision_token_id
        pools = p.allowed_pools if p.allowed_pools is not None else ep.allowed_pools
        if prov and not pools:
            raise PlanError(422, "a provision credential requires at least one allowed pool")
        nodes = p.allowed_nodes if p.allowed_nodes is not None else ep.allowed_nodes
        if prov and not nodes:
            raise PlanError(422, "a provision credential requires at least one authorized node")
    elif action == "endpoint.remove":
        if p.confirm_name != ep.name:
            raise PlanError(422, "confirm_name does not match the endpoint name")
        n = endpoint_refs(db, p.endpoint_id)
        extra["referencing_deployments"] = n
        if n and not p.force_detach:
            raise PlanError(409, f"{n} deployment(s) still reference this endpoint; remove them or set force_detach")
    elif action == "endpoint.disable" and not ep.enabled:
        raise PlanError(409, "endpoint is already disabled")
    elif action == "endpoint.enable" and ep.enabled:
        raise PlanError(409, "endpoint is already enabled")
    return extra


# ---- executors -----------------------------------------------------------------------------------------------------

def exec_register(rt: Runtime, db: Session, m, plan, known: list[str]) -> dict:
    import uuid
    from .actions import endpoint_binding
    eid = uuid.uuid4()
    secret = m.token_secret.get_secret_value()
    psecret = m.provision_token_secret.get_secret_value() if m.provision_token_secret else None
    known += [secret] + ([psecret] if psecret else [])
    res = probe_connection(rt, base_url=m.base_url, token_id=m.token_id, token_secret=secret, ca_pem=m.ca_pem,
                           fingerprint_sha256=m.fingerprint_sha256, provision_token_id=m.provision_token_id,
                           provision_token_secret=psecret,
                           scope=_scope(m.allowed_pools, m.allowed_storage, m.allowed_networks, m.allowed_templates, m.allow_cicustom, m.protected_vmids, m.allowed_nodes))
    _require_ok(res, bool(m.provision_token_id))  # connectivity + TLS trust + credential check before we persist anything
    version = audit.sanitize(res.version)
    b = endpoint_binding(m.base_url, m.token_id, m.fingerprint_sha256, m.ca_pem)
    paad = f"endpoint-provision:{eid}:{b}:{m.provision_token_id}"
    db.execute(text(
        "INSERT INTO endpoints (id, name, type, base_url, token_id, token_secret_enc, ca_pem, fingerprint_sha256, created_by, display_name, "
        "provision_token_id, provision_secret_enc, allowed_pools, allowed_nodes, allowed_storage, allowed_networks, allowed_templates, allow_cicustom, protected_vmids, defaults, "
        "last_probe, last_probe_at) VALUES (:id, :n, :t, :u, :ti, :ts, :ca, :fp, :cb, :dn, :pti, :pse, :ap, :anodes, :ast, :an, :at, :cic, :pv, CAST(:df AS jsonb), "
        "CAST(:lp AS jsonb), now())"),
        {"id": str(eid), "n": m.name, "t": m.type, "u": m.base_url, "ti": m.token_id,
         "ts": rt.vault.encrypt(secret.encode(), f"endpoint-token:{eid}:{b}"), "ca": m.ca_pem, "fp": m.fingerprint_sha256,
         "cb": str(plan.requested_by), "dn": m.display_name, "pti": m.provision_token_id,
         "pse": rt.vault.encrypt(psecret.encode(), paad) if psecret else None,
         "ap": m.allowed_pools or [], "anodes": m.allowed_nodes or [], "ast": m.allowed_storage or [], "an": m.allowed_networks or [], "at": m.allowed_templates or [],
         "cic": bool(m.allow_cicustom), "pv": m.protected_vmids or [], "df": audit.canon(m.defaults.model_dump(exclude_none=True)) if m.defaults else "{}", "lp": audit.canon(probe_dict(res))})
    audit.append(db, "endpoint.registered", actor_name="worker", resource="endpoint", resource_id=str(eid),
                 details={"name": m.name, "base_url": m.base_url, "token_id": m.token_id,
                          "trust": "fingerprint" if m.fingerprint_sha256 else "ca_bundle", "pve_version": version,
                          "provision_token_id": m.provision_token_id, "allowed_pools": m.allowed_pools or [],
                          "allowed_storage": m.allowed_storage or [], "allowed_networks": m.allowed_networks or []})
    return {"endpoint_id": str(eid), "pve_version": version, "provision": bool(m.provision_token_id)}


def exec_update(rt: Runtime, db: Session, m: EndpointUpdate, plan, known: list[str]) -> dict:
    from .actions import endpoint_binding
    ep = _ep(db, m.endpoint_id)
    if ep is None or ep.detached_at is not None:
        raise ProxmoxError("endpoint not found or removed")
    old_b = endpoint_binding(ep.base_url, ep.token_id, ep.fingerprint_sha256, ep.ca_pem)
    base_url = m.base_url or ep.base_url
    ca, fp = ep.ca_pem, ep.fingerprint_sha256
    if m.ca_pem is not None:
        ca, fp = m.ca_pem, None
    if m.fingerprint_sha256 is not None:
        ca, fp = None, m.fingerprint_sha256
    token_id = m.token_id or ep.token_id
    inv_secret = m.token_secret.get_secret_value() if m.token_secret else rt.vault.decrypt(ep.token_secret_enc, f"endpoint-token:{ep.id}:{old_b}").decode()
    prov_id, prov_secret = ep.provision_token_id, None
    if m.remove_provision:
        prov_id = None
    elif m.provision_token_id:
        prov_id, prov_secret = m.provision_token_id, m.provision_token_secret.get_secret_value()
    elif prov_id:
        prov_secret = rt.vault.decrypt(ep.provision_secret_enc, provision_aad(ep, old_b)).decode()
    known += [inv_secret] + ([prov_secret] if prov_secret else [])
    pick = lambda new, old: new if new is not None else (old or [])  # noqa: E731
    pools, storage = pick(m.allowed_pools, ep.allowed_pools), pick(m.allowed_storage, ep.allowed_storage)
    nodes = pick(m.allowed_nodes, ep.allowed_nodes)
    nets, tpls = pick(m.allowed_networks, ep.allowed_networks), pick(m.allowed_templates, ep.allowed_templates)
    cic = ep.allow_cicustom if m.allow_cicustom is None else m.allow_cicustom
    prot = pick(m.protected_vmids, ep.protected_vmids)
    if prov_id and not pools:
        raise ProxmoxError("a provision credential requires at least one allowed pool")
    if prov_id and not nodes:
        raise ProxmoxError("a provision credential requires at least one authorized node")
    conn = m.changed() & {"base_url", "ca_pem", "fingerprint_sha256", "token_id", "token_secret", "provision_token_id",
                          "provision_token_secret", "remove_provision", "allowed_pools", "allowed_nodes", "allowed_storage", "allowed_networks", "protected_vmids"}
    probe = None
    if conn:  # re-probe with the NEW configuration; nothing is persisted when it fails
        probe = probe_connection(rt, base_url=base_url, token_id=token_id, token_secret=inv_secret, ca_pem=ca, fingerprint_sha256=fp,
                                 provision_token_id=prov_id, provision_token_secret=prov_secret, scope=_scope(pools, storage, nets, tpls, cic, prot, nodes))
        _require_ok(probe, bool(prov_id))
    new_b = endpoint_binding(base_url, token_id, fp, ca)
    enabled = ep.enabled if m.enabled is None else m.enabled
    db.execute(text(
        "UPDATE endpoints SET display_name = :dn, base_url = :u, ca_pem = :ca, fingerprint_sha256 = :fp, token_id = :ti, token_secret_enc = :ts, "
        "provision_token_id = :pti, provision_secret_enc = :pse, allowed_pools = :ap, allowed_nodes = :anodes, allowed_storage = :ast, allowed_networks = :an, "
        "allowed_templates = :at, allow_cicustom = :cic, protected_vmids = :pv, defaults = CAST(:df AS jsonb), enabled = :en, last_probe = COALESCE(CAST(:lp AS jsonb), last_probe), "
        "last_probe_at = CASE WHEN :lp IS NULL THEN last_probe_at ELSE now() END WHERE id = :id"),
        {"id": str(ep.id), "dn": m.display_name if m.display_name is not None else ep.display_name, "u": base_url, "ca": ca, "fp": fp,
         "ti": token_id, "ts": rt.vault.encrypt(inv_secret.encode(), f"endpoint-token:{ep.id}:{new_b}"), "pti": prov_id,
         "pse": rt.vault.encrypt(prov_secret.encode(), f"endpoint-provision:{ep.id}:{new_b}:{prov_id}") if prov_id else None,
         "ap": pools, "anodes": nodes, "ast": storage, "an": nets, "at": tpls, "cic": cic, "pv": prot, "df": audit.canon(m.defaults.model_dump(exclude_none=True)) if m.defaults is not None else audit.canon(ep.defaults or {}), "en": enabled,
         "lp": audit.canon(probe_dict(probe)) if probe else None})
    audit.append(db, "endpoint.updated", actor_name="worker", resource="endpoint", resource_id=str(ep.id),
                 details={"name": ep.name, "changed": sorted(m.changed()), "base_url": base_url,
                          "trust": "fingerprint" if fp else "ca_bundle", "token_id": token_id, "provision_token_id": prov_id,
                          "secret_rotated": bool(m.token_secret or m.provision_token_secret), "reprobed": bool(conn), "enabled": enabled,
                          "allowed_pools": pools, "allowed_nodes": nodes, "allowed_storage": storage, "allowed_networks": nets})
    return {"endpoint_id": str(ep.id), "changed": sorted(m.changed()), "reprobed": bool(conn), "enabled": enabled}


def exec_remove(rt: Runtime, db: Session, m: EndpointRemove, plan, known: list[str]) -> dict:
    ep = _ep(db, m.endpoint_id)
    if ep is None or ep.detached_at is not None:
        raise ProxmoxError("endpoint not found or already removed")
    refs = endpoint_refs(db, ep.id)
    if refs and not m.force_detach:
        raise ProxmoxError(f"{refs} deployment(s) reference this endpoint")
    db.execute(text(
        "UPDATE endpoints SET enabled = false, detached_at = now(), token_secret_enc = '\\x'::bytea, provision_token_id = NULL, "
        "provision_secret_enc = NULL, allowed_pools = '{}', allowed_nodes = '{}', allowed_storage = '{}', allowed_networks = '{}', allowed_templates = '{}', "
        "allow_cicustom = false, name = left(name, 40) || '~detached-' || left(id::text, 8) WHERE id = :i"), {"i": str(ep.id)})
    audit.append(db, "endpoint.removed", actor_name="worker", resource="endpoint", resource_id=str(ep.id),
                 details={"name": ep.name, "force_detach": m.force_detach, "referencing_deployments": refs,
                          "history": "inventory rows and metrics are kept, marked detached; stored credentials were destroyed"})
    return {"endpoint_id": str(ep.id), "detached": True, "referencing_deployments": refs}


def _toggle(value: bool):
    def run(rt: Runtime, db: Session, m: EndpointToggle, plan, known: list[str]) -> dict:
        ep = _ep(db, m.endpoint_id)
        if ep is None or ep.detached_at is not None:
            raise ProxmoxError("endpoint not found or removed")
        db.execute(text("UPDATE endpoints SET enabled = :v WHERE id = :i"), {"v": value, "i": str(ep.id)})
        audit.append(db, "endpoint.enabled" if value else "endpoint.disabled", actor_name="worker", resource="endpoint",
                     resource_id=str(ep.id), details={"name": ep.name})
        return {"endpoint_id": str(ep.id), "enabled": value}
    return run


EXECUTORS = {"endpoint.update": exec_update, "endpoint.remove": exec_remove, "endpoint.disable": _toggle(False),
             "endpoint.enable": _toggle(True)}
BINDING_ACTIONS = {"inventory.refresh", "endpoint.update", "endpoint.remove", "endpoint.disable", "endpoint.enable"}
