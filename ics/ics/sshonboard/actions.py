"""Typed actions of the SSH onboarding flow (ADR-0014). All go through plan -> approval by risk -> single-use job -> audit like every other action.

  provider.ssh.discover   low   read-only discovery over the pinned SSH session + API-certificate cross-check
  provider.ssh.preview    low   permission plan (the EXISTING generator) + the exact command list + the ICS's own node identity, hash-bound
  provider.ssh_onboard    high  run exactly the previewed commands, verify, register, wipe the admin credential
  provider.ssh_offboard   high  remove everything onboarding created (admin credential needed again)
  provider.ssh.helper     low   the ICS's OWN SSH identity: self-check / discover / drift / cert-read through ou-pve-helper (never the admin credential)
  provider.ssh.narrow     normal the ICS's OWN SSH identity: delete one of the ICS's own ACL entries (narrowing only)

The admin's SSH credential is referenced by `ssh_session_id` (a vault credential); it never appears in params, results or the audit trail."""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import text
from sqlalchemy.orm import Session

from .. import audit
from ..credentials import service as cred_service
from ..provisioning import actions as prov
from ..provisioning.model import Policy
from ..providers.proxmox import provisioning as pp
from ..proxmox import ProxmoxError, check_destination, fetch_peer_certificate, normalize_fingerprint
from ..runtime import Runtime
from . import admin as A, session as S, templates as T, trust as TR
from .client import HostKey, SshError, SshSession

SERVICE_USER = "officeunbound"
ACCOUNT_DEFAULT = "ou-ics"


# ---------------------------------------------------------------------------------------------------- models
class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ssh_session_id: UUID


class SshDiscover(_Base):
    pass


class SshPreview(_Base):
    policy: Policy
    name: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9_-]{0,62}$")
    endpoint_id: UUID | None = None
    ics_address: str | None = Field(default=None, pattern=r"^[0-9A-Fa-f:.]{3,45}$", description="the ICS's address, written as from= into authorized_keys")
    account: str = Field(default=ACCOUNT_DEFAULT, pattern=r"^[a-z_][a-z0-9_-]{0,31}$")

    @model_validator(mode="after")
    def _chk(self):
        if self.endpoint_id is None and not self.name:
            raise ValueError("name is required for a new integration")
        if self.endpoint_id is not None and self.name:
            raise ValueError("name only applies to a new integration")
        return self


class SshOnboard(_Base):
    preview_id: UUID
    bind_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    name: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9_-]{0,62}$")
    endpoint_id: UUID | None = None
    customer_id: UUID | None = None


class SshOffboard(_Base):
    endpoint_id: UUID
    confirm_name: str = Field(max_length=63)
    delete_pool: bool = False


class SshHelper(BaseModel):
    model_config = ConfigDict(extra="forbid")
    endpoint_id: UUID
    op: Literal["self-check", "discover", "drift", "cert-read"] = "self-check"
    kind: Literal["version", "cluster-status", "nodes", "storage", "pools", "resources", "roles", "users", "acl", "network", "fw-cluster", "fw-options", "fw-rules",
                  "storage-lvm", "storage-zfs"] | None = None
    node: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$")

    @model_validator(mode="after")
    def _chk(self):
        if (self.op == "discover") != (self.kind is not None) or (self.node is not None) != (self.kind in ("network", "fw-options", "fw-rules")):
            raise ValueError("kind is required for (and only for) op=discover; node exactly for the node kinds (network, fw-options, fw-rules)")
        return self


class SshNarrow(BaseModel):
    model_config = ConfigDict(extra="forbid")
    endpoint_id: UUID
    path: str = Field(pattern=r"^/[A-Za-z0-9/._:@+-]{0,200}$")
    role: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,62}$")
    subject: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}@[A-Za-z0-9._-]{1,32}(![A-Za-z0-9][A-Za-z0-9_.-]{0,62})?$")


CATALOG = {
    "provider.ssh.discover": {"model": SshDiscover, "risk": "low", "secrets": ()},
    "provider.ssh.preview": {"model": SshPreview, "risk": "low", "secrets": ()},
    "provider.ssh_onboard": {"model": SshOnboard, "risk": "high", "secrets": ()},
    "provider.ssh_offboard": {"model": SshOffboard, "risk": "high", "secrets": ()},
    "provider.ssh.helper": {"model": SshHelper, "risk": "low", "secrets": ()},
    "provider.ssh.narrow": {"model": SshNarrow, "risk": "normal", "secrets": ()},
}
SESSION_ACTIONS = {"provider.ssh.discover", "provider.ssh.preview", "provider.ssh_onboard", "provider.ssh_offboard"}


# ---------------------------------------------------------------------------------------------------- plan time
def customer_for(db: Session, action: str, p) -> str | None:
    """The customer an SSH action belongs to: the session's (admin credential is bound to it) or the endpoint's. Disagreement is refused."""
    from ..actions import PlanError
    cust = None
    if getattr(p, "ssh_session_id", None) is not None:
        r = S.row(db, p.ssh_session_id)
        if r is None:
            raise PlanError(404, "SSH session not found")
        cust = str(r.customer_id)
    eid = getattr(p, "endpoint_id", None)
    if eid is not None:
        e = db.execute(text("SELECT customer_id FROM endpoints WHERE id = :i"), {"i": str(eid)}).first()
        if e is None:
            raise PlanError(404, "endpoint not found")
        if cust and str(e.customer_id) != cust:
            raise PlanError(409, "the SSH session belongs to another customer than the endpoint")
        cust = str(e.customer_id)
    if getattr(p, "customer_id", None) and cust and str(p.customer_id) != cust:
        raise PlanError(409, "customer_id does not match the SSH session")
    return cust


def _artifact(db: Session, aid):
    return db.execute(text("SELECT * FROM provision_artifacts WHERE id = :i AND kind = 'plan'"), {"i": str(aid)}).first()


def precheck(db: Session, rt: Runtime, action: str, p, user) -> dict:
    from ..actions import PlanError
    extra: dict = {}
    if action in SESSION_ACTIONS:
        try:
            r = S.live(db, p.ssh_session_id, user.id)
        except S.SessionError as e:
            raise PlanError(e.status, e.msg) from None
        if r.state != "pinned":
            raise PlanError(409, "the node's SSH host key has not been confirmed yet")
        extra["ssh"] = {"host": r.host, "port": r.port, "username": r.username, "host_key": r.hk_pinned, "host_key_algo": r.hk_algo}
        if action != "provider.ssh.discover" and action != "provider.ssh_offboard" and not (r.api_trust and r.api_proxy != 'pending'):
            raise PlanError(409, "run discovery first: the node's API certificate has not been cross-checked (or a proxy in front of the API still needs your confirmation)")
    if action == "provider.ssh.preview":
        if p.endpoint_id is not None:
            if prov._ep(db, p.endpoint_id) is None:
                raise PlanError(404, "endpoint not found")
        elif db.execute(text("SELECT 1 FROM endpoints WHERE name = :n"), {"n": p.name}).first():
            raise PlanError(409, "endpoint name already exists")
    if action == "provider.ssh_onboard":
        art = _artifact(db, p.preview_id)
        if art is None or art.data.get("purpose") != "ssh_onboard":
            raise PlanError(404, "preview not found: run provider.ssh.preview first")
        if art.plan_hash != p.bind_hash:
            raise PlanError(409, "bind_hash does not match the stored preview")
        if str(art.data["ssh_session_id"]) != str(p.ssh_session_id):
            raise PlanError(409, "the preview was made for another SSH session")
        if art.data["plan"]["blocked"]:
            raise PlanError(409, "the previewed plan is blocked: " + "; ".join(art.data["plan"]["blocked"]))
        if (art.data.get("endpoint_id") or None) != (str(p.endpoint_id) if p.endpoint_id else None) or (not p.endpoint_id and art.data.get("name") != p.name):
            raise PlanError(409, "name / endpoint do not match the preview")
        extra["onboard"] = {"commands": art.data["commands"], "identity": art.data["identity"], "plan_summary": prov._summary(art.data["plan"]),
                            "bind": art.data["bind"]}
    if action == "provider.ssh_offboard":
        ep = prov._ep(db, p.endpoint_id)
        if ep is None or ep.detached_at is not None:
            raise PlanError(404, "endpoint not found")
        if p.confirm_name != ep.name:
            raise PlanError(422, "confirm_name does not match the endpoint name")
        if db.execute(text("SELECT 1 FROM ssh_identities WHERE endpoint_id = :e AND removed_at IS NULL"), {"e": str(p.endpoint_id)}).first() is None \
                and prov._stored(db, p.endpoint_id) is None:
            raise PlanError(409, "this endpoint was not onboarded by the ICS: nothing to offboard")
    if action in ("provider.ssh.helper", "provider.ssh.narrow"):
        if _identity(db, p.endpoint_id) is None:
            raise PlanError(409, "this endpoint has no ICS SSH identity")
    return extra


def _identity(db: Session, eid):
    return db.execute(text("SELECT * FROM ssh_identities WHERE endpoint_id = :e AND removed_at IS NULL"), {"e": str(eid)}).first()


# ---------------------------------------------------------------------------------------------------- shared helpers
def _connect(rt: Runtime, db: Session, r, known: list[str], actor: str) -> A.SshAdmin:
    """Admin SSH session to the node with the PINNED host key. The credential is read from the vault only here."""
    try:
        check_destination(r.host, rt.settings.allow_loopback_endpoints)
    except ProxmoxError as e:
        raise ProxmoxError(str(e)) from None
    sec = S.load_secret(rt, r.id, actor)
    known += [str(v) for v in sec.values() if v]
    try:
        s = SshSession(r.host, r.port, r.username, S.pinned_key(r), password=sec.get("password"), pem=sec.get("private_key"),
                       passphrase=sec.get("passphrase"), sudo=bool(r.use_sudo), timeout=10.0)
    except SshError as e:
        raise ProxmoxError(str(e)) from None
    finally:
        sec.clear()
    return A.SshAdmin(s)


def _node_certs(adm: A.SshAdmin) -> tuple[str, str | None]:
    """(certificate bundle the node's pveproxy serves, cluster CA PEM if readable). pveproxy-ssl.pem (custom / ACME) wins over pve-ssl.pem."""
    bundle = None
    for i in range(len(T.CERT_PATHS)):
        r = adm.s.run(T.read_cert(i))
        adm.executed.append("cert.read")
        if r.rc == 0 and b"BEGIN CERTIFICATE" in r.out:
            bundle = r.out.decode("utf-8", "replace")
            break
    if bundle is None:
        raise ProxmoxError("could not read the node's API certificate")
    r = adm.s.run(T.read_cluster_ca())
    adm.executed.append("cluster_ca.read")
    ca = r.out.decode("utf-8", "replace") if r.rc == 0 and b"BEGIN CERTIFICATE" in r.out else None
    return bundle, ca


def _api_url(r) -> str:
    return r.api_url or f"https://{r.host}:8006"


def _trust(rt: Runtime, r, adm: A.SshAdmin) -> TR.Trust:
    bundle, ca = _node_certs(adm)
    return TR.decide(_api_url(r), bundle, ca, rt.settings.allow_loopback_endpoints)


def _recheck(rt: Runtime, r, adm: A.SshAdmin) -> TR.Trust:
    """At job time the decision must be the one the admin saw: same mode and CA; the leaf only matters where it IS the pin (fingerprint / confirmed proxy)."""
    t = _trust(rt, r, adm)
    sha_ca = hashlib.sha256(r.api_ca_pem.encode()).hexdigest() if r.api_ca_pem else None
    if t.mode != r.api_trust or t.ca_sha256() != sha_ca:
        raise ProxmoxError("the API's TLS trust changed since it was approved (different mode or CA): nothing was applied; run discovery again")
    if t.mode == "fingerprint" and t.leaf_pin != r.api_cert_pinned:
        raise ProxmoxError("the API certificate changed since it was approved: nothing was applied; run discovery again")
    if t.mode == "proxy_public" and t.seen_leaf != r.api_cert_seen:
        raise ProxmoxError("the proxy's certificate changed since you confirmed it: nothing was applied; run discovery again")
    return t


def _bind_trust(r) -> dict:
    return {"api_url": _api_url(r), "api_trust": r.api_trust, "api_ca_sha256": hashlib.sha256(r.api_ca_pem.encode()).hexdigest() if r.api_ca_pem else None,
            "api_leaf_pinned": r.api_cert_pinned if r.api_trust == "fingerprint" else (r.api_cert_seen if r.api_trust == "proxy_public" else None)}


def _same_node(rt: Runtime, r, t: TR.Trust, secrets: dict, ssh_local: str | None) -> str:
    """The SSH address and the API address must be the same node. Evidence: the node-local marker of /cluster/status read with the NEW token over the pinned
    HTTPS connection versus over SSH; where the token cannot read it, an identical certificate on both paths."""
    from urllib.parse import urlparse
    from ..actions import _new_client
    api_host = (urlparse(_api_url(r)).hostname or "").lower()
    differs = api_host != r.host.lower()
    ca, fp = TR.trust_args(t)
    api_local = None
    tid, sec = secrets["inventory"]
    c = _new_client(rt, _api_url(r), tid, sec, ca, fp)
    try:
        st = c._get("/cluster/status")
        api_local = next((x.get("name") for x in st if x.get("type") == "node" and x.get("local")), None)
    except ProxmoxError:
        pass
    finally:
        c.close()
    if api_local is not None:
        if api_local != ssh_local:
            raise ProxmoxError(f"the API address reaches node {api_local}, but the SSH session is on {ssh_local}: they are not the same node. Nothing was kept.")
        return f"api and ssh agree: {api_local}"
    if t.seen_leaf == t.node_leaf:
        return "same certificate on both paths" + (" (different addresses)" if differs else "")
    raise ProxmoxError("cannot confirm that the API address reaches the same node as the SSH session (the new token cannot read /cluster/status and the "
                       "certificates differ). Nothing was kept; use the same address for both or a certificate the node itself serves.")


def _cluster(adm: A.SshAdmin) -> dict:
    st = adm.get("/cluster/status")
    name = next((x.get("name") for x in st if x.get("type") == "cluster"), None)
    nodes = [x for x in st if x.get("type") == "node"]
    local = next((x["name"] for x in nodes if x.get("local")), None)
    return {"name": name, "nodes": nodes, "local": local, "quorate": next((bool(x.get("quorate")) for x in st if x.get("type") == "cluster"), None)}


def _storage_usage(adm: A.SshAdmin) -> dict:
    """Thin-pool / ZFS usage of the CONNECTED node (display only; other nodes are not logged in to)."""
    from . import storageinfo as SI
    cfg = adm.get("/storage")
    out: dict = {"thin_pools": [], "zfs": [], "note": "Measured on the node you are connected to; storage on other nodes is not read."}
    try:
        raw = adm.optional_text(T.lvs_report())
        if raw:
            out["thin_pools"] = SI.thin_pools(SI.parse_lvs(raw), cfg)
        z = adm.optional_text(T.zfs_list())
        if z and any(s.get("type") == "zfspool" for s in cfg):
            out["zfs"] = SI.zfs_pools(z, cfg)
    except ProxmoxError as e:
        out["error"] = str(e)[:120]
    return out


def _overview(adm: A.SshAdmin, facts: pp.Facts, cl: dict) -> dict:
    from . import storageinfo as SI
    nodes = adm.get("/nodes")
    ips = {n["name"]: n.get("ip") for n in cl["nodes"]}
    guests = facts.guests.values()
    return {
        "cluster_name": cl["name"], "connected_node": cl["local"], "pve_version": facts.version, "pve_major": facts.major, "quorate": cl["quorate"],
        "nodes": [{"name": n["node"], "status": n.get("status"), "ip": ips.get(n["node"]), "local": n["node"] == cl["local"]} for n in nodes],
        "storages": [{"name": k, "type": v["type"], "shared": v["shared"], "content": v["content"], "nodes": v["nodes"]} for k, v in sorted(facts.storages.items())],
        "networks": [{"name": k, "zone": z, "nodes": sorted(facts.bridge_nodes.get(k, []))} for k, z in sorted(facts.networks.items())],
        "pools": sorted(facts.pools),
        "templates": [{"vmid": v, "name": g.get("name"), "node": g.get("node")} for v, g in sorted(facts.guests.items()) if g.get("template")],
        "guests": {"total": len(facts.guests), "running": sum(1 for g in guests if g.get("status") == "running"),
                   "templates": sum(1 for g in guests if g.get("template")), "managed_by_ics": sum(1 for g in guests if "ou-managed" in (g.get("tags") or "").split(";"))},
        "existing": {"service_user": any(u.startswith(SERVICE_USER + "@") for u in facts.users),
                     "roles": sorted(r for r in facts.roles if r.startswith("OfficeUnbound")), "pools": sorted(p for p in facts.pools if p.startswith("officeunbound"))},
        "storage_usage": _storage_usage(adm), "firewall": SI.firewall_state(adm, [n["node"] for n in nodes]),
        "notes": facts.notes[:10],
    }


# ---------------------------------------------------------------------------------------------------- discover
@prov.safe
def exec_discover(rt: Runtime, db: Session, m: SshDiscover, plan, known: list[str]) -> dict:
    r = S.live(db, m.ssh_session_id)
    if str(r.created_by) != str(plan.requested_by) or str(r.customer_id) != str(plan.customer_id):
        raise ProxmoxError("SSH session does not belong to this plan's requester/customer")
    adm = _connect(rt, db, r, known, f"job:{plan.id}")
    try:
        t = _trust(rt, r, adm)
        facts = pp.collect_facts(adm)
        cl = _cluster(adm)
        ov = _overview(adm, facts, cl)
        db.execute(text("UPDATE ssh_sessions SET api_cert_ssh = :a, api_cert_seen = :b, api_cert_pinned = :p, api_trust = :t, api_ca_pem = :c, api_proxy = :x WHERE id = :i"),
                   {"a": t.node_leaf, "b": t.seen_leaf, "p": t.leaf_pin, "t": t.mode, "c": t.ca_pem, "x": "pending" if t.needs_confirmation else "none", "i": str(r.id)})
        audit.append(db, "ssh.discovered", actor_name="worker", resource="ssh_session", resource_id=str(r.id),
                     details={"host": r.host, "commands": sorted(set(adm.executed)), "api_trust": t.mode, "node_leaf": t.node_leaf, "seen_leaf": t.seen_leaf,
                              "needs_confirmation": t.needs_confirmation, "cluster": cl["name"], "nodes": len(ov["nodes"])})
        return {"overview": ov, "api_certificate": {"url": _api_url(r), "mode": t.mode, "explanation": t.explanation, "node_leaf": t.node_leaf, "seen_leaf": t.seen_leaf,
                                                    "ca_sha256": t.ca_sha256(), "needs_confirmation": t.needs_confirmation,
                                                    "cross_check": "proxy" if t.needs_confirmation else "match"}}
    finally:
        adm.discard()


# ---------------------------------------------------------------------------------------------------- plan computation (shared by preview and onboard)
def _compute(rt: Runtime, db: Session, adm: A.SshAdmin, r, policy: Policy, ep, ident_pub: tuple[str, str], account: str, from_addr: str | None):
    facts = pp.collect_facts(adm)
    cl = _cluster(adm)
    managed = prov._managed(db, ep)
    blocked_extra: list[str] = []
    if policy.service_user != SERVICE_USER and ep is None:
        blocked_extra.append(f"the service user must be named '{SERVICE_USER}' for SSH onboarding")
    local = cl["local"]
    if policy.mode() == "single_node" and local not in policy.scope.nodes:
        blocked_extra.append(f"single-node scope: this SSH session is on {local}, which is not the selected node; the ICS's SSH identity is only installed "
                             f"on the node it is limited to. Connect to {', '.join(policy.scope.nodes)} instead")
    pl = pp.plan_for(policy, facts, managed=managed, mode="A")
    pl.blocked += blocked_extra
    d = pp.design_from_plan(pl, policy)
    rotates: list[str] = []
    for s in pl.steps:
        if s.kind == "token" and s.op == "noop":      # existing ICS-managed token: rotate it (a secret can only be captured at creation)
            s.op = "create"
            s.reason = "existing ICS-managed token is rotated (delete + create) so its new secret can be captured into the vault"
            rotates.append(s.target)
    pd = pl.to_dict()
    ident = A.build_identity(account, local or "", ident_pub[0], ident_pub[1], d.userid, list(d.tokens.values()), [n for n, _ in d.roles.values()], from_addr)
    dry = A.DryAdmin(bool(r.use_sudo))
    for t in rotates:
        u, _, n = t.partition("!")
        dry.token_delete(u, n)
    if not pl.blocked:
        pp.apply_plan(dry, pl, d)
    lines = dry.lines()
    lines.append(T.account_exists(account).line(True))
    lines += [c.line(True) for c in A.install_commands(ident)]
    ssh = {"host": r.host, "port": r.port, "username": r.username, "sudo": bool(r.use_sudo), "host_key_algo": r.hk_algo, "host_key": r.hk_pinned,
           **_bind_trust(r)}
    bind = {"plan_hash": pd["plan_hash"], "ssh": ssh, "commands": lines, "identity": ident.summary(), "rotates": rotates}
    bind_hash = hashlib.sha256(audit.canon(bind).encode()).hexdigest()
    return pl, d, pd, facts, cl, ident, rotates, lines, bind, bind_hash


@prov.safe
def exec_preview(rt: Runtime, db: Session, m: SshPreview, plan, known: list[str]) -> dict:
    r = S.live(db, m.ssh_session_id)
    if str(r.created_by) != str(plan.requested_by) or str(r.customer_id) != str(plan.customer_id):
        raise ProxmoxError("SSH session does not belong to this plan's requester/customer")
    if not (r.api_trust and r.api_proxy != "pending"):
        raise ProxmoxError("run discovery first")
    policy = m.policy
    if policy.service_user == "ics-svc":     # the generic default: SSH onboarding creates its own, clearly named account
        policy = policy.model_copy(update={"service_user": SERVICE_USER})
    ep = prov._ep(db, m.endpoint_id) if m.endpoint_id else None
    pem, pub, key_fp = A.generate_keypair()
    adm = _connect(rt, db, r, known, f"job:{plan.id}")
    try:
        _recheck(rt, r, adm)
        pl, d, pd, facts, cl, ident, rotates, lines, bind, bind_hash = _compute(rt, db, adm, r, policy, ep, (pub, key_fp), m.account, m.ics_address)
    finally:
        adm.discard()
    key_cred = str(uuid.uuid4())
    cred_service.create(db, rt, provider=S.PROVIDER, customer_id=r.customer_id, label=f"ICS SSH identity {ident.node}", credential_type="ssh_key",
                        purpose="temporary_provisioning", secret=pem, identity=f"{m.account}@{ident.node}", host=r.host, expires_at=r.expires_at,
                        actor="worker", reason=f"generated for SSH onboarding preview (plan {plan.id})", cred_id=key_cred)
    del pem
    data = {"purpose": "ssh_onboard", "ssh_session_id": str(r.id), "plan": pd, "policy": policy.model_dump(mode="json"), "commands": lines, "bind": bind,
            "identity": {**ident.summary(), "key_credential_id": key_cred, "pub_line": pub}, "name": m.name, "endpoint_id": str(m.endpoint_id) if m.endpoint_id else None,
            "rotates": rotates, "account": m.account, "ics_address": m.ics_address}
    aid = prov._save_artifact(db, "plan", m.endpoint_id, bind_hash, data, plan.requested_by, plan.customer_id)
    audit.append(db, "provider.ssh.previewed", actor_name="worker", resource="plan", resource_id=str(plan.id),
                 details={"preview_id": aid, "bind_hash": bind_hash, "plan_hash": pd["plan_hash"], "blocked": pd["blocked"], "commands": len(lines),
                          "ssh_key_fingerprint": key_fp, "helper_sha256": A.sha(ident.helper)})
    return {"preview_id": aid, "bind_hash": bind_hash, "risk": "high", "approvals_required": rt.settings.required_approvals_high, "plan": pd, "commands": lines, "identity": ident.summary(), "ssh": bind["ssh"],
            "rotates": rotates, "blocked": pd["blocked"], "overview": _overview_safe(facts, cl),
            "widening_note": "Widening this access later (more nodes or privileges) needs an administrator's credentials again, or a Mode B package: "
                             "the ICS's own identities can only read, rotate their own token and narrow their own ACLs."}


def _overview_safe(facts: pp.Facts, cl: dict) -> dict:
    return {"cluster_name": cl["name"], "connected_node": cl["local"], "nodes": sorted(facts.nodes)}


# ---------------------------------------------------------------------------------------------------- onboard
def _helper_verify(rt: Runtime, r, ident: A.NodeIdentity, key_cred_id: str, known: list[str]) -> dict:
    """The new identity must work AND be unable to do anything else."""
    pem = cred_service.get_secret(rt, key_cred_id, use="ssh.identity.verify", actor="provisioning")
    known.append(pem)
    try:
        h = A.HelperClient(r.host, r.port, ident.account, S.pinned_key(r), pem)
    except SshError as e:
        raise ProxmoxError("the ICS's new SSH identity cannot log in: " + str(e)) from None
    finally:
        del pem
    try:
        chk = h.self_check()
        if chk["helper_sha256"] != A.sha(ident.helper) or chk["conf_sha256"] != A.sha(ident.conf):
            raise ProxmoxError("the installed helper or its configuration does not match the approved hashes")
        refused = []
        for probe in ("id", "sh -c id", "bash", "cat /etc/shadow", "discover ../../etc/passwd", "discover nodes; id", "pveum user add x@pve", "acl-narrow / PVEAdmin root@pam"):
            res = h.s.run_raw(probe)
            if res.rc != 126:
                raise ProxmoxError(f"the ICS's SSH identity was able to run a command outside the allowlist ({probe.split()[0]}): rolling back")
            refused.append(probe.split()[0])
        return {"helper_sha256": chk["helper_sha256"], "conf_sha256": chk["conf_sha256"], "probes_refused": len(refused)}
    finally:
        h.close()


@prov.safe
def exec_onboard(rt: Runtime, db: Session, m: SshOnboard, plan, known: list[str]) -> dict:
    r = S.live(db, m.ssh_session_id)
    if str(r.created_by) != str(plan.requested_by) or str(r.customer_id) != str(plan.customer_id):
        raise ProxmoxError("SSH session does not belong to this plan's requester/customer")
    art = _artifact(db, m.preview_id)
    if art is None or art.plan_hash != m.bind_hash or art.data.get("purpose") != "ssh_onboard":
        raise ProxmoxError("the approved preview is missing or does not match the approved hash")
    ep = prov._ep(db, m.endpoint_id) if m.endpoint_id else None
    stored = prov._stored(db, ep.id) if ep else None
    policy = Policy.model_validate(art.data["policy"])
    idata = art.data["identity"]
    adm = None
    res = None
    ident = None
    installed = False
    rolled = False
    try:
        adm = _connect(rt, db, r, known, f"job:{plan.id}")
        t = _recheck(rt, r, adm)
        ca, fp = TR.trust_args(t)
        pl, d, pd, facts, cl, ident, rotates, lines, bind, bind_hash = _compute(
            rt, db, adm, r, policy, ep, (idata["pub_line"], idata["key_fingerprint"]), art.data["account"], art.data.get("ics_address"))
        if bind_hash != m.bind_hash or pl.blocked:
            raise ProxmoxError("the cluster or the SSH binding changed since the plan was previewed and approved (the commands differ): nothing was applied; preview again")
        for t in rotates:
            u, _, n = t.partition("!")
            adm.token_delete(u, n)
        res = pp.apply_plan(adm, pl, d)
        A.install_identity(adm, ident)
        installed = True
        A.verify_files(adm, ident)
        verification = prov._verify_all(rt, _api_url(r), ca, fp, policy, d, dict(res.secrets), facts, known)
        node_check = _same_node(rt, r, t, dict(res.secrets), cl["local"])
        if not verification["ok"]:
            raise ProxmoxError("verification of the resulting permissions failed: " + prov._problem(verification))
        hv = _helper_verify(rt, r, ident, idata["key_credential_id"], known)
        eid = str(ep.id) if ep else prov._register(rt, db, m_named(m, r), plan, known, ep, _api_url(r), ca, fp, policy, dict(res.secrets), d)
        mg = prov._merge_managed(dict(stored.managed) if stored else {}, res)
        prov._upsert_policy(db, eid, policy, pd, pp.stored_design(pl), "A", mg, prov._token_state(d, {k: v.get("gen", 1) + 1 for k, v in (stored.tokens if stored else {}).items()}), verification)
        db.execute(text("UPDATE ssh_identities SET removed_at = now() WHERE endpoint_id = :e AND removed_at IS NULL"), {"e": eid})
        db.execute(text("INSERT INTO ssh_identities (endpoint_id, customer_id, credential_id, host, port, account, node, hostkey_algo, hostkey_fp, key_fp, helper_sha256, "
                        "conf_sha256, sudoers_sha256, authorized_line) VALUES (:e, :c, :cr, :h, :p, :a, :n, :ha, :hf, :kf, :hs, :cs, :ss, :al) "
                        "ON CONFLICT (endpoint_id) DO UPDATE SET customer_id = EXCLUDED.customer_id, credential_id = EXCLUDED.credential_id, host = EXCLUDED.host, "
                        "port = EXCLUDED.port, account = EXCLUDED.account, node = EXCLUDED.node, hostkey_algo = EXCLUDED.hostkey_algo, hostkey_fp = EXCLUDED.hostkey_fp, "
                        "key_fp = EXCLUDED.key_fp, helper_sha256 = EXCLUDED.helper_sha256, conf_sha256 = EXCLUDED.conf_sha256, sudoers_sha256 = EXCLUDED.sudoers_sha256, "
                        "authorized_line = EXCLUDED.authorized_line, installed_at = now(), removed_at = NULL"),
                   {"e": eid, "c": str(r.customer_id), "cr": idata["key_credential_id"], "h": r.host, "p": r.port, "a": ident.account, "n": ident.node, "ha": r.hk_algo,
                    "hf": r.hk_pinned, "kf": ident.key_fp, "hs": A.sha(ident.helper), "cs": A.sha(ident.conf), "ss": A.sha(ident.sudoers), "al": ident.authorized_line})
        db.execute(text("UPDATE credentials SET purpose = 'provision', expires_at = NULL, label = :l WHERE id = :i AND provider = :p"),
                   {"l": f"ICS SSH identity {ident.account}@{ident.node}", "i": idata["key_credential_id"], "p": S.PROVIDER})
        audit.append(db, "provider.ssh.onboarded", actor_name="worker", resource="endpoint", resource_id=eid,
                     details={"bind_hash": m.bind_hash, "host": r.host, "port": r.port, "ssh_user": r.username, "host_key": r.hk_pinned, "api_trust": t.mode, "node_check": node_check,
                              "commands_run": adm.executed, "ssh_identity": {"account": ident.account, "key_fingerprint": ident.key_fp,
                                                                            "helper_sha256": A.sha(ident.helper), "node": ident.node},
                              "helper_verification": hv, "verification_ok": True, "admin_ssh_credential": "wiped"})
        S.wipe(db, r.id, "used", "worker", "onboarding job ended")       # same transaction as the result: the audit chain is single-writer
        return {"endpoint_id": eid, "bind_hash": m.bind_hash, "applied": res.log, "verification": prov._verif_public(verification), "ssh_identity": ident.summary(),
                "helper_verification": hv, "node_check": node_check, "api_trust": t.mode, "admin_ssh_credential": "wiped"}
    except BaseException:
        left: list[str] = []
        if adm is not None and not adm.discarded:
            try:
                if res is not None:
                    left += pp.rollback_created(adm, res)
                if ident is not None and installed:
                    left += A.remove_identity(adm, ident.account)
            except Exception:  # noqa: BLE001
                left.append("rollback itself failed")
        db.rollback()                       # release the audit-chain lock, then record the rollback and wipe the credential in an independent transaction
        with rt.session() as d2:
            audit.append(d2, "provider.ssh.rolled_back", actor_name="worker", resource="plan", resource_id=str(plan.id),
                         details={"created": res.log if res else [], "identity_removed": installed, "not_removed": left})
            S.wipe(d2, r.id, "used", "worker", "onboarding job failed")
            d2.commit()
        raise
    finally:
        if adm is not None:
            adm.discard()


def _wipe_independent(rt: Runtime, db: Session, sid, reason: str) -> None:
    db.rollback()
    with rt.session() as d2:
        S.wipe(d2, sid, "used", "worker", reason)
        d2.commit()


class _Named:
    def __init__(self, name, customer_id):
        self.name, self.customer_id = name, customer_id


def m_named(m: SshOnboard, r) -> _Named:
    return _Named(m.name, m.customer_id or r.customer_id)


# ---------------------------------------------------------------------------------------------------- offboard
@prov.safe
def exec_offboard(rt: Runtime, db: Session, m: SshOffboard, plan, known: list[str]) -> dict:
    r = S.live(db, m.ssh_session_id)
    if str(r.created_by) != str(plan.requested_by) or str(r.customer_id) != str(plan.customer_id):
        raise ProxmoxError("SSH session does not belong to this plan's requester/customer")
    ep = prov._ep(db, m.endpoint_id)
    st = prov._stored(db, ep.id)
    ident = _identity(db, ep.id)
    adm = _connect(rt, db, r, known, f"job:{plan.id}")
    done: list[str] = []
    left: list[str] = []
    try:
        mg = dict(st.managed) if st else {}
        pol = Policy.model_validate(st.policy) if st else None

        def step(label, fn):
            try:
                fn()
                done.append(label)
            except Exception as e:  # noqa: BLE001
                left.append(f"{label}: {str(e)[:100]}")
        for path, subj, role in reversed(mg.get("acl", [])):
            step(f"acl {path} {role}", lambda p=path, s=subj, ro=role: adm.acl_set(p, ro, **({"token": s} if "!" in s else {"user": s}), delete=True))
        for tid in mg.get("tokens", []):
            u, _, n = tid.partition("!")
            step(f"token {tid}", lambda u=u, n=n: adm.token_delete(u, n))
        if mg.get("user"):
            step(f"user {mg['user']}", lambda: adm.user_delete(mg["user"]))
        for ro in mg.get("roles", []):
            step(f"role {ro}", lambda ro=ro: adm.role_delete(ro))
        if m.delete_pool:
            used = {g.get("pool") for g in pp.collect_facts(adm).guests.values()}
            for pool in mg.get("pools", []):
                if pool in used:
                    left.append(f"pool {pool}: not empty, kept")
                else:
                    step(f"pool {pool}", lambda pool=pool: adm.pool_delete(pool))
        if ident is not None:
            left += [f"node: {x}" for x in A.remove_identity(adm, ident.account)]
            done.append(f"node identity {ident.account} (user, key, helper, config, sudoers)")
        for role in ("inventory", "provision"):
            cred_service.release_endpoint_role(db, ep, role, actor="provider.ssh_offboard", reason="integration offboarded")
        if ident is not None:
            c = cred_service.get_row(db, ident.credential_id)
            if c is not None and c.purged_at is None:
                cred_service.revoke(db, ident.credential_id, actor="provider.ssh_offboard", reason="ICS SSH identity removed")
            db.execute(text("UPDATE ssh_identities SET removed_at = now() WHERE endpoint_id = :e"), {"e": str(ep.id)})
        db.execute(text("UPDATE endpoints SET enabled = false, token_secret_enc = '\\x'::bytea, provision_token_id = NULL, provision_secret_enc = NULL WHERE id = :i"), {"i": str(ep.id)})
        db.execute(text("UPDATE endpoint_policy SET status = 'revoked', updated_at = now() WHERE endpoint_id = :i"), {"i": str(ep.id)})
        audit.append(db, "provider.ssh.offboarded", actor_name="worker", resource="endpoint", resource_id=str(ep.id),
                     details={"removed": done, "not_removed": left, "commands_run": adm.executed, "pool_policy": "only empty pools the ICS created" if m.delete_pool else "kept",
                              "admin_ssh_credential": "wiped"})
        S.wipe(db, r.id, "used", "worker", "offboarding job ended")
        return {"endpoint_id": str(ep.id), "removed": done, "not_removed": left, "endpoint": "disabled", "admin_ssh_credential": "wiped"}
    except BaseException:
        _wipe_independent(rt, db, r.id, "offboarding job failed")
        raise
    finally:
        adm.discard()


# ---------------------------------------------------------------------------------------------------- the ICS's own identity
def _helper_for(rt: Runtime, db: Session, eid, known: list[str]) -> A.HelperClient:
    i = _identity(db, eid)
    if i is None:
        raise ProxmoxError("this endpoint has no ICS SSH identity")
    check_destination(i.host, rt.settings.allow_loopback_endpoints)
    pem = cred_service.get_secret(rt, i.credential_id, use="ssh.helper", actor="ics")
    known.append(pem)
    try:
        return A.HelperClient(i.host, i.port, i.account, HostKey(i.hostkey_algo, i.hostkey_fp), pem)
    except SshError as e:
        raise ProxmoxError(str(e)) from None


@prov.safe
def exec_helper(rt: Runtime, db: Session, m: SshHelper, plan, known: list[str]) -> dict:
    h = _helper_for(rt, db, m.endpoint_id, known)
    try:
        if m.op == "self-check":
            out = h.self_check()
        elif m.op == "discover":
            out = {"result": h.discover(m.kind, m.node)}
        elif m.op == "drift":
            out = {"permissions": h.drift()}
        else:
            out = {"certificate_sha256": A.leaf_fingerprint(h.cert())}
    finally:
        h.close()
    audit.append(db, "provider.ssh.helper", actor_name="worker", resource="endpoint", resource_id=str(m.endpoint_id), details={"op": m.op, "kind": m.kind})
    return out


@prov.safe
def exec_narrow(rt: Runtime, db: Session, m: SshNarrow, plan, known: list[str]) -> dict:
    h = _helper_for(rt, db, m.endpoint_id, known)
    try:
        out = h.acl_narrow(m.path, m.role, m.subject)
    finally:
        h.close()
    st = prov._stored(db, m.endpoint_id)
    if st is not None:
        mg = dict(st.managed)
        mg["acl"] = [a for a in mg.get("acl", []) if a != [m.path, m.subject, m.role]]
        db.execute(text("UPDATE endpoint_policy SET managed = CAST(:m AS jsonb), updated_at = now() WHERE endpoint_id = :e"), {"m": json.dumps(mg), "e": str(m.endpoint_id)})
    audit.append(db, "provider.ssh.narrowed", actor_name="worker", resource="endpoint", resource_id=str(m.endpoint_id), details={"path": m.path, "role": m.role, "subject": m.subject})
    return out


EXECUTORS = {"provider.ssh.discover": exec_discover, "provider.ssh.preview": exec_preview, "provider.ssh_onboard": exec_onboard,
             "provider.ssh_offboard": exec_offboard, "provider.ssh.helper": exec_helper, "provider.ssh.narrow": exec_narrow}
