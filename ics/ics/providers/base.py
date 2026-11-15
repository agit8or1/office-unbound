"""Provider adapter interface (ADR-0009 §2). Other packages (deploy/, inventory/) import ONLY from here.

Structural rule: mutating verbs live on `Provider` implementations obtained through a *mutations factory* that
refuses to run outside job execution (`job_execution()` context, entered only by the job runner). Read-only
objects (`ReadProvider`) have no mutating method at all, so a request handler cannot call one by accident.
"""
from __future__ import annotations

import contextlib
import contextvars
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, Protocol, runtime_checkable


class ProviderError(Exception):
    """Operator-readable failure. `code` is stable for programmatic handling; `message` never contains secrets."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


class ScopeViolation(ProviderError):
    """A mutation was refused because the target is outside the endpoint's allowed pool/storage/network/ownership."""

    def __init__(self, message: str):
        super().__init__("scope_violation", message)


class MutationNotAllowed(ProviderError):
    def __init__(self, message: str):
        super().__init__("mutation_not_allowed", message)


class ProviderTimeout(ProviderError):
    def __init__(self, message: str):
        super().__init__("timeout", message)


# ---- value types ------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Scope:
    type: Literal["node", "guest", "storage"]
    node: str | None = None       # node name (node/guest scopes)
    vmid: int | None = None       # guest scope
    kind: Literal["vm", "lxc"] = "vm"
    name: str | None = None       # storage scope


@dataclass(frozen=True)
class Sample:
    scope_type: str
    scope_key: str                # node name | vmid as text | storage name
    metric: str                   # cpu_pct, mem_used_bytes, mem_total_bytes, net_in_bps, net_out_bps, disk_read_bps, disk_write_bps, load1, ...
    ts: datetime                  # tz-aware UTC
    value: float


@dataclass(frozen=True)
class VmRef:
    node: str
    vmid: int
    kind: Literal["vm", "lxc"] = "vm"
    deployment_id: str | None = None   # ownership tag `ou-deployment-<id>` must be present on the guest before any modification


@dataclass(frozen=True)
class TaskRef:
    node: str
    upid: str | None              # None = the change completed synchronously (nothing to poll)
    vmid: int | None = None
    kind: str = "task"            # what the task does (qmclone, qmstart, ...)
    deployment_id: str | None = None


@dataclass(frozen=True)
class TaskStatus:
    state: Literal["running", "ok", "error"]
    exitstatus: str | None = None
    message: str | None = None    # operator-readable, sanitized


@dataclass(frozen=True)
class VmCloneSpec:
    template_vmid: int
    template_node: str
    new_vmid: int | None          # None = ask the cluster for the next free id
    name: str
    pool: str
    storage: str                  # target storage for a full clone (linked clones stay on the template's storage)
    deployment_id: str
    full: bool = True
    target_node: str | None = None


@dataclass(frozen=True)
class NicSpec:
    index: int
    bridge: str
    vlan: int | None = None
    model: Literal["virtio", "e1000", "vmxnet3"] = "virtio"
    firewall: bool = True


@dataclass(frozen=True)
class IpConfig:
    index: int
    ip: str                       # "dhcp" or CIDR
    gw: str | None = None


@dataclass(frozen=True)
class VmConfigSpec:
    cores: int | None = None
    memory_mb: int | None = None
    nics: tuple[NicSpec, ...] = ()
    new_disks: tuple[tuple[str, str, int], ...] = ()      # (disk key e.g. "scsi1", storage, size_gb)
    cloudinit_storage: str | None = None                   # attach a cloud-init drive on this storage
    ciuser: str | None = None
    sshkeys: tuple[str, ...] = ()
    ipconfigs: tuple[IpConfig, ...] = ()
    nameserver: str | None = None
    searchdomain: str | None = None
    cicustom: str | None = None                            # "user=<storage>:snippets/<file>"; refused unless the endpoint allows it
    description: str | None = None


@dataclass
class VerbCheck:
    verb: str
    ok: bool
    missing: list[dict] = field(default_factory=list)      # [{"path": "/pool/x", "privileges": ["VM.Allocate"]}]
    note: str | None = None


@dataclass
class ProbeResult:
    ok: bool
    version: str | None = None
    release: str | None = None
    cluster_name: str | None = None
    quorate: bool | None = None
    nodes: int | None = None
    tls: dict = field(default_factory=dict)                # {"ok": bool, "trust": "fingerprint"|"ca_bundle", "error"?: str}
    credentials: dict = field(default_factory=dict)        # {"inventory": {"authenticated": bool}, "provision": {...}}
    verbs: list[VerbCheck] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    capabilities: list[dict] = field(default_factory=list)   # [{"name","ok","blocking","detail"}] e.g. cloud-init snippets, template import
    discovery: dict | None = None                            # setup wizard: normalized snapshot (only when requested)
    self_vm: dict | None = None                              # the ICS's own VM if found: {"vmid","node","mutable","privileges"}
    simulator: bool = False


@dataclass
class Discovery:
    clusters: list[dict] = field(default_factory=list)
    nodes: list[dict] = field(default_factory=list)
    storage: list[dict] = field(default_factory=list)
    networks: list[dict] = field(default_factory=list)
    guests: list[dict] = field(default_factory=list)
    templates: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    complete: set[str] = field(default_factory=set)        # entity kinds fetched without error (safe to prune stale rows for)


# ---- interfaces --------------------------------------------------------------------------------------------------

@runtime_checkable
class ReadProvider(Protocol):
    kind: str

    def probe(self) -> ProbeResult: ...
    def discover(self) -> Discovery: ...
    def metrics(self, scope: Scope, since: datetime, step: int) -> list[Sample]: ...
    def task_status(self, task: TaskRef) -> TaskStatus: ...


@runtime_checkable
class Provider(ReadProvider, Protocol):
    """ReadProvider + the mutation verbs of ADR-0009 §2. Implementations are handed out only to job execution."""

    def clone_vm(self, spec: VmCloneSpec) -> TaskRef: ...
    def configure_vm(self, ref: VmRef, spec: VmConfigSpec) -> TaskRef: ...
    def resize_disk(self, ref: VmRef, disk: str, new_size_gb: int) -> TaskRef: ...
    def power(self, ref: VmRef, op: Literal["start", "shutdown", "stop", "reboot"]) -> TaskRef: ...
    def snapshot(self, ref: VmRef, name: str) -> TaskRef: ...
    def rollback(self, ref: VmRef, name: str) -> TaskRef: ...
    def migrate(self, ref: VmRef, target_node: str, online: bool) -> TaskRef: ...
    def destroy_vm(self, ref: VmRef) -> TaskRef: ...


# ---- structural "mutations only from job execution" guard -------------------------------------------------------

_JOB: contextvars.ContextVar[str | None] = contextvars.ContextVar("ics_job_execution", default=None)


@contextlib.contextmanager
def job_execution(job_id: str):
    """Entered by the job runner (actions.run_job) around executor code. Request handlers never enter it."""
    tok = _JOB.set(str(job_id))
    try:
        yield
    finally:
        _JOB.reset(tok)


def current_job() -> str | None:
    return _JOB.get()


def require_job_execution() -> str:
    j = _JOB.get()
    if j is None:
        raise MutationNotAllowed("provider mutations are only available from job execution")
    return j
