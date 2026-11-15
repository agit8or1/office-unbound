"""Provider adapter interface (ADR-0009 section 2). MINIMAL STAND-IN written by the deployment-engine branch with exactly the ADR
signatures; the provider branch owns the real module and its version wins at merge. Pure infrastructure verbs: no Office Unbound
knowledge here."""
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol


@dataclass(frozen=True)
class VmRef:
    node: str
    vmid: int


@dataclass(frozen=True)
class TaskRef:
    id: str
    node: str
    vmid: int | None = None


@dataclass
class TaskStatus:
    state: Literal["running", "ok", "failed"]
    message: str = ""
    progress: int = 0


@dataclass
class DiskSpec:
    name: str
    size_gb: int
    storage: str


@dataclass
class NicSpec:
    bridge: str
    vlan: int | None = None


@dataclass
class VmCloneSpec:
    name: str
    template: str
    node: str
    pool: str
    storage: str
    tags: list[str] = field(default_factory=list)


@dataclass
class VmConfigSpec:
    cores: int
    memory_mb: int
    disks: list[DiskSpec] = field(default_factory=list)
    nics: list[NicSpec] = field(default_factory=list)
    cloud_init: dict[str, Any] = field(default_factory=dict)


@dataclass
class GuestInfo:
    vmid: int
    node: str
    name: str
    kind: Literal["vm", "lxc"] = "vm"
    status: str = "unknown"
    tags: list[str] = field(default_factory=list)


@dataclass
class ProbeResult:
    ok: bool
    version: str = ""
    cluster: str = ""
    permissions: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class Discovery:
    nodes: list[dict] = field(default_factory=list)
    storage: list[dict] = field(default_factory=list)
    networks: list[dict] = field(default_factory=list)
    guests: list[GuestInfo] = field(default_factory=list)
    templates: list[dict] = field(default_factory=list)


@dataclass
class Sample:
    scope: str
    id: str
    metric: str
    ts: float
    value: float


class Provider(Protocol):
    kind: str

    def probe(self) -> ProbeResult: ...
    def discover(self) -> Discovery: ...
    def metrics(self, scope: str, since: float, step: int) -> list[Sample]: ...
    def clone_vm(self, spec: VmCloneSpec) -> TaskRef: ...
    def configure_vm(self, ref: VmRef, spec: VmConfigSpec) -> TaskRef: ...
    def resize_disk(self, ref: VmRef, disk: str, new_size_gb: int) -> TaskRef: ...
    def power(self, ref: VmRef, op: Literal["start", "shutdown", "stop", "reboot"]) -> TaskRef: ...
    def snapshot(self, ref: VmRef, name: str) -> TaskRef: ...
    def rollback(self, ref: VmRef, name: str) -> TaskRef: ...
    def migrate(self, ref: VmRef, target_node: str, online: bool) -> TaskRef: ...
    def destroy_vm(self, ref: VmRef) -> TaskRef: ...
    def task_status(self, task: TaskRef) -> TaskStatus: ...
