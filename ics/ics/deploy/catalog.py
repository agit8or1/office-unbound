"""Deployment catalog (ADR-0009 section 4): component + profile definitions loaded from blueprints/catalog/*.yaml and
validated with pydantic. Pure data; nothing here touches infrastructure.

Schema documentation: blueprints/catalog/README.md
"""
import graphlib
import hashlib
import os
import re
from decimal import ROUND_CEILING, Decimal
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

NAME = r"^[a-z][a-z0-9-]{0,40}$"
SEMVER = r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$"
DIGEST_RE = re.compile(r"^sha256:([0-9a-f]{64})?$")  # "sha256:" alone is the explicit placeholder (unpinned)
PIN_RE = r"^[A-Za-z0-9][A-Za-z0-9.+~:_-]{0,63}$"
Exposure = Literal["local", "internal", "edge", "public", "ics"]
CheckKind = Literal["http", "tcp_tls", "smtp_banner", "sip_options_tls", "jitsi_jwt"]  # kinds that need no stored password (checks.py)


class CatalogError(Exception):
    pass


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Formula(_M):
    """value(users) = ceil(base + per_user * users). `source` (evidence or 'assumption') is mandatory."""
    base: float = Field(ge=0)
    per_user: float = Field(ge=0)
    source: str = Field(min_length=3, max_length=400)

    def at(self, users: int) -> int:
        v = Decimal(str(self.base)) + Decimal(str(self.per_user)) * users
        return int(v.to_integral_value(rounding=ROUND_CEILING))


class UnitVolume(_M):
    name: str = Field(pattern=r"^[a-z][a-z0-9-]{0,30}[a-z0-9]$")
    path: str = Field(pattern=r"^/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+){0,6}$")
    read_only: bool = False


class UnitSecret(_M):
    name: str = Field(pattern=r"^[a-z][a-z0-9-]{1,40}$", description="an EXISTING podman secret on the node (secret values never pass through the catalog or the plan)")
    env: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")


class OciUnit(_M):
    """How the container unit is configured on the node: the closed `podman.deploy_unit` shape of the agent (agent/ou_agent/guestspec.py check_deploy), so
    the plan carries exactly what the unit needs and nothing the agent would refuse. `{domain}` in an env value is replaced by the customer's domain.
    Values here are configuration, never secrets (secrets are named podman secrets)."""
    type: Literal["container", "container-hostnet"] = "container"
    env: dict[Annotated[str, Field(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")], Annotated[str, Field(pattern=r"^[A-Za-z0-9_./:@,+={}-]{0,256}$")]] = {}
    secrets: list[UnitSecret] = Field(default=[], max_length=8)
    volumes: list[UnitVolume] = Field(default=[], max_length=8)
    memory_mib: int = Field(default=512, ge=16, le=65536)
    read_only: bool = True
    user: str | None = Field(default=None, pattern=r"^[0-9]{1,5}(:[0-9]{1,5})?$")
    command: list[Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{0,30}$")]] = Field(default=[], max_length=4)   # entrypoint words (agent >= 0.5.0)
    capabilities: list[Literal["SYS_CHROOT"]] = Field(default=[], max_length=1)   # given back after DropCapability=ALL (agent >= 0.5.0-ou9)


class OciArtifact(_M):
    name: str = Field(pattern=NAME)
    kind: Literal["oci"]
    image: str = Field(pattern=r"^[a-z0-9][a-z0-9.:/_-]{2,200}$")
    digest: str = Field(description="sha256:<64 hex>, or exactly 'sha256:' as an explicit unpinned placeholder")
    version: str = Field(pattern=PIN_RE)
    unit: OciUnit | None = Field(default=None, description="node-side configuration of the container unit (env, volumes, named secrets, host networking); absent = bare unit with the component ports")
    signed: bool = Field(default=True, description="false = digest is pinned but the image has NOT been signed through the hardened signing path; plans containing it are refused (artifact_unsigned)")

    @field_validator("digest")
    @classmethod
    def _digest(cls, v: str) -> str:
        if not DIGEST_RE.match(v):
            raise ValueError("digest must be 'sha256:' + 64 lowercase hex (or the bare placeholder 'sha256:')")
        return v

    @property
    def pinned(self) -> bool:
        return len(self.digest) > len("sha256:")


class PackageArtifact(_M):
    name: str = Field(pattern=NAME)
    kind: Literal["package"]
    package: str = Field(pattern=r"^[a-z0-9][a-z0-9.+-]{1,80}$")
    version: str = Field(pattern=PIN_RE, description="exact pinned version; 'latest' / ranges are rejected")
    repo: Literal["ob-apt-stable", "ob-apt-staging", "ob-apt-dev", "ubuntu-noble", "debian-bookworm"]

    @field_validator("version")
    @classmethod
    def _pinned(cls, v: str) -> str:
        if v in ("latest", "*") or any(c in v for c in "^~<>="):
            raise ValueError("version must be an exact pin")
        return v

    @property
    def pinned(self) -> bool:
        return True


Artifact = Annotated[OciArtifact | PackageArtifact, Field(discriminator="kind")]


class Resources(_M):
    cores: Formula
    memory_mb: Formula
    disk_gb: Formula


class Volume(_M):
    name: str = Field(pattern=NAME)
    path: str = Field(pattern=r"^/[A-Za-z0-9_./-]{1,100}$")
    size_gb: Formula
    backup: bool = True


class Port(_M):
    name: str = Field(pattern=NAME)
    port: int = Field(ge=1, le=65535)
    proto: Literal["tcp", "udp"] = "tcp"
    exposure: Exposure
    port_end: int | None = Field(default=None, ge=1, le=65535, description="last port of a range (e.g. RTP 10000-10200); None = single port")
    default_enabled: bool = Field(default=True, description="False = declared but closed unless the plan input enables it (enabled_ports)")
    shared_with: list[str] = Field(default=[], description="components whose SAME process serves this port when placed on one VM (the nginx TLS "
                                                           "proxy: files' 443 and edge's 443); not a port conflict with them")

    @model_validator(mode="after")
    def _range(self) -> Self:
        if self.port_end is not None and self.port_end <= self.port:
            raise ValueError("port_end must be greater than port")
        return self

    @property
    def last(self) -> int:
        return self.port_end or self.port


class DnsRecord(_M):
    host: str = Field(pattern=r"^(@|[a-z0-9][a-z0-9-]{0,62})$")
    type: Literal["A", "CNAME", "MX", "TXT"]
    target: str = Field(max_length=200)


class HealthCheck(_M):
    name: str = Field(pattern=NAME)
    kind: CheckKind
    port: int = Field(ge=1, le=65535)
    path: str | None = Field(default=None, pattern=r"^/[A-Za-z0-9_./?=&%-]{0,200}$")
    expect_status: int = Field(default=200, ge=100, le=599)
    body_contains: str | None = Field(default=None, max_length=200, description="http only: text the response body must contain")
    interval_seconds: int = Field(default=60, ge=5, le=86400)

    @model_validator(mode="after")
    def _chk(self) -> Self:
        if self.path and self.kind != "http":
            raise ValueError("path only applies to http checks")
        if self.body_contains and self.kind != "http":
            raise ValueError("body_contains only applies to http checks")
        return self


class BackupSpec(_M):
    method: Literal["online_dump", "logical_export", "tar_xattr", "config_tar", "stateless"]
    description: str = Field(max_length=300)
    quiesce: Literal["online", "stop_service"]
    rpo_hours: int = Field(ge=0, le=720)
    evidence: str = Field(min_length=3, max_length=300)


class Upgrade(_M):
    downtime_seconds: int = Field(ge=0, le=86400)


# ---- sizing model (sizing engine, docs/status/sizing-api.md) -----------------------------------------------------------
# Every number carries its evidence: `measured` (a lab measurement, cited in `source`) or `estimate` (a planning value; the engine
# adds the component's safety margin to it and labels it). Workload drivers are derived from the wizard's workload input.
Driver = Literal["total_user", "concurrent_user", "office_editor", "meeting_participant", "concurrent_call", "mailbox_gb", "file_gb"]
Evidence = Literal["measured", "estimate"]


class Factor(_M):
    per: Driver
    value: float = Field(ge=0)
    evidence: Evidence
    source: str = Field(min_length=3, max_length=400)


class ResourceModel(_M):
    """value = base + sum(factor.value * driver); estimate parts are multiplied by (1 + safety_margin_pct/100)."""
    base: float = Field(ge=0, description="fixed overhead")
    base_evidence: Evidence
    source: str = Field(min_length=3, max_length=400)
    factors: list[Factor] = []


class VolumeModel(ResourceModel):
    volume: str = Field(pattern=NAME, description="name of a volume declared by the component")


class ResAmount(_M):
    cores: int = Field(ge=0, le=256)
    memory_mb: int = Field(ge=0, le=1048576)
    disk_gb: int = Field(ge=0, le=65536)


class Consolidation(_M):
    group: str = Field(pattern=NAME, description="components with the same group share a VM in the 'balanced' architecture")
    isolation: Literal["none", "preferred", "required"] = Field(default="none", description="required = never shares a VM with another component")
    never_with: list[str] = Field(default=[], description="components that must not share a VM with this one")
    reason: str = Field(default="", max_length=300)


class HaStrategy(_M):
    id: Literal["stateless_active_active", "primary_replica", "multi_primary", "independent_instances", "vm_restart_shared_storage"]
    status: Literal["implemented", "designed", "not_supported"]
    note: str = Field(max_length=300)


class HaCapability(_M):
    min_replicas: int = Field(default=2, ge=2, le=5)
    strategies: list[HaStrategy] = []
    note: str = Field(max_length=400)

    @property
    def capable(self) -> bool:
        """Application-level HA exists only with an IMPLEMENTED replication strategy; VM restart/replicas alone are not application HA."""
        return any(s.status == "implemented" and s.id != "vm_restart_shared_storage" for s in self.strategies)


class Validated(_M):
    """What was actually exercised in a lab (never extrapolated): the engine reports workloads above this as unvalidated."""
    total_users: int | None = Field(default=None, ge=0)
    concurrent: int | None = Field(default=None, ge=0, description="concurrent units of `concurrent_metric`")
    concurrent_metric: Driver | None = None
    reference: str = Field(min_length=3, max_length=300)


class Sizing(_M):
    services: list[Annotated[str, Field(pattern=NAME)]] = Field(default=[], description="wizard service ids this component provides")
    core: bool = Field(default=False, description="always deployed (not selectable)")
    minimum: ResAmount = Field(description="floor for evaluation deployments")
    recommended: ResAmount = Field(description="floor for production deployments")
    cores: ResourceModel
    memory_mb: ResourceModel
    disk_gb: ResourceModel
    volumes: list[VolumeModel] = []
    safety_margin_pct: int = Field(default=30, ge=0, le=200, description="added to every ESTIMATE part")
    consolidation: Consolidation
    ha: HaCapability
    limitations: list[str] = []
    validated: Validated

    @model_validator(mode="after")
    def _floors(self) -> Self:
        m, r = self.minimum, self.recommended
        if r.cores < m.cores or r.memory_mb < m.memory_mb or r.disk_gb < m.disk_gb:
            raise ValueError("recommended must be >= minimum")
        return self


class Component(_M):
    name: str = Field(pattern=NAME)
    version: str = Field(pattern=SEMVER)
    title: str = Field(max_length=100)
    description: str = Field(max_length=500)
    placement: Literal["normal", "every_vm"] = "normal"
    artifacts: list[Artifact] = Field(min_length=1)
    resources: Resources
    volumes: list[Volume] = []
    ports: list[Port] = []
    depends_on: list[str] = []
    after: list[str] = []
    dns: list[DnsRecord] = []
    health_checks: list[HealthCheck] = []
    backup: BackupSpec
    upgrade: Upgrade
    notices: list[str] = Field(default=[], description="plain-language caveats; every plan containing the component lists them as warnings")
    ha_note: str | None = Field(default=None, max_length=300, description="what replication/HA means (or does not mean) for this component")
    os_images: list[str] = Field(default=[], description="OS images the artifacts were built/validated for; empty = no restriction")
    sizing: Sizing | None = Field(default=None, description="sizing-engine model (resources, consolidation, HA, evidence)")

    @model_validator(mode="after")
    def _uniq(self) -> Self:
        for what, items in (("artifacts", [a.name for a in self.artifacts]), ("volumes", [v.name for v in self.volumes]),
                            ("ports", [p.name for p in self.ports]), ("health_checks", [h.name for h in self.health_checks])):
            if len(set(items)) != len(items):
                raise ValueError(f"duplicate names in {what}")
        if self.sizing:
            vols = {v.name for v in self.volumes}
            if {v.volume for v in self.sizing.volumes} != vols:
                raise ValueError("sizing.volumes must model exactly the component's volumes")
        ports = {p.port for p in self.ports}
        for h in self.health_checks:
            if h.port not in ports:
                raise ValueError(f"health check {h.name!r} targets port {h.port} which the component does not declare")
        return self

    @property
    def unpinned(self) -> list[str]:
        return [a.name for a in self.artifacts if not a.pinned]


class VmLayout(_M):
    name: str = Field(pattern=NAME)
    components: list[str] = Field(min_length=1)
    replicas: int = Field(default=1, ge=1, le=5)
    anti_affinity: bool = False
    per_tenant: bool = False


class BackupPolicy(_M):
    schedule: Literal["hourly", "daily", "weekly"]
    retention_days: int = Field(ge=1, le=3650)
    snapshot_before_change: bool = True
    offsite: bool = False


class SizingPreset(_M):
    """How a legacy profile maps onto the sizing engine (the profile itself stays a fixed, legacy layout)."""
    deployment_type: Literal["evaluation", "production", "msp", "custom"]
    architecture: Literal["consolidated", "balanced", "isolated", "ha", "dedicated"] | None = None


class Profile(_M):
    name: str = Field(pattern=NAME)
    version: str = Field(pattern=SEMVER)
    title: str = Field(max_length=100)
    description: str = Field(max_length=500)
    maturity: Literal["lab-validated", "experimental"]
    max_users: int = Field(ge=1, le=100000)
    min_nodes: int = Field(ge=1, le=64)
    ha: bool
    tenancy: Literal["single", "multi"]
    dedicated_nodes: bool = False
    custom: bool = False
    vms: list[VmLayout]
    optional_components: list[str] = []
    default_optional: list[str] = []
    backup: BackupPolicy
    sizing_preset: SizingPreset | None = None

    @model_validator(mode="after")
    def _chk(self) -> Self:
        names = [v.name for v in self.vms]
        if len(set(names)) != len(names):
            raise ValueError("duplicate vm names in layout")
        if not self.custom and not self.vms:
            raise ValueError("only the custom profile may have an empty layout")
        if self.ha and not all(v.replicas >= 2 and v.anti_affinity for v in self.vms):
            raise ValueError("ha profile: every VM needs replicas >= 2 and anti_affinity")
        if not set(self.default_optional) <= set(self.optional_components):
            raise ValueError("default_optional must be a subset of optional_components")
        return self


class OsImage(_M):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]{1,30}$")
    title: str
    template: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{1,60}$")
    sha256: str = Field(pattern=r"^([0-9a-f]{64})?$", description="empty = not pinned yet (plan warns)")


class VmOverhead(_M):
    cores: int = Field(ge=0)
    memory_mb: int = Field(ge=0)
    disk_gb: int = Field(ge=0)


class PlacementDefaults(_M):
    cpu_overcommit: int = Field(ge=1, le=32)
    memory_reserve_pct: int = Field(ge=0, le=50)
    storage_reserve_pct: int = Field(ge=0, le=50)
    thin_max_ratio_pct: int = Field(default=100, ge=100, le=1000, description="max provisioned/physical % on thin pools a plan may create")


class Meta(_M):
    catalog_version: str = Field(pattern=SEMVER)
    os_images: list[OsImage] = Field(min_length=1)
    default_os_image: str
    vm_overhead: VmOverhead
    placement: PlacementDefaults


class Catalog(_M):
    meta: Meta
    components: dict[str, Component]
    profiles: dict[str, Profile]
    digest: str

    @property
    def version(self) -> str:
        return self.meta.catalog_version

    def os_image(self, image_id: str | None) -> OsImage | None:
        want = image_id or self.meta.default_os_image
        return next((o for o in self.meta.os_images if o.id == want), None)

    def dependency_order(self, names: set[str]) -> list[str]:
        """Deterministic topological order over `depends_on` + `after` restricted to `names`."""
        g = {n: sorted((set(self.components[n].depends_on) | set(self.components[n].after)) & names) for n in sorted(names)}
        ts = graphlib.TopologicalSorter(g)
        ts.prepare()
        out: list[str] = []
        while ts.is_active():
            for n in sorted(ts.get_ready()):
                out.append(n)
                ts.done(n)
        return out


def _load_yaml(p: Path) -> dict:
    try:
        raw = yaml.safe_load(p.read_text())
    except yaml.YAMLError as e:
        raise CatalogError(f"{p.name}: invalid YAML: {str(e).splitlines()[0]}") from None
    if not isinstance(raw, dict):
        raise CatalogError(f"{p.name}: must be a YAML mapping")
    return raw


def _validate(model, raw: dict, what: str):
    try:
        return model.model_validate(raw)
    except ValidationError as e:
        x = e.errors()[0]
        raise CatalogError(f"{what}: {'.'.join(str(i) for i in x['loc'])}: {x['msg']}") from None


def build_catalog(meta_raw: dict, comp_raws: list[dict], prof_raws: list[dict], digest: str = "") -> Catalog:
    meta = _validate(Meta, meta_raw, "catalog.yaml")
    comps: dict[str, Component] = {}
    for r in comp_raws:
        c = _validate(Component, r, f"component {r.get('name')}")
        if c.name in comps:
            raise CatalogError(f"duplicate component {c.name}")
        comps[c.name] = c
    profs: dict[str, Profile] = {}
    for r in prof_raws:
        p = _validate(Profile, r, f"profile {r.get('name')}")
        if p.name in profs:
            raise CatalogError(f"duplicate profile {p.name}")
        profs[p.name] = p
    if not meta.os_images or meta.default_os_image not in {o.id for o in meta.os_images}:
        raise CatalogError("default_os_image is not in os_images")
    for c in comps.values():
        for o in c.os_images:
            if o not in {i.id for i in meta.os_images}:
                raise CatalogError(f"component {c.name}: os_images entry {o!r} is not in catalog os_images")
        for d in (*c.depends_on, *c.after):
            if d not in comps:
                raise CatalogError(f"component {c.name}: unknown dependency {d!r}")
        if set(c.depends_on) & set(c.after):
            raise CatalogError(f"component {c.name}: a dependency cannot be in both depends_on and after")
        if c.sizing:
            for o in c.sizing.consolidation.never_with:
                if o not in comps:
                    raise CatalogError(f"component {c.name}: sizing.consolidation.never_with names unknown component {o!r}")
    try:
        tuple(graphlib.TopologicalSorter({c.name: set(c.depends_on) | set(c.after) for c in comps.values()}).static_order())
    except graphlib.CycleError:
        raise CatalogError("dependency cycle between components") from None
    for p in profs.values():
        placed: list[str] = []
        for v in p.vms:
            for c in v.components:
                if c not in comps:
                    raise CatalogError(f"profile {p.name}: unknown component {c!r}")
                if comps[c].placement == "every_vm":
                    raise CatalogError(f"profile {p.name}: {c} is placed on every VM automatically; do not list it")
            placed += v.components
        if len(set(placed)) != len(placed):
            raise CatalogError(f"profile {p.name}: a component appears on more than one VM entry")
        for o in p.optional_components:
            if o not in placed:
                raise CatalogError(f"profile {p.name}: optional component {o!r} is not in the layout")
        have = set(placed)
        for c in placed:
            missing = [d for d in comps[c].depends_on if d not in have and d not in p.optional_components]
            if missing and not p.custom:
                raise CatalogError(f"profile {p.name}: {c} depends on {missing} which the layout lacks")
    return Catalog(meta=meta, components=comps, profiles=profs, digest=digest)


def default_dir() -> Path:
    env = os.environ.get("OU_CATALOG_DIR")
    return Path(env) if env else Path(__file__).resolve().parents[3] / "blueprints" / "catalog"


def load_catalog(directory: Path | str | None = None) -> Catalog:
    d = Path(directory) if directory else default_dir()
    files = [d / "catalog.yaml", *sorted((d / "components").glob("*.yaml")), *sorted((d / "profiles").glob("*.yaml"))]
    if not files[0].is_file():
        raise CatalogError(f"catalog not found at {d}")
    h = hashlib.sha256()
    for f in files:
        h.update(f.name.encode() + b"\0" + f.read_bytes() + b"\0")
    return build_catalog(_load_yaml(files[0]), [_load_yaml(f) for f in files if f.parent.name == "components"],
                         [_load_yaml(f) for f in files if f.parent.name == "profiles"], h.hexdigest())


@lru_cache(maxsize=1)
def _default() -> Catalog:
    return load_catalog()


def get_catalog() -> Catalog:
    return _default()


def profile_vm_counts(p: Profile) -> dict:
    """VM counts DERIVED from the layout (never hand-written in a title): default optional set, and everything enabled.
    For per-tenant layouts the counts are per tenant plus the shared VMs."""
    def count(enabled: set[str]) -> int:
        return sum(v.replicas for v in p.vms if [c for c in v.components if c not in set(p.optional_components) - enabled])
    return {"default": count(set(p.default_optional)), "all_optional": count(set(p.optional_components)),
            "minimum": count(set()), "per_tenant": p.tenancy == "multi"}


def describe_profile(p: Profile) -> dict:
    return {**p.model_dump(mode="json"), "vm_counts": profile_vm_counts(p)}


def describe_component(c: Component) -> dict:
    d = c.model_dump(mode="json")
    d["unpinned_artifacts"] = c.unpinned
    return d
