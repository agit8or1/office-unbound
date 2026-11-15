"""Provisioning policy (provider-agnostic shape): what the integration may do and where. The provider turns it into roles/ACLs."""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

PRESETS = ("monitoring", "deploy", "custom", "full_admin")
CAPABILITIES = ("monitor", "deploy", "storage", "template_clone", "network", "backup", "custom")
_NAME = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$"
_NODE = r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$"
_PATH = r"^/[A-Za-z0-9/._:@+-]{0,200}$"


class Grant(BaseModel):
    """Custom preset only: extra privileges on one ACL path (validated against the per-version privilege matrix)."""
    model_config = ConfigDict(extra="forbid")
    path: str = Field(pattern=_PATH)
    privileges: list[str] = Field(min_length=1, max_length=40)
    why: str = Field(default="", max_length=300)


class AccessScope(BaseModel):
    """Where the integration is authorised. Proxmox enforces pools/storages/bridges/templates through ACL paths; nodes, VMID ranges,
    guest types and resource caps are enforced by the ICS broker (see the plan's `enforcement` list)."""
    model_config = ConfigDict(extra="forbid")
    nodes: list[str] = Field(default_factory=list, max_length=50)
    storages: list[str] = Field(default_factory=list, max_length=50)
    pools: list[str] = Field(default_factory=list, max_length=20)
    networks: list[str] = Field(default_factory=list, max_length=50, description="bridge or SDN vnet names")
    template_vmids: list[int] = Field(default_factory=list, max_length=50)
    vmid_ranges: list[tuple[int, int]] = Field(default_factory=list, max_length=20)
    guest_types: list[Literal["qemu", "lxc"]] = Field(default_factory=lambda: ["qemu"])
    backup_storages: list[str] = Field(default_factory=list, max_length=20)
    protected_vmids: list[int] = Field(default_factory=list, max_length=100)
    max_cores: int | None = Field(default=None, ge=1, le=1024)
    max_memory_mb: int | None = Field(default=None, ge=128)
    max_disk_gb: int | None = Field(default=None, ge=1)

    @field_validator("nodes")
    @classmethod
    def _n(cls, v):
        if any(not re.match(_NODE, x) for x in v):
            raise ValueError("invalid node name")
        return sorted(set(v))

    @field_validator("storages", "pools", "networks", "backup_storages")
    @classmethod
    def _names(cls, v):
        if any(not re.match(_NAME, x) for x in v):
            raise ValueError("names may contain letters, digits, . _ - only")
        return sorted(set(v))

    @field_validator("template_vmids", "protected_vmids")
    @classmethod
    def _ids(cls, v):
        if any(not 100 <= x <= 999_999_999 for x in v):
            raise ValueError("vmids must be 100..999999999")
        return sorted(set(v))

    @field_validator("vmid_ranges")
    @classmethod
    def _r(cls, v):
        if any(not 100 <= a <= b <= 999_999_999 for a, b in v):
            raise ValueError("vmid range must be 100 <= low <= high")
        return sorted(set(v))


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: Literal["proxmox"] = "proxmox"
    preset: Literal["monitoring", "deploy", "custom", "full_admin"] = "deploy"
    capabilities: list[Literal["monitor", "deploy", "storage", "template_clone", "network", "backup", "custom"]] = Field(
        default_factory=list, description="only for preset=custom; presets derive their own set")
    scope: AccessScope = Field(default_factory=AccessScope)
    realm: Literal["pve"] = Field(default="pve", description="service-account realm. Only the Proxmox VE realm is accepted: never PAM, never an OS account")
    service_user: str = Field(default="ics-svc", pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")
    token_base: str = Field(default="ics", pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,20}$")
    role_prefix: str = Field(default="OfficeUnbound", pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,30}$")
    role_names: dict[str, str] = Field(default_factory=dict, description="override per capability, e.g. {'deploy': 'MyDeploy'}")
    custom_grants: list[Grant] = Field(default_factory=list, max_length=30)
    allow_cicustom: bool = False
    allow_migrate: bool = False
    guest_agent: bool = False
    acknowledge_full_admin: bool = False
    approve_elevated: list[str] = Field(default_factory=list, description="elevated privileges the approver explicitly accepts, e.g. ['Sys.Modify']")

    @field_validator("role_names")
    @classmethod
    def _rn(cls, v):
        for k, n in v.items():
            if k not in CAPABILITIES + ("full_admin",) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", n):
                raise ValueError("role_names keys must be capabilities; values plain role names")
        return v

    @model_validator(mode="after")
    def _shape(self):
        if self.preset == "full_admin" and not self.acknowledge_full_admin:
            raise ValueError("full cluster administration is high-risk: set acknowledge_full_admin=true to confirm you accept its consequences")
        if self.preset != "full_admin" and self.acknowledge_full_admin:
            raise ValueError("acknowledge_full_admin only applies to preset=full_admin")
        if self.preset == "custom" and not self.capabilities:
            raise ValueError("preset=custom needs a capabilities list")
        if self.preset != "custom" and self.capabilities:
            raise ValueError("capabilities can only be chosen with preset=custom")
        if self.custom_grants and not (self.preset == "custom" and "custom" in self.capabilities):
            raise ValueError("custom_grants need preset=custom with the 'custom' capability")
        s = self.scope
        if self.preset != "full_admin" and not (s.nodes or s.pools or s.storages or s.template_vmids):
            raise ValueError("scope is empty: choose at least one node, pool, storage or template")
        return self
