"""Request model of a scope change (provider.scope.change): where the integration should end up."""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .model import _NAME, _NODE


class ScopeTarget(BaseModel):
    """Where a scope change should end up. Everything not stated stays as it is."""
    model_config = ConfigDict(extra="forbid")
    mode: Literal["single_node", "whole_cluster"]
    nodes: list[str] = Field(default_factory=list, max_length=50, description="single_node: the complete list of selected nodes (normally one); ignored for whole_cluster")
    storages: list[str] | None = Field(default=None, max_length=50, description="complete storage list; omitted = unchanged")
    template_vmids: list[int] | None = Field(default=None, max_length=50, description="complete template list; omitted = unchanged")
    risk_overrides: list[str] = Field(default_factory=list, max_length=50)
    allow_migrate: bool | None = None
    detach_orphans: bool = Field(default=False, description="narrowing only: ICS stops managing guests that would fall outside the new scope (they keep running in Proxmox)")

    @field_validator("nodes")
    @classmethod
    def _n(cls, v):
        if any(not re.match(_NODE, x) for x in v):
            raise ValueError("invalid node name")
        return sorted(set(v))

    @field_validator("storages")
    @classmethod
    def _s(cls, v):
        if v is not None and any(not re.match(_NAME, x) for x in v):
            raise ValueError("names may contain letters, digits, . _ - only")
        return sorted(set(v)) if v is not None else v

    @field_validator("template_vmids")
    @classmethod
    def _t(cls, v):
        if v is not None and any(not 100 <= x <= 999_999_999 for x in v):
            raise ValueError("vmids must be 100..999999999")
        return sorted(set(v)) if v is not None else v


Direction = Literal["widen", "narrow", "same"]
