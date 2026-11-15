"""Plan / diff model shared by every provider. A plan is plain data (JSON-serialisable) and carries a stable hash so an
approval of "apply this plan" can be bound to exactly what the approver saw (state drift between preview and apply => refuse)."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Literal, Protocol

SCHEMA = "office-unbound/provisioning-plan/v1"
Op = Literal["create", "modify", "noop", "remove", "conflict"]


@dataclass
class Step:
    kind: str                      # pool | role | user | token | acl
    op: Op
    target: str                    # stable identifier (role name, userid, token id, "path|subject|role")
    detail: dict = field(default_factory=dict)
    reason: str = ""
    risk: Literal["normal", "high"] = "normal"


@dataclass
class EnforcementNote:
    control: str
    enforced_by: Literal["proxmox", "ics", "both", "not_enforced"]
    detail: str


@dataclass
class ProvisioningPlan:
    provider: str
    policy: dict
    facts: dict = field(default_factory=dict)          # summary of what discovery found (versions, counts) - no secrets
    steps: list[Step] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    elevated: list[dict] = field(default_factory=list)   # privileges beyond the minimum: {"privilege","path","why","what_it_grants"}
    consequences: list[str] = field(default_factory=list)
    enforcement: list[EnforcementNote] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)     # reasons the plan cannot be applied as it stands
    schema: str = SCHEMA

    def hash(self) -> str:
        body = {"schema": self.schema, "provider": self.provider, "policy": self.policy,
                "steps": [[s.kind, s.op, s.target, s.detail] for s in self.steps], "elevated": self.elevated,
                "blocked": self.blocked}
        return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()

    def changes(self) -> list[Step]:
        return [s for s in self.steps if s.op in ("create", "modify", "remove")]

    @property
    def risk(self) -> str:
        return "high" if (self.elevated or any(s.risk == "high" for s in self.steps) or self.policy.get("preset") == "full_admin") else "normal"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["plan_hash"] = self.hash()
        d["risk"] = self.risk
        d["summary"] = {op: sum(1 for s in self.steps if s.op == op) for op in ("create", "modify", "remove", "noop", "conflict")}
        return d


class PackageGenerator(Protocol):
    """Mode B: turn a plan into customer-runnable artifacts. Returns {filename: text}. MUST NOT embed secrets."""

    def generate(self, plan: ProvisioningPlan, meta: dict) -> dict[str, str]: ...


def diff_names(desired: dict[str, object], existing: dict[str, object]) -> tuple[list[str], list[str], list[str]]:
    """(missing, extra, different) between two name->value mappings."""
    missing = sorted(k for k in desired if k not in existing)
    extra = sorted(k for k in existing if k not in desired)
    different = sorted(k for k in desired if k in existing and desired[k] != existing[k])
    return missing, extra, different
