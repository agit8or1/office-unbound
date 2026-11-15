"""Permission drift: expected (stored policy) vs actual (what the provider reports for the credential). Provider-agnostic comparison.

Corrections are PLANS that need approval (provider.permissions.reconcile). Nothing here restores or expands anything by itself."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DriftReport:
    ok: bool
    missing: list[dict] = field(default_factory=list)       # [{"path","privileges"}] expected but absent
    unexpected: list[dict] = field(default_factory=list)    # [{"path","privileges"}] present but not in the policy
    forbidden: list[dict] = field(default_factory=list)     # forbidden privileges present anywhere (always an alert)
    acl: dict = field(default_factory=dict)                 # {"checked": bool, "missing": [...], "unexpected": [...], "note": str}
    suggestion: list[str] = field(default_factory=list)     # human-readable correction plan (never auto-applied)
    error: str | None = None
    error_code: str | None = None                           # auth | permission | unreachable | tls | ...

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def covered(path: str, expected: dict[str, set[str]]) -> set[str]:
    """Privileges a path may legitimately carry: expected at itself or at any ancestor that propagates; pool grants also cover member guests."""
    out: set[str] = set()
    for p, privs in expected.items():
        if p == "/" or path == p or path.startswith(p.rstrip("/") + "/"):
            out |= privs
    if path.startswith("/vms/"):
        for p, privs in expected.items():
            if p.startswith("/pool/"):
                out |= privs
    return out


def compare_permissions(expected: dict[str, set[str]], actual: dict[str, set[str]], forbidden: set[str]) -> DriftReport:
    miss, extra, bad = [], [], []
    for path, privs in sorted(expected.items()):
        lack = sorted(privs - actual.get(path, set()))
        if lack:
            miss.append({"path": path, "privileges": lack})
    for path, privs in sorted(actual.items()):
        more = sorted(privs - covered(path, expected))
        if more:
            extra.append({"path": path, "privileges": more})
        f = sorted(privs & forbidden)
        if f:
            bad.append({"path": path, "privileges": f})
    sug = [f"restore {', '.join(m['privileges'])} on {m['path']} (re-apply the stored role/ACL)" for m in miss]
    sug += [f"remove {', '.join(e['privileges'])} on {e['path']} (not part of the approved policy)" for e in extra]
    return DriftReport(ok=not (miss or extra or bad), missing=miss, unexpected=extra, forbidden=bad, suggestion=sug)


def compare_acl(expected: set[tuple], actual: set[tuple], managed_subjects: set[str]) -> dict:
    """expected/actual: sets of (path, subject, role). Only entries for subjects the ICS manages are considered 'unexpected'."""
    return {"checked": True, "missing": sorted(expected - actual),
            "unexpected": sorted(a for a in actual - expected if a[1] in managed_subjects)}
