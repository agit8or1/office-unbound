"""Experimental features: off unless the host owner opts in (public-alpha directive 2026-11-25, PUBLIC-ALPHA-READINESS PA-20/PA-30/PA-31).

`ICS_EXPERIMENTAL` in /etc/office-unbound/ics.env is a comma list of the names below. A feature not listed is refused with a plain reason;
it is never silently enabled. The ICS reads the list at start (config.Settings.experimental) and `configure()` publishes it to the planner,
the tenancy setting and the identity actions."""
from __future__ import annotations

FEATURES = {
    "meetings": "Video meetings (Jitsi): lab prototype, not verified on a deployment",
    "telephony": "Telephony (Asterisk): lab prototype, not verified on a deployment",
    "multi-tenant": "Several customers on shared infrastructure: network isolation between them is not verified on real Proxmox",
    "remote-wipe": "ActiveSync remote wipe: asks EVERY device of the person for a FULL wipe (can erase a personal phone); tested only with a scripted client",
}
_enabled: frozenset[str] = frozenset()


class NotEnabled(ValueError):
    pass


def parse(v: str | None) -> frozenset[str]:
    names = frozenset(x.strip().lower() for x in (v or "").split(",") if x.strip())
    bad = names - set(FEATURES)
    if bad:
        raise RuntimeError(f"ICS_EXPERIMENTAL: unknown feature(s) {', '.join(sorted(bad))}; known: {', '.join(sorted(FEATURES))}")
    return names


def configure(names) -> None:
    global _enabled
    _enabled = frozenset(names or ())


def enabled(name: str) -> bool:
    return name in _enabled


def require(name: str) -> None:
    if name not in _enabled:
        raise NotEnabled(f"{FEATURES[name]}. It is experimental and off on this installation; the host owner can turn it on with "
                         f"ICS_EXPERIMENTAL={name} in /etc/office-unbound/ics.env (then restart the ICS)")


def state() -> list[dict]:
    return [{"name": n, "description": d, "enabled": n in _enabled} for n, d in FEATURES.items()]
