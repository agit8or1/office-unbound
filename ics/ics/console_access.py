"""Settings -> Network & domains -> Management access (owner 2026-11-20: "we should have lockdown options in settings").

Who may reach THIS console under its public name (console.<domain>, nginx site ou-console-public.conf, whose access rule is the include
/etc/nginx/ou-console-access.conf). The bare-IP console stays LAN/VPN only and is not changed here. Real client addresses reach nginx through the
PROXY protocol, so allow/deny on the client address is correct.

Typed action settings.management.update (plan -> approval -> job): the rendered rules go to the root helper /usr/local/sbin/ou-console-access
(argv list, no shell, rules on stdin; it accepts only comment/allow/deny lines, checks `nginx -t` and restores the previous file on failure).
The setting is stored only after the helper succeeded."""
from __future__ import annotations

import ipaddress
import json
import re
import subprocess
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import text

KEY = "management.access"
LAN_VPN_DEFAULT = ["192.168.22.0/24", "10.0.0.0/8"]
SOCKET = "/run/ou-console-access.sock"   # ou-console-access.socket (ics/deploy): the only way the console changes the host
MAX_RANGES = 32


class ApplyError(RuntimeError):
    pass


class ManagementAccess(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["public", "lan_vpn", "allowlist"] = Field(default="public", description="public: anyone may reach the sign-in page; "
                                                            "lan_vpn: only the listed internal ranges; allowlist: only the listed ranges")
    allowed: list[str] = Field(default_factory=list, max_length=MAX_RANGES, description="IPv4/IPv6 address ranges (CIDR) allowed in lan_vpn/allowlist mode")

    @model_validator(mode="after")
    def _check(self):
        out = []
        for a in self.allowed:
            try:
                n = ipaddress.ip_network(str(a).strip(), strict=False)
            except ValueError:
                raise ValueError(f"not an IPv4/IPv6 address range: {str(a)[:60]!r}") from None
            if str(n) not in out:
                out.append(str(n))
        if self.mode == "public":
            out = []
        elif self.mode == "lan_vpn" and not out:
            out = list(LAN_VPN_DEFAULT)
        elif self.mode == "allowlist" and not out:
            raise ValueError("the allow list needs at least one address range")
        if any(ipaddress.ip_network(x).prefixlen == 0 for x in out):
            raise ValueError("0.0.0.0/0 and ::/0 allow everyone: choose Public instead")
        self.allowed = out
        return self


def render_access_conf(m: ManagementAccess) -> str:
    """Pure: the include file for ou-console-public.conf. Only comment lines and allow/deny lines (the helper refuses anything else)."""
    lines = ["# Office Unbound: who may reach the ICS console under its public name (written by ou-console-access; Settings -> Network & domains)",
             f"# mode: {m.mode}"]
    if m.mode == "public":
        lines.append("allow all;")
    else:
        lines += [f"allow {a};" for a in m.allowed] + ["deny all;"]
    out = "\n".join(lines) + "\n"
    if not all(re.fullmatch(r"#[^\n]*|allow [0-9a-fA-F:./]+;|allow all;|deny all;", x) for x in out.splitlines()):
        raise ValueError("refusing to render an access rule outside the allowed language")
    return out


def get(db) -> ManagementAccess:
    row = db.execute(text("SELECT value FROM system_settings WHERE key = :k"), {"k": KEY}).first()
    return ManagementAccess.model_validate(row.value) if row else ManagementAccess()


def put(db, m: ManagementAccess, by: str) -> None:
    db.execute(text("INSERT INTO system_settings (key, value, updated_at, updated_by) VALUES (:k, CAST(:v AS jsonb), now(), :b) "
                    "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now(), updated_by = EXCLUDED.updated_by"),
               {"k": KEY, "v": json.dumps(m.model_dump(mode="json")), "b": by[:120]})


def apply_conf(conf: str, sock_path: str | None = None, timeout: float = 120) -> str:
    """Hands the rules to the root helper through its socket (ou-console-access.socket: root-owned, group ics, one connection at a time).
    The console service keeps its sandbox (NoNewPrivileges): it never runs anything as root itself. Raises ApplyError on refusal/failure."""
    import socket
    path = sock_path or SOCKET
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(path)
            s.sendall(conf.encode())
            s.shutdown(socket.SHUT_WR)
            out = b""
            while len(out) < 4096 and b"\n" not in out:   # the helper answers exactly one line
                chunk = s.recv(4096)
                if not chunk:
                    break
                out += chunk
    except OSError as e:
        raise ApplyError(f"could not reach the access helper ({path}): {e.strerror or type(e).__name__}; is ou-console-access.socket installed and active?") from None
    line = out.decode("utf-8", "replace").strip().splitlines()[:1]
    if not line or not line[0].startswith("OK"):
        raise ApplyError(("the access helper refused or failed: " + (line[0] if line else "no answer"))[:400])
    return line[0][3:][:200]


def exec_update(rt, db, m: ManagementAccess, plan, known) -> dict:
    """settings.management.update: apply on the host first; store and audit only when the helper succeeded (a failure keeps the old setting)."""
    from . import audit
    old = get(db)
    apply_conf(render_access_conf(m))
    put(db, m, f"plan:{plan.id}")
    audit.append(db, "settings.management_access_updated", actor_name="worker", resource="settings", resource_id=KEY,
                 details={"old": old.model_dump(), "new": m.model_dump(), "requested_by": str(plan.requested_by), "plan_id": str(plan.id)})
    return {"management": m.model_dump()}
