"""Fixed runbook allowlist. The allowlist comes from a root-owned config file the agent user cannot modify.
No shell, no string commands: systemctl is called with an argv list and the unit must equal an allowlisted name exactly."""
import os
import re
import subprocess

from .proto import Reject

SYSTEMCTL = "/usr/bin/systemctl"
UNIT_RE = re.compile(r"^[a-z0-9][a-z0-9_.@-]{0,62}$")
RUNBOOKS = ("service.restart", "service.status", "disk.usage")
_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C"}


def validate_config(cfg: dict) -> dict:
    """Shape of /etc/ou-agent/agent.json: {"listen": {"address","port"}, "runbooks": {name: {"units":[...]} | {"paths":[...]}}}"""
    rb = cfg.get("runbooks")
    if not isinstance(rb, dict) or set(rb) - set(RUNBOOKS):
        raise ValueError("runbooks must be a subset of " + ", ".join(RUNBOOKS))
    for name in ("service.restart", "service.status"):
        for u in rb.get(name, {}).get("units", []):
            if not UNIT_RE.match(u):
                raise ValueError(f"bad unit name {u!r}")
    for p in rb.get("disk.usage", {}).get("paths", []):
        if not (isinstance(p, str) and p.startswith("/") and "\0" not in p):
            raise ValueError(f"bad path {p!r}")
    return cfg


def capabilities(cfg: dict) -> dict:
    rb = cfg["runbooks"]
    return {k: {"units": sorted(v.get("units", []))} if k.startswith("service") else {"paths": sorted(v.get("paths", []))}
            for k, v in rb.items()}


def check_allowed(cfg: dict, action: str, params: dict) -> dict:
    """Returns normalised params or raises Reject(not_allowed|bad_params). Exact match against the allowlist, nothing else."""
    spec = cfg["runbooks"].get(action)
    if spec is None:
        raise Reject("not_allowed", "action is not an allowlisted runbook")
    if action.startswith("service."):
        if set(params) != {"unit"} or not isinstance(params["unit"], str):
            raise Reject("bad_params", "params must be exactly {unit}")
        if params["unit"] not in spec.get("units", []):
            raise Reject("not_allowed", "unit is not allowlisted for this runbook")
        return {"unit": params["unit"]}
    if set(params) != {"path"} or not isinstance(params["path"], str):
        raise Reject("bad_params", "params must be exactly {path}")
    if params["path"] not in spec.get("paths", []):
        raise Reject("not_allowed", "path is not allowlisted")
    return {"path": params["path"]}


def _systemctl(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run([SYSTEMCTL, "--no-ask-password", *args], shell=False, stdin=subprocess.DEVNULL, capture_output=True,
                          timeout=timeout, env=_ENV, text=True)


def _show(unit: str) -> dict:
    r = _systemctl("show", "--property=ActiveState,SubState,UnitFileState,MainPID,NRestarts", unit + ".service", timeout=15)
    out = {}
    for line in r.stdout.splitlines():
        k, _, v = line.partition("=")
        out[k] = v
    return out


def execute(action: str, params: dict) -> dict:
    """Run an already allowlisted runbook. Returns a small JSON-safe dict."""
    if action == "service.status":
        s = _show(params["unit"])
        return {"unit": params["unit"], "active_state": s.get("ActiveState"), "sub_state": s.get("SubState"),
                "unit_file_state": s.get("UnitFileState"), "main_pid": int(s.get("MainPID") or 0)}
    if action == "service.restart":
        r = _systemctl("restart", params["unit"] + ".service")
        s = _show(params["unit"])
        res = {"unit": params["unit"], "returncode": r.returncode, "active_state": s.get("ActiveState"), "sub_state": s.get("SubState")}
        if r.returncode != 0:
            res["stderr"] = r.stderr.strip()[:300]
        return res
    if action == "disk.usage":
        st = os.statvfs(params["path"])
        total, free = st.f_blocks * st.f_frsize, st.f_bavail * st.f_frsize
        return {"path": params["path"], "total_bytes": total, "free_bytes": free, "used_percent": round(100 * (total - free) / total) if total else 0}
    raise Reject("not_allowed")
