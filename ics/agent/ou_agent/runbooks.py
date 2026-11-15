"""Fixed runbook allowlist. The allowlist comes from a root-owned config file the agent user cannot modify.
No shell, no string commands: systemctl is called with an argv list and the unit must equal an allowlisted name exactly."""
import json
import os
import re
import secrets
import subprocess
import time

from . import guestspec
from .proto import Reject

SYSTEMCTL = "/usr/bin/systemctl"
UNIT_RE = re.compile(r"^[a-z0-9][a-z0-9_.@-]{0,62}$")
RUNBOOKS = ("service.restart", "service.status", "disk.usage")
# Per-user identity runbooks: fixed systemd oneshot TEMPLATE units (installed root-owned on the node) started with the validated uid as the
# instance name. The privileged work is done by a fixed root helper that validates the uid again; the agent never builds a command line from
# anything but the regex-checked uid. Result: JSON file written by the helper into RESULT_DIR (root-owned, world readable).
USER_RUNBOOKS = {
    "gromox.sync_user": ("ou-rb-gromox-sync", "gromox-sync"),         # reconcile the directory user into Gromox (create / suspend / reactivate)
    "gromox.kick_user": ("ou-rb-gromox-quarantine", "gromox-quarantine"),  # lock the (already suspended) mailbox for already-open sessions
    "gromox.user_state": ("ou-rb-gromox-state", "gromox-state"),      # read-only: SQL status + mailbox lock state
    "opencloud.check_user": ("ou-rb-opencloud-check", "opencloud-check"),  # can OpenCloud still resolve this user (1 s app token probe)
}
UID_RE = re.compile(r"^[a-z][a-z0-9._-]{1,31}$")
RESULT_DIR = "/run/ou-rb"
MAX_RESULT = 24576
_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C"}


def validate_config(cfg: dict) -> dict:
    """Shape of /etc/ou-agent/agent.json: {"listen": {"address","port"}, "runbooks": {name: {"units":[...]} | {"paths":[...]}}}"""
    rb = cfg.get("runbooks")
    if not isinstance(rb, dict) or set(rb) - set(RUNBOOKS) - set(USER_RUNBOOKS) - set(guestspec.GUEST_RUNBOOKS):
        raise ValueError("runbooks must be a subset of " + ", ".join(RUNBOOKS + tuple(USER_RUNBOOKS) + guestspec.GUEST_RUNBOOKS))
    for name in guestspec.GUEST_RUNBOOKS:
        if name in rb:
            guestspec.validate_runbook_config(name, rb[name])
    for name in USER_RUNBOOKS:
        if name in rb and rb[name] != {"enabled": True}:
            raise ValueError(f"{name} takes exactly {{\"enabled\": true}}")
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
    out = {}
    for k, v in rb.items():
        if k in USER_RUNBOOKS:
            out[k] = {"enabled": True}
        elif k in guestspec.GUEST_RUNBOOKS:
            out[k] = {key: sorted(val) if isinstance(val, list) else val for key, val in v.items()}
        elif k.startswith("service"):
            out[k] = {"units": sorted(v.get("units", []))}
        else:
            out[k] = {"paths": sorted(v.get("paths", []))}
    return out


def check_allowed(cfg: dict, action: str, params: dict) -> dict:
    """Returns normalised params or raises Reject(not_allowed|bad_params). Exact match against the allowlist, nothing else."""
    spec = cfg["runbooks"].get(action)
    if spec is None:
        raise Reject("not_allowed", "action is not an allowlisted runbook")
    if action in guestspec.GUEST_RUNBOOKS:
        return guestspec.CHECKS[action](params, spec)   # typed, closed-shape validation; nothing is spooled before this passes
    if action in USER_RUNBOOKS:
        if set(params) != {"user"} or not isinstance(params["user"], str) or not UID_RE.match(params["user"]):
            raise Reject("bad_params", "params must be exactly {user} (lowercase uid)")
        return {"user": params["user"]}
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


def _user_runbook(action: str, uid: str) -> dict:
    unit, stem = USER_RUNBOOKS[action]
    started = int(time.time())
    r = _systemctl("start", "--wait", f"{unit}@{uid}.service", timeout=100)
    out = {"user": uid, "returncode": r.returncode}
    path = os.path.join(RESULT_DIR, f"{stem}-{uid}.json")
    try:
        if os.stat(path).st_size > MAX_RESULT:
            raise ValueError("result too large")
        with open(path) as f:
            data = json.load(f)
        if not isinstance(data, dict) or data.get("uid") != uid or int(data.get("ts", 0)) < started - 2:
            raise ValueError("stale or foreign result")
        out["result"] = data
    except (OSError, ValueError):
        out["result"] = None
        if r.returncode != 0:
            out["stderr"] = r.stderr.strip()[:300]
    return out


SPOOL_DIR = "/run/ou-agent-spool"   # RuntimeDirectory of ou-agent.service (agent-writable, world-readable); params are not secret
RESULT_ROOT = "/run"


def _guest_runbook(action: str, params: dict) -> dict:
    """Spool the validated params, start the fixed template unit ou-rb-<family>@<rid>.service (polkit allows exactly that), read the result."""
    fam = guestspec.FAMILY_OF[action]
    rid = "r" + secrets.token_hex(8)
    spool = os.path.join(SPOOL_DIR, rid + ".json")
    fd = os.open(spool, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, "w") as f:
        json.dump({"action": action, "params": params}, f)
    try:
        r = _systemctl("start", "--wait", f"ou-rb-{fam}@{rid}.service", timeout=1000)
        out = {"returncode": r.returncode}
        path = os.path.join(RESULT_ROOT, f"ou-rb-{fam}", rid + ".json")
        try:
            if os.stat(path).st_size > MAX_RESULT:
                raise ValueError("result too large")
            with open(path) as f:
                data = json.load(f)
            if data.get("rid") != rid:
                raise ValueError("foreign result")
            out.update({k: data[k] for k in ("result", "rejected", "error") if k in data})
            os.unlink(path)
        except (OSError, ValueError):
            out["result"] = None
            if r.returncode != 0:
                out["stderr"] = r.stderr.strip()[:300]
        return out
    finally:
        try:
            os.unlink(spool)
        except OSError:
            pass


def execute(action: str, params: dict) -> dict:
    """Run an already allowlisted runbook. Returns a small JSON-safe dict."""
    if action in guestspec.GUEST_RUNBOOKS:
        return _guest_runbook(action, params)
    if action in USER_RUNBOOKS:
        return _user_runbook(action, params["user"])
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
