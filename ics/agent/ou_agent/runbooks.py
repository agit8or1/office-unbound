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
    "gromox.kill_sessions": ("ou-rb-gromox-kill", "gromox-kill"),     # USER-KICK on the event bus: gromox-imap closes the user's open sessions
    "gromox.wipe_devices": ("ou-rb-gromox-wipe", "gromox-wipe"),      # request an ActiveSync remote wipe for every device of the user
    "gromox.devices": ("ou-rb-gromox-devices", "gromox-devices"),     # read-only: the user's EAS devices + wipe status/history
    "opencloud.check_user": ("ou-rb-opencloud-check", "opencloud-check"),  # can OpenCloud still resolve this user (1 s app token probe)
    "opencloud.revoke_app_tokens": ("ou-rb-opencloud-revoke", "opencloud-revoke"),  # delete ALL app tokens of the user (before the lock)
    # telephony (PBX node). The PBX derives everything from the directory: the uid only selects what is reported/kicked.
    "pbx.sync_extensions": ("ou-rb-pbx-sync", "pbx-sync"),     # read LDAP, rewrite pjsip/dialplan/voicemail config, reload; report this user's state
    "pbx.kick_user": ("ou-rb-pbx-kick", "pbx-kick"),            # sync, then delete the user's registrations and hang up live calls
    "pbx.user_state": ("ou-rb-pbx-state", "pbx-state"),         # read-only: endpoint present? registered contacts? live channels?
    "pbx.issue_credential": ("ou-rb-pbx-issue", "pbx-issue"),   # params {user, device}: new SIP credential, returned ONCE (PBX keeps an md5 digest)
}
# Backup product (ADR-0010): fixed runbooks; the root helper /usr/local/sbin/ou-backup does the work and re-validates. config: {"tiers": [...]}.
BACKUP_RESULT_DIR = "/run/ou-rb-backup"
BACKUP_RUNBOOKS = ("backup.run", "backup.verify", "backup.prune")
BACKUP_TIERS = ("files", "identity", "groupware", "ics")
CUSTOMER_PROFILE_RE = re.compile(r"^c-[0-9a-f]{32}$")
SNAPSHOT_RE = re.compile(r"^[0-9a-f]{8,64}$")
UID_RE = re.compile(r"^[a-z][a-z0-9._-]{1,31}\Z")
SIP_DEVICES = ("web", "native", "desk")
SECRET_DIR = "/run/ou-rb-secret"   # 0700 dir owned by ou-agent (made by the helper); the credential result is 0600, the agent unlinks it after reading
RESULT_DIR = "/run/ou-rb"
MAX_RESULT = 24576
_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C"}


def validate_config(cfg: dict) -> dict:
    """Shape of /etc/ou-agent/agent.json: {"listen": {"address","port"}, "runbooks": {name: {"units":[...]} | {"paths":[...]}}}"""
    rb = cfg.get("runbooks")
    if not isinstance(rb, dict) or set(rb) - set(RUNBOOKS) - set(USER_RUNBOOKS) - set(guestspec.GUEST_RUNBOOKS) - set(BACKUP_RUNBOOKS):
        raise ValueError("runbooks must be a subset of " + ", ".join(RUNBOOKS + tuple(USER_RUNBOOKS) + guestspec.GUEST_RUNBOOKS + BACKUP_RUNBOOKS))
    for name in BACKUP_RUNBOOKS:
        if name in rb and (not {"tiers"} <= set(rb[name]) <= {"tiers", "customers"} or not isinstance(rb[name]["tiers"], list) or not rb[name]["tiers"]
                           or not set(rb[name]["tiers"]) <= set(BACKUP_TIERS)
                           or not (isinstance(rb[name].get("customers", []), list)
                                   and all(isinstance(c, str) and CUSTOMER_PROFILE_RE.match(c) for c in rb[name].get("customers", [])))):
            raise ValueError(f"{name} takes {{\"tiers\": [subset of {', '.join(BACKUP_TIERS)}], \"customers\": [optional c-<32 hex> profiles]}}")
    for name in guestspec.GUEST_RUNBOOKS:
        if name in rb:
            guestspec.validate_runbook_config(name, rb[name])
    for name in USER_RUNBOOKS:
        if name in rb and rb[name] != {"enabled": True}:
            raise ValueError(f"{name} takes exactly {{\"enabled\": true}}")
    for name in ("service.restart", "service.status"):
        for u in rb.get(name, {}).get("units", []):
            if not UNIT_RE.fullmatch(u):
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
        elif k in BACKUP_RUNBOOKS:
            out[k] = {"tiers": sorted(v["tiers"]), **({"customers": sorted(v["customers"])} if v.get("customers") else {})}
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
    if action in BACKUP_RUNBOOKS:
        return check_backup(action, params, spec)
    if action == "pbx.issue_credential":
        if set(params) != {"user", "device"} or not isinstance(params["user"], str) or not UID_RE.fullmatch(params["user"]) \
                or params["device"] not in SIP_DEVICES:
            raise Reject("bad_params", "params must be exactly {user, device} (device web|native|desk)")
        return {"user": params["user"], "device": params["device"]}
    if action in USER_RUNBOOKS:
        if set(params) != {"user"} or not isinstance(params["user"], str) or not UID_RE.fullmatch(params["user"]):
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


def check_backup(action: str, p: dict, spec: dict) -> dict:
    """Closed shapes; no free text anywhere: tier (enum, must be enabled in agent.json), level (enum), small ints, a hex snapshot id."""
    def exact(keys, req=None):
        req = tuple(req if req is not None else keys)
        keys = (*keys, "customer")
        if not isinstance(p, dict) or set(p) - set(keys) or set(req) - set(p):
            raise Reject("bad_params", "unexpected or missing parameters")
    if action == "backup.run":
        exact(("tier",))
    elif action == "backup.verify":
        exact(("tier", "level", "percent", "snapshot"), ("tier", "level"))
        if p["level"] not in ("check", "restore"):
            raise Reject("bad_params", "level must be check or restore")
        if "percent" in p and (type(p["percent"]) is not int or not 1 <= p["percent"] <= 100):
            raise Reject("bad_params", "percent must be 1..100")
        if "snapshot" in p and not (isinstance(p["snapshot"], str) and SNAPSHOT_RE.match(p["snapshot"])):
            raise Reject("bad_params", "snapshot must be a hex id")
    else:
        exact(("tier", "last", "daily", "weekly", "monthly"))
        for k, hi in (("last", 100), ("daily", 366), ("weekly", 260), ("monthly", 240)):
            if type(p[k]) is not int or not 0 <= p[k] <= hi:
                raise Reject("bad_params", f"{k} out of range")
        if p["last"] + p["daily"] + p["weekly"] + p["monthly"] < 1:
            raise Reject("bad_params", "retention keeps nothing")
    if not isinstance(p["tier"], str) or p["tier"] not in spec["tiers"]:
        raise Reject("not_allowed", "tier is not enabled for this runbook on this node")
    if "customer" in p and not (isinstance(p["customer"], str) and CUSTOMER_PROFILE_RE.match(p["customer"]) and p["customer"] in spec.get("customers", [])):
        raise Reject("not_allowed", "customer profile is not enabled for this runbook on this node")
    return dict(p)


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


def _pbx_issue(uid: str, device: str) -> dict:
    """The result carries a one-time secret: read from SECRET_DIR (not world readable) and unlinked at once. Never logged by the agent."""
    started = int(time.time())
    inst = f"{uid}.{device}"          # uid may contain dots, the device never does: the helper splits on the LAST dot
    r = _systemctl("start", "--wait", f"ou-rb-pbx-issue@{inst}.service", timeout=100)
    out = {"user": uid, "returncode": r.returncode}
    path = os.path.join(SECRET_DIR, f"pbx-issue-{inst}.json")
    try:
        with open(path) as f:
            data = json.load(f)
        if not isinstance(data, dict) or data.get("uid") != uid or data.get("device") != device or int(data.get("ts", 0)) < started - 2:
            raise ValueError("stale or foreign result")
        out["result"] = data
    except (OSError, ValueError):
        out["result"] = None
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    return out


SPOOL_DIR = "/run/ou-agent-spool"   # RuntimeDirectory of ou-agent.service (agent-writable, world-readable); params are not secret
RESULT_ROOT = "/run"


def _guest_runbook(action: str, params: dict) -> dict:
    """Spool the validated params, start the fixed template unit ou-rb-<family>@<rid>.service (polkit allows exactly that), read the result."""
    fam = guestspec.FAMILY_OF[action]
    rid = "r" + secrets.token_hex(8)
    spool = os.path.join(SPOOL_DIR, rid + ".json")
    fd = os.open(spool, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    os.fchmod(fd, 0o644)  # the agent's UMask is 0077; the helper units run as other users and must be able to read the (non-secret) request
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
            out.update({k: data[k] for k in ("result", "rejected", "error") if k in data})  # the helper's own run prunes old result files
        except (OSError, ValueError):
            raise RuntimeError("helper produced no result") from None  # -> signed status=error/exec_failed; never "ok" with an empty result
        return out
    finally:
        try:
            os.unlink(spool)
        except OSError:
            pass


def _backup_runbook(action: str, params: dict) -> dict:
    """Spool the validated params, start ou-rb-backup@<rid>.service (polkit allows exactly that template), read the helper's result file.
    The result is data from the root helper (counts, durations, canary comparison): never a credential."""
    rid = "r" + secrets.token_hex(8)
    spool = os.path.join(SPOOL_DIR, rid + ".json")
    fd = os.open(spool, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    os.fchmod(fd, 0o644)
    with os.fdopen(fd, "w") as f:
        json.dump({"action": action, "params": params}, f)
    try:
        r = _systemctl("start", "--wait", f"ou-rb-backup@{rid}.service", timeout=3600)
        path = os.path.join(BACKUP_RESULT_DIR, rid + ".json")
        try:
            if os.stat(path).st_size > 4 * MAX_RESULT:
                raise ValueError("result too large")
            with open(path) as f:
                data = json.load(f)
            if data.get("rid") != rid:
                raise ValueError("foreign result")
        except (OSError, ValueError):
            raise RuntimeError("backup helper produced no result") from None
        out = {"returncode": r.returncode}
        out.update({k: data[k] for k in ("result", "error") if k in data})
        return out
    finally:
        try:
            os.unlink(spool)
        except OSError:
            pass


def execute(action: str, params: dict) -> dict:
    """Run an already allowlisted runbook. Returns a small JSON-safe dict."""
    if action in BACKUP_RUNBOOKS:
        return _backup_runbook(action, params)
    if action in guestspec.GUEST_RUNBOOKS:
        return _guest_runbook(action, params)
    if action == "pbx.issue_credential":
        return _pbx_issue(params["user"], params["device"])
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
