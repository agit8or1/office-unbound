"""Node-side executor of `guest.journal` (diagspec.py): READ-ONLY. Started ONLY by the fixed template unit ou-rb-diag@<rid>.service, which the agent
may start through polkit. The unit runs as uid 0 with a single capability (CAP_DAC_READ_SEARCH: read any file, write none it does not own),
no network, a read-only file system and group ou-agent (the result file is 0640 root:ou-agent, never world-readable).
Usage: python3 -m ou_agent.diaghelper <rid>

The helper never trusts the spool: it re-validates with the same code the agent used, against the root-owned /etc/ou-agent/agent.json. The
request names a key; the journal match / file path comes from the fixed tables in diagspec.py. journalctl is called with an argv list (no shell).
Every line is redacted (diagspec.redact_line) before it is written to the result; the total is capped."""
import json
import os
import pwd
import re
import stat
import subprocess
import sys
import time

from . import diagspec as d
from .proto import Reject

CONFIG = "/etc/ou-agent/agent.json"
SPOOL_DIR = "/run/ou-agent-spool"
RESULT_DIR = "/run/ou-rb-diag"
RID_RE = re.compile(r"^r[0-9a-f]{16}$")
JOURNALCTL = "/usr/bin/journalctl"
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "SYSTEMD_COLORS": "0", "SYSTEMD_PAGER": "", "SYSTEMD_LESS": ""}
TAIL_BYTES, TAIL_BYTES_GREP = 256 * 1024, 2 * 1024 * 1024


def _filter(lines, p):
    if p.get("grep"):
        rx = re.compile(d.GREPS[p["grep"]], re.IGNORECASE)
        lines = [ln for ln in lines if rx.search(ln)]
    return lines[-p["lines"]:]


def journal_argv(p, now=None, uid_of=lambda n: pwd.getpwnam(n).pw_uid):
    kind, unit = d.UNITS[p["unit"]]
    n = d.SCAN_LINES if p.get("grep") else p["lines"]
    if kind == "system":
        match = ["-u", unit]
    else:   # the rootless service user's unit: its own messages (container output) OR the user manager's messages about it, that uid only
        uid = str(int(uid_of(d.SERVICE_USER)))
        match = [f"_SYSTEMD_USER_UNIT={unit}", f"_UID={uid}", "+", f"USER_UNIT={unit}", f"_UID={uid}"]
    argv = [JOURNALCTL, "--no-pager", "-q", "-o", "short-iso", "--no-hostname", "-n", str(n), *match]
    if p.get("since_minutes"):
        argv.insert(-len(match), f"--since=@{int((now or time.time()) - 60 * p['since_minutes'])}")
    return argv


def read_journal(p):
    kind, unit = d.UNITS[p["unit"]]
    r = subprocess.run(journal_argv(p), shell=False, stdin=subprocess.DEVNULL, capture_output=True, timeout=45, env=ENV, cwd="/")
    if r.returncode != 0 and not r.stdout:
        return {"source": "unit", "key": p["unit"], "target": unit, "scope": kind, "lines": [], "error": "journalctl failed (rc %d): %s"
                % (r.returncode, d.redact_line(r.stderr.decode("utf-8", "replace").strip()[-300:]))}
    raw = r.stdout.decode("utf-8", "replace").splitlines()
    return {"source": "unit", "key": p["unit"], "target": unit, "scope": kind, "lines": _filter(raw, p)}


def read_file(p, path=None):
    path = path or d.FILES[p["file"]]
    out = {"source": "file", "key": p["file"], "target": path, "lines": []}
    try:
        # O_NOFOLLOW: a service user that owns the log directory cannot point the file at /etc/shadow; one link only (no hard-linked foreign file)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return {**out, "exists": False}
    except OSError as e:
        return {**out, "error": "cannot open the log file (%s)" % ("a symbolic link" if e.errno == 40 else type(e).__name__)}
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            return {**out, "error": "not a plain log file"}
        want = TAIL_BYTES_GREP if p.get("grep") else TAIL_BYTES
        start = max(0, st.st_size - want)
        f.seek(start)
        data = f.read(want)
    lines = data.decode("utf-8", "replace").splitlines()
    if start > 0 and lines:
        lines = lines[1:]   # the first line was cut by the seek
    return {**out, "exists": True, "size_bytes": st.st_size, "lines": _filter(lines, p)}


def journal(p):
    res = read_journal(p) if "unit" in p else read_file(p)
    lines, truncated = d.cap([d.redact_line(ln) for ln in res["lines"]])
    res.update(lines=lines, count=len(lines), truncated=truncated, redacted=True, requested=p["lines"])
    for k in ("grep", "since_minutes"):
        if p.get(k):
            res[k] = p[k]
    return res


def handle(req, cfg):
    if not isinstance(req, dict) or req.get("action") != d.DIAG_RUNBOOK or d.DIAG_RUNBOOK not in cfg.get("runbooks", {}):
        raise Reject("not_allowed", "action not allowed for this helper")
    return journal(d.check(req.get("params"), cfg["runbooks"][d.DIAG_RUNBOOK]))


def _write(path, text):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o640)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)


def main(argv):
    if len(argv) != 1 or not RID_RE.fullmatch(argv[0]):
        print("usage: diaghelper <rid>", file=sys.stderr)
        return 2
    rid = argv[0]
    result = {"rid": rid, "ts": int(time.time())}
    try:
        fd = os.open(os.path.join(SPOOL_DIR, rid + ".json"), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as f:
            req = json.loads(f.read(16384))
        with open(CONFIG) as f:
            cfg = json.load(f)
        result["result"] = handle(req, cfg)
    except Reject as r:
        result["rejected"] = {"code": r.code, "message": r.msg}
    except Exception as e:  # noqa: BLE001  never echo an exception text
        result["error"] = type(e).__name__
    os.makedirs(RESULT_DIR, mode=0o750, exist_ok=True)
    _write(os.path.join(RESULT_DIR, rid + ".json"), json.dumps(result))
    for fn in os.listdir(RESULT_DIR):   # results are read at once by the agent; anything older than 10 minutes goes
        p = os.path.join(RESULT_DIR, fn)
        try:
            if fn != rid + ".json" and time.time() - os.stat(p).st_mtime > 600:
                os.unlink(p)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
