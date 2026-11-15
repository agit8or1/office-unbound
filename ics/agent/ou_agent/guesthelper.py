"""Node-side executors for the guest runbooks. Started ONLY by the fixed template units ou-rb-podman@<rid>.service (User=ou-svc, no root)
and ou-rb-pkg@<rid>.service (root), which the agent may start through polkit. Usage: python3 -m ou_agent.guesthelper {podman|pkg} <rid>
The helper never trusts the spool file: it re-validates against the root-owned /etc/ou-agent/agent.json with the same code the agent used.
All commands are argv lists with absolute paths (no shell). Output: JSON result file in /run/ou-rb-<family>/<rid>.json."""
import json
import os
import re
import subprocess
import sys
import time

from . import guestspec as g
from .proto import Reject

CONFIG = "/etc/ou-agent/agent.json"
SPOOL_DIR = "/run/ou-agent-spool"
RESULT_ROOT = "/run"
PODMAN, SYSTEMCTL, APT_GET, DPKG_QUERY, GPG = "/usr/bin/podman", "/usr/bin/systemctl", "/usr/bin/apt-get", "/usr/bin/dpkg-query", "/usr/bin/gpg"
APT_DIR = "/etc/ou-agent/apt"                 # root-owned: sources.list + keyrings/ + pinned-fingerprints
APT_STATE = "/var/lib/ou-pkg"
RID_RE = re.compile(r"^r[0-9a-f]{16}$")
MAX_OUT = 4000


def home():
    return g.SERVICE_HOME


def user_env():
    uid = os.getuid()
    return {"PATH": "/usr/bin:/bin", "LANG": "C", "HOME": home(), "XDG_RUNTIME_DIR": f"/run/user/{uid}",
            "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{uid}/bus"}


def run(argv, env=None, timeout=120):
    return subprocess.run(argv, shell=False, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout,
                          env=env if env is not None else user_env())


def tail(s):
    return (s or "").strip()[-MAX_OUT:]


def dirs():
    cfgdir = os.path.join(home(), ".config/containers/systemd")
    data = os.path.join(home(), ".local/share/ou-agent")
    return cfgdir, os.path.join(data, "units"), os.path.join(data, "verified")


def atomic_write(path, text, mode=0o644):
    os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.replace(tmp, path)


def user_systemctl(*a, timeout=120):
    return run([SYSTEMCTL, "--user", "--no-ask-password", *a], timeout=timeout)


def unit_state(base):
    r = user_systemctl("show", "--property=ActiveState,SubState,NRestarts,Result", base + ".service", timeout=15)
    return dict(line.partition("=")[::2] for line in r.stdout.splitlines())


# ---------------------------------------------------------------- podman.pull_verified
def pull_verified(p, cfg):
    reg, repo, digest = g.parse_image(p["image"], cfg["runbooks"]["podman.pull_verified"]["registries"])
    # --signature-policy: the ROOT-owned policy (default reject; sigstoreSigned with the pinned key for the allowlisted registries). The
    # service user's own ~/.config/containers/policy.json is never consulted for this pull.
    r = run([PODMAN, "pull", "--quiet", "--signature-policy", g.POLICY_FILE, p["image"]], timeout=600)
    if r.returncode != 0:
        return {"verified": False, "image": p["image"], "error": tail(r.stderr)[-600:]}
    insp = run([PODMAN, "image", "inspect", "--format", "{{.Digest}}", p["image"]], timeout=30)
    got = insp.stdout.strip()
    if insp.returncode != 0 or got != digest:
        return {"verified": False, "image": p["image"], "error": "pulled digest does not match the pinned digest"}
    atomic_write(os.path.join(dirs()[2], digest.split(":")[1] + ".json"), json.dumps({"image": p["image"], "ts": int(time.time())}), 0o600)
    return {"verified": True, "image": p["image"], "digest": got, "policy": "sigstoreSigned"}


# ---------------------------------------------------------------- podman.deploy_unit / remove / status
def deploy_unit(p, cfg):
    s = g.check_deploy(p, cfg["runbooks"]["podman.deploy_unit"])
    cfgdir, unitdir, verdir = dirs()
    digest = s["image"].partition("@")[2].split(":")[1]
    if not os.path.exists(os.path.join(verdir, digest + ".json")):
        raise Reject("image_not_verified", "image was not pulled with podman.pull_verified on this node")
    if run([PODMAN, "image", "exists", s["image"]]).returncode != 0:
        raise Reject("image_missing", "verified image is not in local storage; pull it again")
    files = g.render(s)
    names = g.resource_names(s)
    changed = False
    for fn, text in files.items():
        path = os.path.join(cfgdir, fn)
        try:
            same = open(path).read() == text
        except FileNotFoundError:
            same = False
        if not same:
            atomic_write(path, text)
            changed = True
    base = names["base"]
    manifest = {"component": s["component"], "name": s["name"], "image": s["image"], "files": sorted(files),
                "volumes": sorted(names["volumes"].values()), "network": names["network"], "type": s["type"],
                "spec_sha256": g.spec_hash(s), "deployed_at": int(time.time())}
    atomic_write(os.path.join(unitdir, base + ".json"), json.dumps(manifest), 0o600)
    r = user_systemctl("daemon-reload")
    if r.returncode != 0:
        return {"unit": base, "started": False, "error": tail(r.stderr)}
    r = user_systemctl("restart" if changed else "start", base + ".service", timeout=150)
    st = {}
    for _ in range(30):
        st = unit_state(base)
        if st.get("ActiveState") in ("active", "failed"):
            break
        time.sleep(1)
    out = {"unit": base, "started": st.get("ActiveState") == "active", "active_state": st.get("ActiveState"), "sub_state": st.get("SubState"),
           "changed": changed, "spec_sha256": manifest["spec_sha256"]}
    if r.returncode != 0:
        out["error"] = tail(r.stderr)[-400:]
    return out


def _manifests(component=None):
    _, unitdir, _ = dirs()
    out = []
    try:
        names = sorted(os.listdir(unitdir))
    except FileNotFoundError:
        return out
    for fn in names:
        if fn.endswith(".json"):
            try:
                m = json.load(open(os.path.join(unitdir, fn)))
            except ValueError:
                continue
            if component is None or m.get("component") == component:
                out.append(m)
    return out


def remove_unit(p, cfg):
    cfgdir, unitdir, _ = dirs()
    base = g.unit_base(p["component"], p["name"])
    mpath = os.path.join(unitdir, base + ".json")
    try:
        m = json.load(open(mpath))
    except FileNotFoundError:
        return {"unit": base, "removed": False, "reason": "unknown unit"}
    user_systemctl("stop", base + ".service", timeout=100)
    others = [x for x in _manifests(p["component"]) if x["name"] != p["name"]]
    for fn in m["files"]:
        shared = any(fn in o["files"] for o in others)   # volume/network files used by a sibling unit stay
        if fn == base + ".container" or (p["purge_volumes"] and fn.endswith(".volume") and not shared) or (fn.endswith(".network") and not others):
            try:
                os.unlink(os.path.join(cfgdir, fn))
            except FileNotFoundError:
                pass
    os.unlink(mpath)
    user_systemctl("daemon-reload")
    run([PODMAN, "rm", "--force", "--ignore", base])
    purged = []
    if p["purge_volumes"]:
        for v in m["volumes"]:
            if not any(v in o["volumes"] for o in others) and run([PODMAN, "volume", "rm", "--force", v]).returncode == 0:
                purged.append(v)
    return {"unit": base, "removed": True, "purged_volumes": purged}


def status(p, cfg):
    units = []
    for m in _manifests(p.get("component")):
        base = g.unit_base(m["component"], m["name"])
        st = unit_state(base)
        health = run([PODMAN, "inspect", "--format", "{{.State.Status}}|{{.ImageDigest}}", base], timeout=20)
        cs, _, dg = health.stdout.strip().partition("|") if health.returncode == 0 else ("absent", "", "")
        units.append({"unit": base, "component": m["component"], "name": m["name"], "image": m["image"], "type": m["type"],
                      "active_state": st.get("ActiveState"), "sub_state": st.get("SubState"), "restarts": int(st.get("NRestarts") or 0),
                      "container_state": cs, "running_digest": dg, "digest_matches": dg == m["image"].partition("@")[2] if dg else None,
                      "spec_sha256": m["spec_sha256"]})
    return {"units": units}


def facts(p, cfg):
    osr = {}
    try:
        for line in open("/etc/os-release"):
            k, _, v = line.strip().partition("=")
            if k in ("ID", "VERSION_ID", "PRETTY_NAME"):
                osr[k.lower()] = v.strip('"')
    except OSError:
        pass
    mem = {}
    for line in open("/proc/meminfo"):
        k, _, v = line.partition(":")
        if k in ("MemTotal", "MemAvailable"):
            mem[k] = int(v.split()[0]) * 1024
    disks = {}
    for path in ("/", home()):
        try:
            st = os.statvfs(path)
            disks[path] = {"total_bytes": st.f_blocks * st.f_frsize, "free_bytes": st.f_bavail * st.f_frsize}
        except OSError:
            pass
    pv = run([PODMAN, "version", "--format", "{{.Client.Version}}"], timeout=20)
    rl = run([PODMAN, "info", "--format", "{{.Host.Security.Rootless}}"], timeout=30)
    from . import __version__
    return {"os": osr, "kernel": os.uname().release, "hostname": os.uname().nodename, "arch": os.uname().machine, "cpus": os.cpu_count(),
            "mem_total_bytes": mem.get("MemTotal"), "mem_available_bytes": mem.get("MemAvailable"), "disks": disks,
            "podman_version": pv.stdout.strip() or None, "podman_rootless": rl.stdout.strip() == "true",
            "uptime_seconds": int(float(open("/proc/uptime").read().split()[0])), "agent_version": __version__,
            "units": status({}, cfg)["units"]}


# ---------------------------------------------------------------- pkg.install_pinned (root)
def _apt_opts():
    return ["-o", f"Dir::Etc::sourcelist={APT_DIR}/sources.list", "-o", "Dir::Etc::sourceparts=/nonexistent",
            "-o", f"Dir::State::lists={APT_STATE}/lists", "-o", "Acquire::AllowInsecureRepositories=false",
            "-o", "Acquire::AllowDowngradeToInsecureRepositories=false", "-o", "APT::Get::AllowUnauthenticated=false"]


def _keyring_fingerprints():
    pinned = {l.strip().upper() for l in open(os.path.join(APT_DIR, "pinned-fingerprints")) if l.strip() and not l.startswith("#")}
    found = set()
    kd = os.path.join(APT_DIR, "keyrings")
    for fn in sorted(os.listdir(kd)):
        r = run([GPG, "--batch", "--no-default-keyring", "--show-keys", "--with-colons", os.path.join(kd, fn)], env={"PATH": "/usr/bin:/bin", "LANG": "C", "HOME": "/nonexistent"})
        found |= {l.split(":")[9].upper() for l in r.stdout.splitlines() if l.startswith("fpr:")}
    return pinned, found


def install_pinned(p, cfg):
    pinned, found = _keyring_fingerprints()
    if not found or not found <= pinned:    # every key in the allowlisted keyring dir must be pinned; an extra/replaced key stops the install
        raise Reject("repo_key_mismatch", "repository keyring does not match the pinned fingerprints")
    os.makedirs(APT_STATE + "/lists/partial", exist_ok=True)
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "DEBIAN_FRONTEND": "noninteractive"}
    u = run([APT_GET, "-q", *_apt_opts(), "update"], env=env, timeout=300)
    if u.returncode != 0:
        return {"installed": [], "error": "apt update failed: " + tail(u.stderr)[-300:]}
    specs = [f"{x['name']}={x['version']}" for x in p["packages"]]
    r = run([APT_GET, "-q", "-y", "--no-install-recommends", *_apt_opts(), "install", *specs], env=env, timeout=900)
    res = []
    for x in p["packages"]:
        q = run([DPKG_QUERY, "-W", "-f=${Version}", x["name"]], env=env, timeout=20)
        res.append({"name": x["name"], "wanted": x["version"], "installed": q.stdout.strip() or None, "ok": q.stdout.strip() == x["version"]})
    out = {"installed": res, "ok": r.returncode == 0 and all(x["ok"] for x in res)}
    if r.returncode != 0:
        out["error"] = tail(r.stderr)[-400:]
    return out


DISPATCH = {"podman.pull_verified": pull_verified, "podman.deploy_unit": deploy_unit, "podman.remove_unit": remove_unit,
            "podman.status": status, "guest.facts": facts, "pkg.install_pinned": install_pinned}


def main(argv):
    if len(argv) != 2 or argv[0] not in ("podman", "pkg") or not RID_RE.match(argv[1]):
        print("usage: guesthelper {podman|pkg} <rid>", file=sys.stderr)
        return 2
    fam, rid = argv
    fd = os.open(os.path.join(SPOOL_DIR, rid + ".json"), os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as f:
        req = json.loads(f.read(16384))
    with open(CONFIG) as f:
        cfg = json.load(f)
    result = {"rid": rid, "ts": int(time.time())}
    try:
        action = req["action"]
        if g.FAMILY_OF.get(action) != fam or action not in cfg["runbooks"]:
            raise Reject("not_allowed", "action not allowed for this helper")
        params = g.CHECKS[action](req["params"], cfg["runbooks"][action])
        result["result"] = DISPATCH[action](params, cfg)
    except Reject as r:
        result["rejected"] = {"code": r.code, "message": r.msg}
    except Exception as e:  # noqa: BLE001
        result["error"] = type(e).__name__
    out = os.path.join(RESULT_ROOT, f"ou-rb-{fam}", rid + ".json")
    atomic_write(out, json.dumps(result), 0o644)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
