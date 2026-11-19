"""Typed, strictly validated parameters for the guest runbooks, and the Quadlet renderer. Pure functions, stdlib only.
Used twice: by the agent (before anything is spooled) and again by the node-side helper (which re-validates; it never trusts the spool).
No free-form arguments exist anywhere: every field has a closed shape, every string a tight character class, and the generated
unit text is assembled from a fixed template, so no user value can add a key, a line or an option."""
import hashlib
import json
import re

from .proto import Reject

SERVICE_USER = "ou-svc"
SERVICE_HOME = "/var/lib/ou-svc"
POLICY_FILE = "/etc/ou-agent/image-policy.json"
PULLONLY_POLICY_FILE = "/etc/ou-agent/image-policy-pullonly.json"   # used ONLY after the agent verified the signature itself (podman without sigstore)
PUBKEY_FILE = "/etc/ou-agent/image-signing.pub"
GUEST_RUNBOOKS = ("podman.pull_verified", "podman.deploy_unit", "podman.remove_unit", "podman.status", "guest.facts", "pkg.install_pinned")
PODMAN_FAMILY = ("podman.pull_verified", "podman.deploy_unit", "podman.remove_unit", "podman.status", "guest.facts")  # run as ou-svc
FAMILY_OF = {**{a: "podman" for a in PODMAN_FAMILY}, "pkg.install_pinned": "pkg"}

NAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,30}[a-z0-9]$")
REGISTRY_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,120}[a-z0-9])?(:[0-9]{1,5})?$")
REPO_RE = re.compile(r"^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*){0,5}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ENVKEY_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
ENVVAL_RE = re.compile(r"^[A-Za-z0-9_./:@,+=-]{0,256}$")        # no space, quote, backslash, $, %, newline
VOLNAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,30}[a-z0-9]$")
MOUNT_RE = re.compile(r"^/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+){0,6}$")
FORBIDDEN_MOUNT_PREFIXES = ("/proc", "/sys", "/dev", "/run", "/etc", "/boot", "/var/run", "/root")
IPV4_RE = re.compile(r"^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$")
PKGNAME_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]{1,62}$")
PKGVER_RE = re.compile(r"^[0-9][A-Za-z0-9.+~:-]{0,63}$")
PKG_MATCH = ("exact", "floor")
SECRET_RE = re.compile(r"^[a-z][a-z0-9-]{1,40}$")
USER_RE = re.compile(r"^[0-9]{1,5}(:[0-9]{1,5})?$")
UNIT_TYPES = ("container", "container-hostnet")                  # host networking only when the spec says so explicitly
MAX_ENV, MAX_PORTS, MAX_VOLUMES, MAX_SECRETS, MAX_PACKAGES = 32, 16, 8, 8, 8
CMDWORD_RE = re.compile(r"^[a-z][a-z0-9-]{0,30}$")
MAX_COMMAND = 4
# capabilities a unit may get back after DropCapability=ALL. Only SYS_CHROOT: the document engine (Collabora coolforkit-ns) chroots every document
# process into its jail; with an empty bounding set that chroot fails with EPERM even inside its own user namespace (the bounding set survives
# CLONE_NEWUSER + execve), no document process ever starts and coolwsd never answers HTTP (real VM e2e-fo6; reproduced in the lab, 2026-11-19).
UNIT_CAPS = ("SYS_CHROOT",)


def _exact(p, keys, required=None):
    if not isinstance(p, dict) or not set(p) <= set(keys) or not set(keys if required is None else required) <= set(p):
        raise Reject("bad_params", "unexpected or missing parameters")


def _s(v, rx, what):
    if not isinstance(v, str) or not rx.fullmatch(v):
        raise Reject("bad_params", f"invalid {what}")
    return v


def _int(v, lo, hi, what):
    if type(v) is not int or not lo <= v <= hi:
        raise Reject("bad_params", f"invalid {what}")
    return v


def _bool(v, what):
    if type(v) is not bool:
        raise Reject("bad_params", f"{what} must be boolean")
    return v


def parse_image(ref, registries):
    """registry/repo@sha256:<64 hex>, nothing else: a tag, a missing registry, a missing digest or an unlisted registry is refused."""
    if not isinstance(ref, str) or len(ref) > 400 or "@" not in ref or "/" not in ref:
        raise Reject("bad_params", "image must be <registry>/<repo>@sha256:<digest>")
    name, _, digest = ref.partition("@")
    reg, _, repo = name.partition("/")
    if ":" in repo or not REGISTRY_RE.fullmatch(reg) or not REPO_RE.fullmatch(repo) or not DIGEST_RE.fullmatch(digest):
        raise Reject("bad_params", "image must be <registry>/<repo>@sha256:<digest> (digest-pinned, no tag)")
    if reg not in registries:
        raise Reject("not_allowed", "registry is not allowlisted on this node")
    return reg, repo, digest


def unit_base(component, name):
    return f"ou-{component}-{name}"


def check_pull(p, cfg):
    _exact(p, ("image",))
    parse_image(p["image"], cfg.get("registries", []))
    return {"image": p["image"]}


def check_deploy(p, cfg):
    _exact(p, ("component", "name", "type", "image", "env", "ports", "volumes", "secrets", "user", "read_only", "memory_mib", "command",
                  "capabilities"),
           ("component", "name", "type", "image"))
    out = {"component": _s(p["component"], NAME_RE, "component"), "name": _s(p["name"], NAME_RE, "name")}
    if len(unit_base(out["component"], out["name"])) > 60:
        raise Reject("bad_params", "component+name too long")
    if p["type"] not in UNIT_TYPES:
        raise Reject("bad_params", f"type must be one of {', '.join(UNIT_TYPES)}")
    out["type"] = p["type"]
    parse_image(p["image"], cfg.get("registries", []))
    out["image"] = p["image"]
    env = p.get("env", {})
    if not isinstance(env, dict) or len(env) > MAX_ENV:
        raise Reject("bad_params", "env must be an object with at most %d entries" % MAX_ENV)
    out["env"] = {_s(k, ENVKEY_RE, "env key"): _s(v, ENVVAL_RE, "env value") for k, v in sorted(env.items())}
    ports = p.get("ports", [])
    if not isinstance(ports, list) or len(ports) > MAX_PORTS or (ports and out["type"] == "container-hostnet"):
        raise Reject("bad_params", "ports: list of at most %d (none with host networking)" % MAX_PORTS)
    out["ports"] = []
    for x in ports:
        _exact(x, ("bind", "host", "container", "proto"))
        if x["proto"] not in ("tcp", "udp"):
            raise Reject("bad_params", "invalid proto")
        out["ports"].append({"bind": _s(x["bind"], IPV4_RE, "bind address"), "host": _int(x["host"], 1024, 65535, "host port"),
                             "container": _int(x["container"], 1, 65535, "container port"), "proto": x["proto"]})
    vols = p.get("volumes", [])
    if not isinstance(vols, list) or len(vols) > MAX_VOLUMES:
        raise Reject("bad_params", "volumes: list of at most %d" % MAX_VOLUMES)
    out["volumes"] = []
    for x in vols:
        _exact(x, ("name", "path", "read_only"), ("name", "path"))   # a NAMED volume of this component; host paths do not exist in this schema
        path = _s(x["path"], MOUNT_RE, "mount path")
        if ".." in path.split("/") or any(path == f or path.startswith(f + "/") for f in FORBIDDEN_MOUNT_PREFIXES):
            raise Reject("bad_params", "mount path is not allowed")
        v = {"name": _s(x["name"], VOLNAME_RE, "volume name"), "path": path, "read_only": _bool(x.get("read_only", False), "read_only")}
        if any(v["name"] == o["name"] or path == o["path"] for o in out["volumes"]):
            raise Reject("bad_params", "duplicate volume name or mount path")
        out["volumes"].append(v)
    secrets_ = p.get("secrets", [])
    if not isinstance(secrets_, list) or len(secrets_) > MAX_SECRETS:
        raise Reject("bad_params", "secrets: list of at most %d" % MAX_SECRETS)
    out["secrets"] = []
    for x in secrets_:
        _exact(x, ("name", "env"))  # an existing podman secret exposed as an environment variable; secret values never pass through here
        out["secrets"].append({"name": _s(x["name"], SECRET_RE, "secret name"), "env": _s(x["env"], ENVKEY_RE, "secret env")})
    out["user"] = _s(p["user"], USER_RE, "user") if p.get("user") is not None else None
    out["read_only"] = _bool(p.get("read_only", True), "read_only")
    out["memory_mib"] = _int(p.get("memory_mib", 512), 16, 65536, "memory_mib")
    cmd = p.get("command", [])   # arguments to the image's entrypoint (e.g. OpenCloud's `collaboration server`): plain words only, no options/paths
    if not isinstance(cmd, list) or len(cmd) > MAX_COMMAND:
        raise Reject("bad_params", "command: list of at most %d words" % MAX_COMMAND)
    if cmd:   # only when set: a spec without a command keeps its earlier spec_hash
        out["command"] = [_s(w, CMDWORD_RE, "command word") for w in cmd]
    caps = p.get("capabilities", [])
    if not isinstance(caps, list) or any(c not in UNIT_CAPS for c in caps) or len(set(caps)) != len(caps):
        raise Reject("bad_params", "capabilities: distinct values from " + ", ".join(UNIT_CAPS))
    if caps:   # only when set: a spec without capabilities keeps its earlier spec_hash
        out["capabilities"] = sorted(caps)
    return out


def check_remove(p, cfg):
    _exact(p, ("component", "name", "purge_volumes"), ("component", "name"))
    return {"component": _s(p["component"], NAME_RE, "component"), "name": _s(p["name"], NAME_RE, "name"),
            "purge_volumes": _bool(p.get("purge_volumes", False), "purge_volumes")}


def check_status(p, cfg):
    _exact(p, ("component",), ())
    return {"component": _s(p["component"], NAME_RE, "component")} if "component" in p else {}


def check_facts(p, cfg):
    _exact(p, (), ())
    return {}


def check_pkg(p, cfg):
    _exact(p, ("packages",))
    pk = p["packages"]
    if not isinstance(pk, list) or not 1 <= len(pk) <= MAX_PACKAGES:
        raise Reject("bad_params", "packages: 1..%d entries" % MAX_PACKAGES)
    allowed, out = cfg.get("packages", []), []
    for x in pk:
        _exact(x, ("name", "version", "match"), ("name", "version"))
        n = _s(x["name"], PKGNAME_RE, "package name")
        if n not in allowed:
            raise Reject("not_allowed", "package is not allowlisted on this node")
        m = x.get("match", "exact")
        if m not in PKG_MATCH:
            raise Reject("bad_params", "package match must be exact or floor")
        # exact: this version, no ranges/wildcards (our own repository). floor: the distro archive's current version, never older than this one
        # (an Ubuntu/Debian archive keeps only the newest build per pocket, so an exact pin breaks on every security update: real VM e2e-fo3)
        out.append({"name": n, "version": _s(x["version"], PKGVER_RE, "package version"), "match": m})
    if len({o["name"] for o in out}) != len(out):
        raise Reject("bad_params", "duplicate package")
    return {"packages": out}


CHECKS = {"podman.pull_verified": check_pull, "podman.deploy_unit": check_deploy, "podman.remove_unit": check_remove,
          "podman.status": check_status, "guest.facts": check_facts, "pkg.install_pinned": check_pkg}


def validate_runbook_config(name, c):
    if name in ("podman.pull_verified", "podman.deploy_unit"):
        if not isinstance(c, dict) or "registries" not in c or not set(c) <= {"registries", "insecure"} or not isinstance(c["registries"], list) \
                or not c["registries"] or not all(isinstance(r, str) and REGISTRY_RE.fullmatch(r) for r in c["registries"]) \
                or not isinstance(c.get("insecure", []), list) or not set(c.get("insecure", [])) <= set(c["registries"]):
            raise ValueError(f"{name} takes {{\"registries\": [host[:port], ...], \"insecure\": [subset of registries, optional]}}")
    elif name == "pkg.install_pinned":
        if not isinstance(c, dict) or set(c) != {"packages"} or not isinstance(c["packages"], list) or \
                not all(isinstance(r, str) and PKGNAME_RE.fullmatch(r) for r in c["packages"]):
            raise ValueError("pkg.install_pinned takes exactly {\"packages\": [name, ...]}")
    elif c != {"enabled": True}:
        raise ValueError(f"{name} takes exactly {{\"enabled\": true}}")


# ---------------------------------------------------------------- Quadlet rendering
def resource_names(s):
    base = unit_base(s["component"], s["name"])
    return {"base": base, "container_file": base + ".container",
            "volumes": {v["name"]: f"ou-{s['component']}-{v['name']}" for v in s["volumes"]},
            "network": None if s["type"] == "container-hostnet" else f"ou-{s['component']}"}


def render(s):
    """{filename: text} for a validated spec: the .container, one .volume per named volume, and the component .network."""
    n = resource_names(s)
    hdr = "# generated by ou-agent (podman.deploy_unit); do not edit"
    files = {}
    for v in s["volumes"]:
        vn = n["volumes"][v["name"]]
        files[vn + ".volume"] = f"{hdr}\n[Volume]\nVolumeName={vn}\nLabel=ou.component={s['component']}\n"
    if n["network"]:
        files[n["network"] + ".network"] = f"{hdr}\n[Network]\nNetworkName={n['network']}\nLabel=ou.component={s['component']}\n"
    c = [hdr, "[Unit]", f"Description=Office Unbound {s['component']}/{s['name']}"]
    c += ["", "[Container]", f"Image={s['image']}", "Pull=never", f"ContainerName={n['base']}", "NoNewPrivileges=true", "DropCapability=ALL",
          f"ReadOnly={'true' if s['read_only'] else 'false'}", f"Label=ou.component={s['component']}", f"Label=ou.unit={s['name']}",
          f"PodmanArgs=--memory={s['memory_mib']}m"]
    c += [f"AddCapability={x}" for x in s.get("capabilities", [])]
    c.append("Network=host" if s["type"] == "container-hostnet" else f"Network={n['network']}.network")
    if s["user"]:
        c.append(f"User={s['user']}")
    for k, v in s["env"].items():
        c.append(f"Environment={k}={v}")
    for sec in s["secrets"]:
        c.append(f"Secret={sec['name']},type=env,target={sec['env']}")
    for pt in s["ports"]:
        c.append(f"PublishPort={pt['bind']}:{pt['host']}:{pt['container']}/{pt['proto']}")
    for v in s["volumes"]:
        c.append(f"Volume={n['volumes'][v['name']]}.volume:{v['path']}" + (":ro" if v["read_only"] else ""))
    if s.get("command"):
        c.append("Exec=" + " ".join(s["command"]))
    c += ["", "[Service]", "Restart=always", "TimeoutStartSec=120", "", "[Install]", "WantedBy=default.target", ""]
    files[n["container_file"]] = "\n".join(c)
    return files


def spec_hash(s):
    return hashlib.sha256(json.dumps(s, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# ---------------------------------------------------------------- plain systemd unit rendering (podman < 4.4: no Quadlet generator)
# Debian 12 ships podman 4.3.1, which has no Quadlet. The same validated spec is then rendered as an ordinary systemd USER unit that runs
# `podman run` with the same confinement. Every interpolated value passed the closed character classes above (no whitespace, quote, `$`,
# `%` or backslash can occur), so systemd's argv splitting cannot be influenced by the spec.
PODMAN_BIN = "/usr/bin/podman"


def render_service(s):
    """{filename: text} (one .service) for a validated spec; networks/volumes are created by ExecStartPre (idempotent)."""
    n = resource_names(s)
    hdr = "# generated by ou-agent (podman.deploy_unit, plain unit: no Quadlet on this podman); do not edit"
    # --cgroup-manager=cgroupfs: with the default (systemd) manager podman 4.3.1 inside a user service asks crun for
    # .../user@UID.service/user.slice/libpod-<id>.scope, which does not exist -> "crun: create directory ...: No such file or directory"
    # (real Debian 12 VM). cgroupfs inside the delegated user cgroup keeps the memory limit (--cgroups=disabled would drop it).
    run = [PODMAN_BIN, "--cgroup-manager=cgroupfs", "run", "--rm", "--name", n["base"], "--cap-drop=ALL", "--security-opt=no-new-privileges",
           f"--read-only={'true' if s['read_only'] else 'false'}", f"--memory={s['memory_mib']}m",
           f"--label=ou.component={s['component']}", f"--label=ou.unit={s['name']}"]
    run += [f"--cap-add={x}" for x in s.get("capabilities", [])]
    if s["type"] == "container-hostnet":
        run.append("--network=host")
    # no per-component network on this path: rootless `podman run --network=<user-defined>` fails on Debian 12's podman 4.3.1 with "unable to find
    # network" although `network create` succeeded (real VM, docs/status/first-real-deployment.md). The default rootless network is used instead;
    # units of one component therefore cannot resolve each other by name until the guest has a Quadlet-capable podman.
    if s["user"]:
        run.append(f"--user={s['user']}")
    for k, v in s["env"].items():
        run.append(f"--env={k}={v}")
    for sec in s["secrets"]:
        run.append(f"--secret={sec['name']},type=env,target={sec['env']}")
    for pt in s["ports"]:
        run.append(f"--publish={pt['bind']}:{pt['host']}:{pt['container']}/{pt['proto']}")
    for v in s["volumes"]:
        run.append(f"--volume={n['volumes'][v['name']]}:{v['path']}" + (":ro" if v["read_only"] else ""))
    run.append(s["image"])
    run.extend(s.get("command") or [])
    pre = [f"ExecStartPre=-{PODMAN_BIN} rm --force --ignore {n['base']}"]
    for v in s["volumes"]:
        pre.append(f"ExecStartPre=-{PODMAN_BIN} volume create --label ou.component={s['component']} {n['volumes'][v['name']]}")
    lines = [hdr, "[Unit]", f"Description=Office Unbound {s['component']}/{s['name']}", "", "[Service]", "Restart=always", "TimeoutStartSec=120",
             *pre, "ExecStart=" + " ".join(run), f"ExecStop={PODMAN_BIN} stop --time 10 {n['base']}", "", "[Install]", "WantedBy=default.target", ""]
    return {n["base"] + ".service": "\n".join(lines)}
