#!/usr/bin/env python3
"""Faithful fakes of the node-side tools used by SSH onboarding (ADR-0014), driven by tests/pve_sim.py data (real PVE 9 JSON shapes).

Installed by tests/ssh_node.py as symlinks (pvesh, pveum, sudo, install, mv, rm, cat, sha256sum, visudo, useradd, userdel, passwd, getent) on the PATH of
a REAL OpenSSH server that runs as the test user. Absolute paths are mapped under $OU_FAKE_ROOT. Every executed command is appended (argv, one JSON
line) to $OU_FAKE_ROOT/executed.log so tests can assert that only templates ran. pvesh/pveum talk to the PVE simulator (SIM_URL) as root@pam."""
import json
import os
import ssl
import subprocess
import sys
import urllib.parse
import urllib.request

ROOT = os.environ["OU_FAKE_ROOT"]
SIM = os.environ.get("SIM_URL", "")
PW = os.environ.get("SIM_ROOT_PW", "")
LOCAL = os.environ.get("FAKE_LOCAL_NODE", "")
NAME = os.path.basename(sys.argv[0])


def log(argv):
    with open(os.path.join(ROOT, "executed.log"), "a") as f:
        f.write(json.dumps([NAME] + argv) + "\n")


def m(p: str) -> str:
    return ROOT + p if p.startswith("/") and not p.startswith("/dev/") and not p.startswith(ROOT) else p


def real(tool: str) -> str:
    for d in ("/usr/bin", "/bin", "/usr/sbin"):
        if os.path.exists(f"{d}/{tool}"):
            return f"{d}/{tool}"
    raise SystemExit(f"no real {tool}")


def api(method, path, data=None, ticket=None):
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(SIM + "/api2/json" + path, data=body, method=method)
    if ticket:
        req.add_header("Cookie", "PVEAuthCookie=" + ticket["ticket"])
        if method != "GET":
            req.add_header("CSRFPreventionToken", ticket["CSRFPreventionToken"])
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=20) as r:
            return json.loads(r.read())["data"]
    except urllib.error.HTTPError as e:
        sys.stderr.write(f"{e.code} {e.reason}: {e.read().decode(errors='replace')[:200]}\n")
        sys.exit(255)


def login():
    return api("POST", "/access/ticket", {"username": "root@pam", "password": PW})


def opt(args, name, default=None):
    return args[args.index(name) + 1] if name in args else default


def pvesh(a):
    assert a[0] == "get" and opt(a, "--output-format") == "json"
    path = a[1]
    q = {k: opt(a, "--" + k) for k in ("type", "full", "userid") if opt(a, "--" + k) is not None}
    out = api("GET", path + ("?" + urllib.parse.urlencode(q) if q else ""), ticket=login())
    if path == "/cluster/status":   # the real pvesh marks the node it runs on
        for n in out:
            if n.get("type") == "node":
                n["local"] = 1 if n["name"] == LOCAL else 0
    print(json.dumps(out))


def pveum(a):
    t = login()
    if a[:2] == ["user", "add"]:
        api("POST", "/access/users", {"userid": a[2], "comment": opt(a, "--comment", ""), "enable": opt(a, "--enable", "1")}, t)
    elif a[:2] == ["user", "delete"]:
        api("DELETE", "/access/users/" + urllib.parse.quote(a[2], safe="@"), None, t)
    elif a[:3] == ["user", "token", "add"]:
        out = api("POST", f"/access/users/{urllib.parse.quote(a[3], safe='@')}/token/{a[4]}", {"privsep": opt(a, "--privsep", "1"), "comment": opt(a, "--comment", "")}, t)
        print(json.dumps(out))
    elif a[:3] == ["user", "token", "remove"]:
        api("DELETE", f"/access/users/{urllib.parse.quote(a[3], safe='@')}/token/{a[4]}", None, t)
    elif a[:2] == ["role", "add"]:
        api("POST", "/access/roles", {"roleid": a[2], "privs": opt(a, "--privs")}, t)
    elif a[:2] == ["role", "modify"]:
        api("PUT", "/access/roles/" + a[2], {"privs": opt(a, "--privs")}, t)
    elif a[:2] == ["role", "delete"]:
        api("DELETE", "/access/roles/" + a[2], None, t)
    elif a[:2] == ["acl", "modify"]:
        d = {"path": a[2], "roles": opt(a, "--roles"), "propagate": opt(a, "--propagate", "1")}
        for k in ("users", "tokens"):
            if opt(a, "--" + k):
                d[k] = opt(a, "--" + k)
        if opt(a, "--delete"):
            d["delete"] = opt(a, "--delete")
        api("PUT", "/access/acl", d, t)
    elif a[:2] == ["pool", "add"]:
        api("POST", "/pools", {"poolid": a[2], "comment": opt(a, "--comment", "")}, t)
    elif a[:2] == ["pool", "delete"]:
        api("DELETE", "/pools/" + a[2], None, t)
    else:
        sys.stderr.write("pveum: unsupported in the fake\n")
        sys.exit(2)


def state(name):
    return os.path.join(ROOT, "state", name)


def main():
    a = sys.argv[1:]
    log(a)
    if NAME == "pvesh":
        pvesh(a)
    elif NAME == "pveum":
        pveum(a)
    elif NAME == "sudo":
        rest = [x for x in a if x not in ("-n", "--")]
        if not rest:
            sys.exit(1)
        cmd = rest[0]
        if cmd.startswith("/"):
            cmd = m(cmd)
        os.execvp(cmd, [cmd] + rest[1:])
    elif NAME == "install":
        args, skip, out = [], False, []
        for i, x in enumerate(a):
            if skip:
                skip = False
            elif x in ("-o", "-g"):
                skip = True
            else:
                out.append(x)
        os.execv(real("install"), ["install"] + [m(x) for x in out])
    elif NAME in ("mv", "rm", "cat"):
        os.execv(real(NAME), [NAME] + [m(x) if x.startswith("/") else x for x in a])
    elif NAME == "sha256sum":
        os.execv(real("sha256sum"), ["sha256sum", m(a[0])])
    elif NAME == "visudo":
        p = m(a[-1])
        txt = open(p).read() if os.path.exists(p) else ""
        sys.exit(0 if ("ALL=(root)" in txt and txt.endswith("\n")) else 1)
    elif NAME in ("lvs", "zfs"):
        f = state("lvs.json" if NAME == "lvs" else "zfs.txt")
        if not os.path.exists(f):
            sys.stderr.write(f"{NAME}: not available on this fake node\n")
            sys.exit(127)
        sys.stdout.write(open(f).read())
    elif NAME == "getent":
        sys.exit(0 if os.path.exists(state("user-" + a[1])) else 2)
    elif NAME == "useradd":
        name = a[-1]
        home = opt(a, "--home-dir")
        os.makedirs(os.path.join(ROOT, "state"), exist_ok=True)
        open(state("user-" + name), "w").write(json.dumps({"args": a}))
        os.makedirs(m(home), exist_ok=True)
    elif NAME == "usermod":
        open(state("locked-" + a[-1]), "w").write(a[1] + a[2])
    elif NAME == "userdel":
        name = a[-1]
        for f in ("user-" + name, "locked-" + name):
            if os.path.exists(state(f)):
                os.remove(state(f))
        subprocess.run([real("rm"), "-rf", ROOT + "/var/lib/" + name])
    else:
        sys.exit(127)


main()
