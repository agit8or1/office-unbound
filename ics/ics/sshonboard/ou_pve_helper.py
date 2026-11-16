#!/usr/bin/python3
"""ou-pve-helper: the ONLY thing the Office Unbound ICS SSH identity can run on this Proxmox node (ADR-0014).

Installed root-owned at /usr/local/sbin/ou-pve-helper. It is the forced command of the `ou-ics` account's authorized key
(restrict,command="sudo -n /usr/local/sbin/ou-pve-helper") and the only program sudoers lets that account run (no arguments, no wildcards).
It reads SSH_ORIGINAL_COMMAND, accepts ONLY the operations below with strictly validated arguments and executes fixed argv lists without a shell.
There is no shell, no pveum passthrough, no way to add users, roles, privileges or ACL entries or to widen anything: it can read, rotate the
ICS's own token and NARROW (delete) the ICS's own ACL entries.

  self-check                       hashes of this helper and of its config
  discover KIND [NODE]             read-only: pvesh GET of a fixed path (see DISCOVER / NODE_KINDS), `storage-lvm` (lvs report), `storage-zfs` (zfs list)
  cert-read                        print the PVE API certificate (PEM)
  drift                            effective permissions of the ICS's own user and tokens
  token-rotate NAME                delete + re-create one of the ICS's own tokens (privsep=1); prints the pveum JSON once
  acl-narrow PATH ROLE SUBJECT     delete one ACL entry of the ICS's own user/token for one of the ICS's own roles
"""
import hashlib
import json
import os
import re
import subprocess
import sys

CONF_PATH = "/etc/office-unbound/ou-pve-helper.json"
CERTS = ("/etc/pve/local/pveproxy-ssl.pem", "/etc/pve/local/pve-ssl.pem")
VERSION = 1
# A non-root euid means a developer/test run: honour OU_HELPER_ROOT (a path prefix) and use bare tool names. As root (production, via sudo) the
# environment is ignored entirely (sudo also resets it).
TEST = os.geteuid() != 0
ROOT = os.environ.get("OU_HELPER_ROOT", "") if TEST else ""
PVESH = "pvesh" if TEST else "/usr/bin/pvesh"
PVEUM = "pveum" if TEST else "/usr/sbin/pveum"

DISCOVER = {
    "version": "/version", "cluster-status": "/cluster/status", "nodes": "/nodes", "storage": "/storage", "pools": "/pools",
    "resources": "/cluster/resources", "roles": "/access/roles", "users": "/access/users", "acl": "/access/acl", "fw-cluster": "/cluster/firewall/options",
}
NODE_KINDS = {"network": "/nodes/{n}/network", "fw-options": "/nodes/{n}/firewall/options", "fw-rules": "/nodes/{n}/firewall/rules"}
LVS = "lvs" if TEST else "/usr/sbin/lvs"
ZFS = "zfs" if TEST else "/usr/sbin/zfs"
OK_LINE = re.compile(r"[A-Za-z0-9 ._:@!/+-]{1,300}")
ARG = re.compile(r"[A-Za-z0-9/][A-Za-z0-9._:@!/+-]{0,200}")
NODE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}")


def refuse(msg: str, code: int = 126):
    sys.stderr.write("ou-pve-helper: refused: " + msg + "\n")
    sys.exit(code)


def sha(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def conf() -> dict:
    with open(ROOT + CONF_PATH) as f:
        c = json.load(f)
    if c.get("version") != VERSION or not re.fullmatch(r"[A-Za-z0-9._-]{1,32}@pve", c.get("user", "")):
        refuse("bad helper configuration", 70)
    return c


def run(argv: list[str]) -> str:
    p = subprocess.run(argv, capture_output=True, text=True, timeout=60, shell=False, stdin=subprocess.DEVNULL)
    if p.returncode != 0:
        sys.stderr.write(p.stderr[-800:])
        sys.exit(p.returncode or 1)
    return p.stdout


def pvesh(path: str, *extra: str) -> str:
    return run([PVESH, "get", path, "--output-format", "json", *extra])


def main() -> None:
    cmd = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    if not OK_LINE.fullmatch(cmd):
        refuse("unsupported characters or empty command")
    parts = cmd.split(" ")
    op, args = parts[0], parts[1:]
    if any(not ARG.fullmatch(a) for a in args):
        refuse("malformed argument")
    c = None
    if op == "self-check" and not args:
        c = conf()
        out = {"version": VERSION, "helper_sha256": sha(os.path.abspath(__file__)), "conf_sha256": sha(ROOT + CONF_PATH), "user": c["user"]}
        print(json.dumps(out))
    elif op == "discover" and 1 <= len(args) <= 2:
        kind = args[0]
        if kind in NODE_KINDS and len(args) == 2 and NODE.fullmatch(args[1]):
            sys.stdout.write(pvesh(NODE_KINDS[kind].format(n=args[1])))
        elif kind == "storage-lvm" and len(args) == 1:
            sys.stdout.write(run([LVS, "--reportformat", "json", "--units", "b", "--nosuffix", "-o", "lv_name,vg_name,lv_size,data_percent,metadata_percent,pool_lv,lv_attr"]))
        elif kind == "storage-zfs" and len(args) == 1:
            sys.stdout.write(run([ZFS, "list", "-Hp", "-t", "filesystem,volume", "-o", "name,used,avail,volsize,refreservation"]))
        elif kind in DISCOVER and len(args) == 1:
            sys.stdout.write(pvesh(DISCOVER[kind], *(["--type", "vm"] if kind == "resources" else [])))
        else:
            refuse("unknown discovery kind")
    elif op == "cert-read" and not args:
        for p in CERTS:
            if os.path.exists(ROOT + p):
                with open(ROOT + p) as f:
                    sys.stdout.write(f.read())
                return
        refuse("no certificate found", 1)
    elif op == "drift" and not args:
        c = conf()
        for subj in [c["user"]] + [f"{c['user']}!{t}" for t in c["tokens"]]:
            print(json.dumps({"subject": subj, "permissions": json.loads(pvesh("/access/permissions", "--userid", subj))}))
    elif op == "token-rotate" and len(args) == 1:
        c = conf()
        if args[0] not in c["tokens"]:
            refuse("not one of the ICS's own tokens")
        subprocess.run([PVEUM, "user", "token", "remove", c["user"], args[0]], capture_output=True, timeout=60, shell=False, stdin=subprocess.DEVNULL)
        sys.stdout.write(run([PVEUM, "user", "token", "add", c["user"], args[0], "--privsep", "1", "--comment", "Office Unbound token rotated",
                              "--output-format", "json"]))
    elif op == "acl-narrow" and len(args) == 3:
        c = conf()
        path, role, subj = args
        own = [c["user"]] + [f"{c['user']}!{t}" for t in c["tokens"]]
        if subj not in own:
            refuse("subject is not one of the ICS's own identities")
        if role not in c["roles"]:
            refuse("role is not one of the ICS's own roles")
        if not path.startswith("/") or ".." in path:
            refuse("bad path")
        flag = "--tokens" if "!" in subj else "--users"
        run([PVEUM, "acl", "modify", path, "--roles", role, flag, subj, "--delete", "1"])
        print(json.dumps({"narrowed": [path, role, subj]}))
    else:
        refuse("operation not allowed")


if __name__ == "__main__":
    main()
