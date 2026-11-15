#!/usr/bin/python3
"""Canary reader. Runs INSIDE a tier machine (the live source while it is being backed up, or the scratch machine after a restore), READ-ONLY, and prints
one JSON object. The backup run records it from the live source; restore verification reads the same thing from the restored machine and compares.
usage: ou-backup-canary.py <tier> '<json config>'      (config is not secret: name patterns only)

files      canary document(s): sha256 + size of the current bytes, and sha256 of every stored version (REV blob) of that node
identity   canary directory entry (entryUUID) and the realm role that exists ONLY in the database (not in any import file)
groupware  canary mailbox: number of messages and sha256 over the sorted subject list (message ids are re-assigned by an import, subjects are not)
"""
import fnmatch
import hashlib
import json
import os
import subprocess
import sys

OC_STORAGE = "/var/lib/opencloud/storage"


def sha256_file(p: str) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def files(cfg: dict) -> dict:
    pat = cfg.get("name_glob", "ou-canary-*")
    out = {}
    for root, dirs, names in os.walk(OC_STORAGE):
        dirs[:] = [d for d in dirs if d != ".oc-nodes"]   # nodes are internal; the user-visible tree is walked
        for n in names:
            if not fnmatch.fnmatch(n, pat):
                continue
            p = os.path.join(root, n)
            try:
                nid = os.getxattr(p, "user.oc.id").decode()
            except OSError:
                nid = ""
            revs = []
            if nid:
                d = os.path.join(root.split("/.oc-nodes")[0], ".oc-nodes", nid[0:2], nid[2:4], nid[4:6], nid[6:8])
                stem = "-" + nid[8:] if nid[8:9] != "-" else nid[8:]
                try:
                    revs = sorted(sha256_file(os.path.join(d, f)) for f in os.listdir(d) if f.startswith(stem + ".REV."))
                except OSError:
                    pass
            out[n] = {"sha256": sha256_file(p), "size": os.stat(p).st_size, "versions": revs}
    return {"documents": out}


def run(*argv: str) -> str:
    return subprocess.run(argv, capture_output=True, text=True, check=True, timeout=60).stdout


def identity(cfg: dict) -> dict:
    uid = cfg.get("ldap_uid", "drillcanary")
    ldif = run("slapcat", "-n", "1", "-a", f"(uid={uid})")
    uuids = sorted(line.split(": ", 1)[1] for line in ldif.splitlines() if line.startswith("entryUUID: "))
    like = cfg.get("role_prefix", "drill-canary-")
    roles = run("sudo", "-u", "postgres", "psql", "-At", "-d", "keycloak", "-c",
                f"select name from keycloak_role where realm_id is not null and client_role = false and name like '{like}%' order by name").split()
    return {"ldap_entryuuid": uuids, "keycloak_roles": roles}


def groupware(cfg: dict) -> dict:
    user = cfg.get("mailbox", "alice@gw1.ou-lab.internal")
    d = run("mysql", "-N", "email", "-e", f"select maildir from users where username='{user}'").strip()
    q = ("select p.propval from messages m join message_properties p on p.message_id=m.message_id and p.proptag=236781599 "
         "where m.is_associated=0 and m.parent_attid is null and m.is_deleted=0 order by p.propval")
    subj = run("sqlite3", "-readonly", f"{d}/exmdb/exchange.sqlite3", q).splitlines()
    n = int(run("sqlite3", "-readonly", f"{d}/exmdb/exchange.sqlite3",
                "select count(*) from messages where is_associated=0 and parent_attid is null and is_deleted=0").strip())
    return {"mailbox": user, "messages": n, "subjects_sha256": hashlib.sha256("\n".join(subj).encode()).hexdigest(), "subjects_counted": len(subj)}


if __name__ == "__main__":
    tier, cfg = sys.argv[1], json.loads(sys.argv[2] if len(sys.argv) > 2 else "{}")
    fn = {"files": files, "identity": identity, "groupware": groupware}[tier]
    print(json.dumps(fn(cfg), sort_keys=True))
