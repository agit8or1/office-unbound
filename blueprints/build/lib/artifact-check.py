#!/usr/bin/env python3
"""Untrusted builder output (security review 4, H1). A builder runs upstream code as root, so everything it hands back is hostile until proven otherwise.
  artifact-check.py extract <dest-dir> <component> <build-root>  < tar-stream
        Reads the stream member by member and writes ONLY regular files of the flat artifact name set (no links, no devices, no directories, no
        paths) with O_CREAT|O_EXCL|O_NOFOLLOW mode 0644, then runs `verify`. Anything else aborts and removes <dest-dir>.
  artifact-check.py verify <dir> <component> <build-root>
        lstat every entry (regular file, link count 1, allowed name); every .deb is parsed with `dpkg-deb -f`: Package must be one of the recipe's
        packages (or its -dbgsym), Version must equal <upstream>-<ou_revision>, Architecture amd64/all; every .dsc must carry Source + Version of the
        same component and list only files that are present with matching sha256.
Exit 0 = acceptable, 1 = rejected (reason on stderr).
"""
import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile

import yaml

NAME_OK = re.compile(r"^(?:[A-Za-z0-9][A-Za-z0-9._+~:-]{0,200})$")
KIND_OK = re.compile(r"\.(deb|dsc|buildinfo|changes|txt|json|err|log)$|\.tar\.(xz|gz|zst|bz2)$|^SHA256SUMS$")


def reject(msg):
    print("REJECTED: " + msg, file=sys.stderr)
    sys.exit(1)


def recipe_expect(comp, root):
    r = yaml.safe_load(open(os.path.join(root, comp, "recipe.yaml")))
    rev = r.get("ou_revision")
    if not rev:
        for ln in open(os.path.join(root, "tools.env")):
            if ln.startswith("OU_REVISION="):
                rev = ln.split("=", 1)[1].strip()
    ver = "%s-%s" % (r["source"]["upstream_version"], rev)
    pk = set(r["packages"])
    return r["src_name"], ver, pk | {p + "-dbgsym" for p in pk}


def fields(path):
    p = subprocess.run(["dpkg-deb", "-f", path], capture_output=True, text=True)
    if p.returncode != 0:
        reject("%s: dpkg-deb cannot parse it" % os.path.basename(path))
    d = {}
    for ln in p.stdout.splitlines():
        m = re.match(r"^([A-Za-z0-9-]+):\s*(.*)$", ln)
        if m:
            d[m.group(1)] = m.group(2)
    return d


def verify(d, comp, root):
    src, ver, pkgs = recipe_expect(comp, root)
    names = []
    dd = os.lstat(d)
    if not stat.S_ISDIR(dd.st_mode):
        reject("%s is not a directory" % d)
    for n in sorted(os.listdir(d)):
        p = os.path.join(d, n)
        st = os.lstat(p)
        if not stat.S_ISREG(st.st_mode):
            reject("%s is not a regular file (mode %o)" % (n, st.st_mode))
        if st.st_nlink != 1:
            reject("%s has %d hard links" % (n, st.st_nlink))
        if not NAME_OK.match(n) or not KIND_OK.search(n):
            reject("file name %r not allowed" % n)
        names.append(n)
    for n in names:
        p = os.path.join(d, n)
        if n.endswith(".deb"):
            f = fields(p)
            if f.get("Package") not in pkgs:
                reject("%s: Package %r is not one of the recipe packages %s" % (n, f.get("Package"), sorted(pkgs)))
            if f.get("Version") != ver:
                reject("%s: Version %r != expected %r" % (n, f.get("Version"), ver))
            if f.get("Architecture") not in ("amd64", "all"):
                reject("%s: Architecture %r" % (n, f.get("Architecture")))
            if not n.startswith("%s_%s_" % (f["Package"], ver)):
                reject("%s: file name does not match control fields" % n)
        elif n.endswith(".dsc"):
            txt = open(p, encoding="utf8", errors="replace").read()
            if not re.search(r"^Source:\s*%s\s*$" % re.escape(src), txt, re.M) or not re.search(r"^Version:\s*%s\s*$" % re.escape(ver), txt, re.M):
                reject("%s: Source/Version do not match %s %s" % (n, src, ver))
            sec = re.search(r"^Checksums-Sha256:\n((?: .*\n?)+)", txt, re.M)
            if not sec:
                reject("%s: no Checksums-Sha256" % n)
            for ln in sec.group(1).splitlines():
                h, _, fn = ln.split()
                fp = os.path.join(d, fn)
                if not os.path.isfile(fp) or os.path.islink(fp) or hashlib.sha256(open(fp, "rb").read()).hexdigest() != h:
                    reject("%s: listed file %s missing or hash differs" % (n, fn))
    if not any(n.endswith(".deb") for n in names):
        reject("no .deb in the artifact set")
    print("artifact set ok: %d files, version %s" % (len(names), ver))


def extract(dest, comp, root):
    if os.path.exists(dest):
        shutil.rmtree(dest)
    os.makedirs(dest, mode=0o700)
    try:
        with tarfile.open(fileobj=sys.stdin.buffer, mode="r|*") as tf:
            for m in tf:
                name = m.name[2:] if m.name.startswith("./") else m.name
                if m.isdir() and name in ("", "."):
                    continue
                if not m.isreg():
                    reject("tar member %r is not a regular file (link/device/directory)" % m.name)
                if "/" in name or not NAME_OK.match(name):
                    reject("tar member name %r not allowed" % m.name)
                fd = os.open(os.path.join(dest, name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
                with os.fdopen(fd, "wb") as out:
                    shutil.copyfileobj(tf.extractfile(m), out)
        verify(dest, comp, root)
    except SystemExit:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    except Exception as e:           # a damaged stream is a rejection, too
        shutil.rmtree(dest, ignore_errors=True)
        reject("extraction failed: %s" % e)


if __name__ == "__main__":
    if len(sys.argv) != 5 or sys.argv[1] not in ("extract", "verify"):
        print(__doc__)
        sys.exit(2)
    (extract if sys.argv[1] == "extract" else verify)(*sys.argv[2:5])
