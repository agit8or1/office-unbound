#!/usr/bin/env python3
"""Read blueprints/build/<component>/recipe.yaml for build.sh.
  recipe.py vars <component>      -> shell assignments (eval-able)
  recipe.py field <component> a.b -> single value
"""
import os
import re
import shlex
import subprocess
import sys

import yaml

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def load(c):
    with open(os.path.join(BASE, c, "recipe.yaml")) as f:
        return yaml.safe_load(f)


def deb_version_from_tag(tag):
    """v0.1.1-dev.1 -> 0.1.1~dev.1 (Debian: a pre-release sorts BEFORE the release); v0.1.0 -> 0.1.0"""
    v = tag[1:] if tag.startswith("v") else tag
    if not re.fullmatch(r"\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?", v):
        sys.exit("tag %r is not vMAJOR.MINOR.PATCH[-prerelease]" % tag)
    return v.replace("-", "~", 1)


def main():
    cmd, comp = sys.argv[1], sys.argv[2]
    r = load(comp)
    if cmd == "field":
        v = r
        for k in sys.argv[3].split("."):
            v = v[k]
        print(v if not isinstance(v, (list, dict)) else yaml.safe_dump(v))
        return
    s, ver = dict(r["source"]), r["source"].get("upstream_version", "")
    if s.get("dynamic"):   # the ICS ships from THIS repository: the release tag (and optionally its commit) come from the operator, never from the recipe
        tag = os.environ.get("OU_ICS_TAG") or sys.exit("set OU_ICS_TAG=vX.Y.Z (the release tag to package)")
        s["tag"], s["commit"], s["tag_object"] = tag, os.environ.get("OU_ICS_COMMIT", ""), ""
        s["repo"] = os.environ.get("OU_ICS_REPO") or subprocess.check_output(["git", "-C", BASE, "rev-parse", "--show-toplevel"], text=True).strip()
        ver = deb_version_from_tag(tag)
    out = {
        "COMPONENT": r["component"], "SRC_NAME": r["src_name"], "REPO": s["repo"], "TAG": s["tag"],
        "TAG_OBJECT": s.get("tag_object", ""), "COMMIT": s["commit"], "UPSTREAM_VERSION": ver,
        "SIGFPR": r.get("verification", {}).get("signer_fingerprint", ""),
        "VERKIND": r.get("verification", {}).get("kind", "sha-pin"),
        "PREFETCH": r.get("prefetch", ""), "OU_REVISION_C": r.get("ou_revision", ""), "PACKAGES": " ".join(r["packages"]), "DYNAMIC": "1" if s.get("dynamic") else "0",
    }
    for k, v in out.items():
        print(f"{k}={shlex.quote(str(v))}")


main()
