#!/usr/bin/env python3
"""Read blueprints/build/<component>/recipe.yaml for build.sh.
  recipe.py vars <component>      -> shell assignments (eval-able)
  recipe.py field <component> a.b -> single value
"""
import os
import shlex
import sys

import yaml

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def load(c):
    with open(os.path.join(BASE, c, "recipe.yaml")) as f:
        return yaml.safe_load(f)


def main():
    cmd, comp = sys.argv[1], sys.argv[2]
    r = load(comp)
    if cmd == "field":
        v = r
        for k in sys.argv[3].split("."):
            v = v[k]
        print(v if not isinstance(v, (list, dict)) else yaml.safe_dump(v))
        return
    s, ver = r["source"], r["source"]["upstream_version"]
    out = {
        "COMPONENT": r["component"], "SRC_NAME": r["src_name"], "REPO": s["repo"], "TAG": s["tag"],
        "TAG_OBJECT": s.get("tag_object", ""), "COMMIT": s["commit"], "UPSTREAM_VERSION": ver,
        "SIGFPR": r.get("verification", {}).get("signer_fingerprint", ""),
        "VERKIND": r.get("verification", {}).get("kind", "sha-pin"),
        "PREFETCH": r.get("prefetch", ""), "OU_REVISION_C": r.get("ou_revision", ""), "PACKAGES": " ".join(r["packages"]),
    }
    for k, v in out.items():
        print(f"{k}={shlex.quote(str(v))}")


main()
