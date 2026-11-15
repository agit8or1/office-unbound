"""Regenerate migration/requirements*.lock from ics/requirements.lock (same pinned hashes).

Run from the repository root: python3 migration/tools/mklock.py
"""
import re

t = open("ics/requirements.lock").read()
blocks = re.split(r"\n(?=\S)", t)


def pick(names):
    out = []
    for b in blocks:
        m = re.match(r"([A-Za-z0-9_.-]+)==", b)
        if m and m.group(1).lower() in names:
            out.append(re.sub(r"\n\s+# via.*", "", b.rstrip()))
    return "\n".join(out) + "\n"


RUNTIME = {"cryptography", "cffi", "pycparser"}
DEV = RUNTIME | {"pytest", "iniconfig", "packaging", "pluggy", "pygments"}
open("migration/requirements.lock", "w").write(
    "# runtime: cryptography (RS256 for the Google service-account JWT) + transitive.\n"
    "# Hashes copied from ics/requirements.lock.\n" + pick(RUNTIME))
open("migration/requirements-dev.lock", "w").write(
    "# runtime + pytest (test only). Hashes copied from ics/requirements.lock.\n" + pick(DEV))
open("migration/requirements.txt", "w").write("cryptography==50.0.2\n")
