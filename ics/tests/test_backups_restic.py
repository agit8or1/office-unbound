"""Retention math cross-checked against the real restic (`forget --dry-run`) on a throwaway local repository with synthetic snapshot times.
Skipped when restic is not installed (the product pins 0.19.1; the lab host has it in /usr/local/bin)."""
import json
import os
import random
import shutil
import subprocess
from datetime import datetime, timedelta, timezone

import pytest

from ics.backups import policy as pol

RESTIC = shutil.which("restic") or "/usr/local/bin/restic"
pytestmark = pytest.mark.skipif(not os.path.exists(RESTIC), reason="restic not installed")


def r(repo, *args, env=None):
    e = {"PATH": "/usr/bin:/bin", "RESTIC_PASSWORD": "test-only-password-0123456789", "RESTIC_CACHE_DIR": os.path.join(repo, "..", "cache")}
    return subprocess.run([RESTIC, "-r", repo, *args], env=e, capture_output=True, text=True, check=True).stdout


@pytest.mark.parametrize("seed,keep", [(1, (2, 7, 4, 6)), (2, (0, 3, 2, 1)), (3, (1, 0, 0, 3)), (5, (3, 14, 8, 12)), (6, (0, 300, 0, 0)), (7, (0, 0, 100, 0))])
def test_retention_matches_restic(tmp_path, seed, keep):
    repo = str(tmp_path / "repo")
    src = tmp_path / "data"
    src.mkdir()
    (src / "f").write_text("x")
    r(repo, "init")
    rnd = random.Random(seed)
    t = datetime(2026, 1, 3, 12, 0, tzinfo=timezone.utc)
    for _ in range(32):   # irregular gaps: several per day, skipped days, week and month boundaries
        t += timedelta(hours=rnd.choice([3, 7, 20, 26, 50, 130, 400]))
        (src / "f").write_text(str(t))
        r(repo, "backup", str(src), "--time", t.strftime("%Y-%m-%d %H:%M:%S"), "--quiet")
    snaps = json.loads(r(repo, "snapshots", "--json"))
    parsed = [(s["id"], datetime.fromisoformat(s["time"]).astimezone(timezone.utc)) for s in snaps]
    last, daily, weekly, monthly = keep
    args = []
    for n, v in zip(("last", "daily", "weekly", "monthly"), keep):
        if v:
            args += [f"--keep-{n}", str(v)]
    out = json.loads(r(repo, "forget", "--dry-run", "--json", *args))
    want = {x["id"] for g in out for x in (g.get("keep") or [])}
    got = set(pol.retention_keep(parsed, pol.Retention(last=last, daily=daily, weekly=weekly, monthly=monthly)))
    assert got == want, (sorted(got - want), sorted(want - got))
