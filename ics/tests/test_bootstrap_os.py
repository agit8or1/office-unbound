"""bootstrap.sh platform detection (no root, no changes: --check-os exits before anything else)."""
import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "bootstrap.sh"


def check(tmp_path, body):
    f = tmp_path / "os-release"
    f.write_text(body)
    return subprocess.run(["bash", str(SCRIPT), "--check-os"], env={**os.environ, "OU_OS_RELEASE": str(f)}, capture_output=True, text=True)


@pytest.mark.parametrize("body,out", [
    ('ID=ubuntu\nVERSION_ID="24.04"\n', "noble 16"),
    ('ID=debian\nVERSION_ID="12"\n', "bookworm 15"),
])
def test_supported_platforms_pick_the_matching_postgresql(tmp_path, body, out):
    r = check(tmp_path, body)
    assert r.returncode == 0 and r.stdout.strip() == out


@pytest.mark.parametrize("body", [
    'ID=ubuntu\nVERSION_ID="22.04"\n', 'ID=debian\nVERSION_ID="13"\n', 'ID=debian\nVERSION_ID="11"\n', 'ID=fedora\nVERSION_ID="40"\n', "",
])
def test_other_platforms_are_refused(tmp_path, body):
    r = check(tmp_path, body)
    assert r.returncode == 1 and r.stdout.strip() == "unsupported"
