"""Run: python3 -m pytest scripts/tests   (stdlib-only scripts; pytest is the only dependency)."""
import importlib.util
import json
import pathlib
import subprocess
import sys

import pytest

S = pathlib.Path(__file__).resolve().parent.parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, S / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


cd, rn, rr = load("changelog_draft"), load("release_notes"), load("render_roadmap")


def test_classify_conventional_and_freeform():
    assert cd.classify("feat(portal): add about page") == ("Added", "**portal**: add about page")
    assert cd.classify("fix: retention sentinel")[0] == "Fixed"
    assert cd.classify("security: bound request size")[0] == "Security"
    assert cd.classify("feat!: drop v0 endpoint")[1].startswith("**BREAKING**")
    assert cd.classify("Merge branch 'x'")[0] is None
    assert cd.classify("docs: typo")[0] is None
    assert cd.classify("Fix production /catalog 500")[0] == "Fixed"
    assert cd.classify("Add telephony lab")[0] == "Added"
    assert cd.classify("Restore drill (files tier)")[0] == "Changed"
    assert cd.classify("Security review 4 report")[0] == "Security"


def test_draft_groups_dedups_and_flags_evidence():
    out = cd.draft(["feat: a thing", "feat: a thing", "fix: broke", "chore: bump", "Merge x"])
    assert out.lower().count("a thing") == 1 and "### Added" in out and "### Fixed" in out and "bump" not in out
    assert "TODO: add evidence link" in out
    assert "No user-visible commits" in cd.draft(["chore: x"])


def test_draft_from_a_real_git_repo(tmp_path):
    def g(*a):
        subprocess.run(["git", "-C", str(tmp_path), "-c", "user.email=t@t", "-c", "user.name=t", *a], check=True, capture_output=True)
    g("init", "-q")
    g("commit", "--allow-empty", "-q", "-m", "feat: first")
    g("tag", "v0.0.1")
    g("commit", "--allow-empty", "-q", "-m", "fix: second")
    out = subprocess.run([sys.executable, str(S / "changelog_draft.py"), "--repo", str(tmp_path)], capture_output=True, text=True, check=True).stdout
    assert "second" in out.lower() and "first" not in out.lower()


SAMPLE = """# Changelog

## [Unreleased]

### Added
- next

## [0.2.0] - 2027-01-01

### Added
- see [doc](docs/x.md)

## [0.1.0] - 2026-11-15

### Added
- old

[Unreleased]: https://example.invalid/compare
[0.2.0]: https://example.invalid/0.2.0
[0.1.0]: https://example.invalid/0.1.0
"""


def test_release_notes_extracts_section_and_absolutizes_links():
    n = rn.notes("0.2.0", SAMPLE, "https://example.invalid/r")
    assert "see [doc](https://example.invalid/r/blob/v0.2.0/docs/x.md)" in n and "next" not in n and "old" not in n
    assert "compare/v0.1.0...v0.2.0" in n and "pre-release" in n
    with pytest.raises(SystemExit):
        rn.notes("0.9.9", SAMPLE)
    with pytest.raises(SystemExit):
        rn.notes("Unreleased", SAMPLE)


def test_repo_changelog_and_feed_are_consistent():
    assert rn.check() == 0


def test_roadmap_release_validation_rejects_bad_feeds():
    d = json.loads((S.parent / "docs" / "progress.json").read_text())
    rr.validate_releases(d)
    bad = json.loads(json.dumps(d)); bad["current_version"] = "9.9.9"
    with pytest.raises(AssertionError):
        rr.validate_releases(bad)
    bad = json.loads(json.dumps(d)); bad["releases"][0]["date"] = "yesterday"
    with pytest.raises(AssertionError):
        rr.validate_releases(bad)
    bad = json.loads(json.dumps(d)); bad["releases"][0]["status"] = "shipped"
    with pytest.raises(AssertionError):
        rr.validate_releases(bad)
