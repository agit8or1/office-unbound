"""Security review 5 H3: the root PBX helper must not follow a symlink planted by the (compromised) agent when it creates the one-time secret file."""
import importlib.machinery
import importlib.util
import json
import os
import stat

import pytest

HELPER = os.path.join(os.path.dirname(__file__), "..", "agent", "deploy", "runbooks", "ou-pbx-user")


@pytest.fixture(scope="module")
def helper():
    loader = importlib.machinery.SourceFileLoader("ou_pbx_user_helper", HELPER)
    spec = importlib.util.spec_from_loader("ou_pbx_user_helper", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)          # must not run main() on import
    return mod


ME, MYG = os.getuid(), os.getgid()


def test_planted_dangling_symlink_is_not_followed(helper, tmp_path):
    d = tmp_path / "sec"
    d.mkdir()
    victim = tmp_path / "etc-ld.so.preload"                    # does not exist: the classic root-creates-it target
    (d / "pbx-issue-alice.web.json").symlink_to(victim)
    helper.write_secret(str(d), "pbx-issue-alice.web.json", b'{"password":"x"}', ME, ME, MYG)
    assert not victim.exists()                                   # nothing was created through the link
    f = d / "pbx-issue-alice.web.json"
    assert not f.is_symlink() and json.loads(f.read_bytes())["password"] == "x"
    assert stat.S_IMODE(f.stat().st_mode) == 0o600


def test_symlink_to_existing_file_does_not_touch_target(helper, tmp_path):
    d = tmp_path / "sec"
    d.mkdir()
    victim = tmp_path / "victim"
    victim.write_text("keep")
    os.chmod(victim, 0o644)
    (d / "pbx-issue-alice.web.json").symlink_to(victim)
    helper.write_secret(str(d), "pbx-issue-alice.web.json", b"{}", ME, ME, MYG)
    assert victim.read_text() == "keep" and stat.S_IMODE(victim.stat().st_mode) == 0o644


def test_race_replanted_entry_fails_closed(helper, tmp_path, monkeypatch):
    """the agent re-plants the link between our unlink and our open: O_EXCL|O_NOFOLLOW must refuse, never follow"""
    d = tmp_path / "sec"
    d.mkdir()
    victim = tmp_path / "victim2"
    real_open = os.open

    def racing_open(path, flags, mode=0o777, *, dir_fd=None):
        if path == "pbx-issue-bob.web.json":
            os.symlink(str(victim), path, dir_fd=dir_fd)
        return real_open(path, flags, mode, dir_fd=dir_fd)
    monkeypatch.setattr(os, "open", racing_open)
    with pytest.raises(OSError):
        helper.write_secret(str(d), "pbx-issue-bob.web.json", b"{}", ME, ME, MYG)
    assert not victim.exists()


def test_directory_swapped_for_symlink_or_foreign_owner_is_replaced(helper, tmp_path):
    real = tmp_path / "elsewhere"
    real.mkdir()
    d = tmp_path / "sec"
    d.symlink_to(real)                                           # an old/agent-made path component
    helper.write_secret(str(d), "pbx-issue-a.web.json", b"{}", ME, ME, MYG)
    assert not d.is_symlink() and d.is_dir() and not list(real.iterdir())
    assert stat.S_IMODE(d.stat().st_mode) == 0o1770


def test_directory_owned_by_someone_else_is_refused_or_rebuilt(helper, tmp_path):
    d = tmp_path / "sec"
    d.mkdir()
    # helper identity "root" = uid ME+1: the existing directory is not ours -> rebuilt, and it must then be created for that identity
    with pytest.raises(SystemExit):
        helper.write_secret(str(d), "pbx-issue-a.web.json", b"{}", ME + 1, ME, MYG)


def test_name_is_validated(helper, tmp_path):
    for bad in ("../x", "a/b", "", "x" * 200):
        with pytest.raises(SystemExit):
            helper.write_secret(str(tmp_path / "s"), bad, b"{}", ME, ME, MYG)
