"""Security review 7 H-2 (client side): strict channel check on the guest's own apt fetch."""
import pytest


def _lists(tmp_path, suite, body):
    d = tmp_path / "lists"
    d.mkdir(exist_ok=True)
    (d / f"repo.example_dists_{suite}_InRelease").write_text(body + "\n-----BEGIN PGP SIGNATURE-----\nx\n")
    return str(d)


def _setup(tmp_path, monkeypatch, suite="stable"):
    from ou_agent import guesthelper as gh
    monkeypatch.setattr(gh, "APT_DIR", str(tmp_path))
    (tmp_path / "sources.list").write_text(f"deb [signed-by=/etc/ou-agent/apt/keyrings/ou-repo.asc] https://repo.example/apt {suite} main\n")
    return gh


def test_h2_dev_release_served_as_stable_is_refused(tmp_path, monkeypatch):
    from ou_agent.proto import Reject
    gh = _setup(tmp_path, monkeypatch)
    lists = _lists(tmp_path, "stable", "Origin: Office Unbound\nSuite: dev\nCodename: dev\nDate: x")
    with pytest.raises(Reject) as e:
        gh._check_channel_release(lists)
    assert e.value.code == "release_channel_mismatch"


def test_h2_matching_release_is_accepted_and_missing_is_refused(tmp_path, monkeypatch):
    from ou_agent.proto import Reject
    gh = _setup(tmp_path, monkeypatch)
    gh._check_channel_release(_lists(tmp_path, "stable", "Origin: Office Unbound\nSuite: stable\nCodename: stable"))
    gh = _setup(tmp_path, monkeypatch, suite="staging")
    with pytest.raises(Reject):
        gh._check_channel_release(str(tmp_path / "lists"))


def test_h2_apt_is_told_to_treat_release_info_changes_as_errors():
    from ou_agent import guesthelper as gh
    assert "Acquire::AllowReleaseInfoChange=false" in gh._apt_opts()


def test_distro_suites_are_not_subject_to_the_channel_contract(tmp_path, monkeypatch):
    """artifacts-core lab run: `noble-updates` has Codename=noble; the check refused every distro package install. Only the OU repo is checked."""
    gh = _setup(tmp_path, monkeypatch)
    (tmp_path / "sources.list").write_text(
        "deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] http://archive.ubuntu.com/ubuntu noble-updates main\n"
        "deb [signed-by=/etc/ou-agent/apt/keyrings/ou-repo.asc] https://repo.example/apt stable main\n")
    d = tmp_path / "lists"
    d.mkdir()
    (d / "archive.ubuntu.com_ubuntu_dists_noble-updates_InRelease").write_text("Suite: noble-updates\nCodename: noble\n-----BEGIN PGP SIGNATURE-----\nx\n")
    (d / "repo.example_dists_stable_InRelease").write_text("Suite: stable\nCodename: stable\n-----BEGIN PGP SIGNATURE-----\nx\n")
    gh._check_channel_release(str(d))
