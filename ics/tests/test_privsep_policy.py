"""Argument policy of the lab-workflow shims (ics/deploy/privsep/lib/ou-lab-policy). No database, no root: the real program is replaced by a recorder."""
import importlib.machinery
import importlib.util
import io
from pathlib import Path

import pytest

POLICY = Path(__file__).resolve().parents[1] / "deploy" / "privsep" / "lib" / "ou-lab-policy"


@pytest.fixture()
def pol(monkeypatch):
    loader = importlib.machinery.SourceFileLoader("ou_lab_policy", str(POLICY))
    spec = importlib.util.spec_from_loader("ou_lab_policy", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    calls = []
    monkeypatch.setattr(mod.os, "execv", lambda path, argv: calls.append((path, argv)))
    mod.calls = calls
    return mod


def run(pol, tool, *args):
    pol.calls.clear()
    pol.REAL = dict(pol.REAL)
    getattr(pol, "p_" + tool.replace("-", "_") if tool != "systemd-run" else "p_run")(list(args))
    return pol.calls[0] if pol.calls else None


def refused(pol, tool, *args):
    with pytest.raises(SystemExit) as e:
        run(pol, tool, *args)
    assert e.value.code == 77
    assert not pol.calls


@pytest.mark.parametrize("args", [
    ("-M", ".host", "id"), ("-M", "ou-x", "-M", ".host", "id"), ("--machine=ou-x", "-M", "ou-y", "id"), ("id",), ("-M", "ou-x"),
    ("-M", "ou-x", "--host=root@y", "id"), ("-M", "ou-x", "--user", "id"), ("-M", "ou-base-noble", "id"), ("-M", "ou-x/../etc", "id"),
    ("-M", "OU-x", "id"), ("-M", "ou-x", "--machine", "ou-y", "id"), ("-M", "ou-" + "a" * 40, "id"), ("-M", "ou-x", "-H", "h", "id"),
])
def test_systemd_run_refusals(pol, args):
    refused(pol, "systemd-run", *args)


def test_systemd_run_allowed_forms_are_rebuilt(pol):
    path, argv = run(pol, "systemd-run", "-M", "ou-pkg1", "--wait", "--pipe", "-q", "/bin/bash", "-c", "echo hi; id")
    assert path == "/usr/bin/systemd-run"
    # options come first, the caller's command follows a literal "--": nothing after it can be parsed as an option
    assert argv == ["/usr/bin/systemd-run", "-M", "ou-pkg1", "--wait", "--pipe", "-q", "--", "/bin/bash", "-c", "echo hi; id"]
    _, argv = run(pol, "systemd-run", "--machine=ou-id1", "-p", "MemoryMax=1G", "--", "-M", ".host")
    assert argv[-3:] == ["--", "-M", ".host"] and argv[1:3] == ["-M", "ou-id1"]  # a later -M is only an argument of the command inside the machine


@pytest.mark.parametrize("args", [
    ("remove", "ou-base-noble"), ("poweroff", "ou-base-bookworm"), ("clone", "ou-pkg1", "ou-base-noble"), ("start", "../x"), ("shell", "ou-x"),
    ("copy-to", "ou-x", "/etc/shadow", "/x"), ("show",), ("--host=a", "list"), ("list", "extra"), ("clone", "ou-x"), ("terminate", "ou-base-x"),
])
def test_machinectl_refusals(pol, args):
    refused(pol, "machinectl", *args)


def test_machinectl_allowed(pol):
    assert run(pol, "machinectl", "clone", "ou-base-noble", "ou-priv1")[1] == ["/usr/bin/machinectl", "clone", "ou-base-noble", "ou-priv1"]
    assert run(pol, "machinectl", "start", "ou-base-noble")  # starting is not destructive
    assert run(pol, "machinectl", "list")


@pytest.mark.parametrize("args", [
    ("restart", "ics"), ("set-property", "ics.service", "MemoryMax=1G"), ("set-property", "systemd-nspawn@ou-x.service", "CPUShares=1"),
    ("set-property", "systemd-nspawn@ou-base-noble.service", "MemoryMax=1G"), ("set-property", "systemd-nspawn@ou-x.service", "MemoryMax=1G;id"),
])
def test_systemctl_refusals(pol, args):
    refused(pol, "systemctl", *args)


def test_systemctl_allowed(pol):
    assert run(pol, "systemctl", "set-property", "systemd-nspawn@ou-pkg1.service", "MemoryMax=3G")
    assert run(pol, "systemctl", "set-property", "--runtime", "systemd-nspawn@ou-pkg1.service", "MemoryMax=infinity")


@pytest.mark.parametrize("args", [("-d", "/etc"), ("-e", "/var/lib/machines/../../etc"), ("-d", "/var/lib/machines/ou-x/../..")])
def test_test_refusals(pol, args):
    refused(pol, "test", *args)


def test_tee_only_fixed_template(pol, monkeypatch, tmp_path):
    monkeypatch.setattr(pol.sys, "stdin", type("S", (), {"buffer": io.BytesIO(b"[Exec]\nBinds=/\n")})())
    with pytest.raises(SystemExit) as e:
        pol.p_tee(["/etc/systemd/nspawn/ou-x.nspawn"])
    assert e.value.code == 77
    for bad in (["/etc/passwd"], ["/etc/systemd/nspawn/ou-base-noble.nspawn"], ["/etc/systemd/nspawn/../../passwd"], []):
        monkeypatch.setattr(pol.sys, "stdin", type("S", (), {"buffer": io.BytesIO(pol.NSPAWN_TEMPLATES[0].encode())})())
        with pytest.raises(SystemExit) as e:
            pol.p_tee(bad)
        assert e.value.code == 77
