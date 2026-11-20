"""Management access (ics/console_access.py, helper ics/deploy/public-entry/ou-console-access + ics/console_access_core.py): who may reach the
console under its public name. Model validation, the exact rendered include, the helper's closed input language, apply + rollback against
temporary files, and the typed action end to end with the helper stubbed."""
import io
import sys

import pytest
from pydantic import ValidationError
from sqlalchemy import text

from ics import console_access as ca
from ics import console_access_core as core
from ics import worker

H = "/api/v1"


# ---------------------------------------------------------------- model + render
def test_public_mode_allows_everyone_and_ignores_the_list():
    m = ca.ManagementAccess(mode="public", allowed=["10.0.0.0/8"])
    assert m.allowed == []
    assert ca.render_access_conf(m) == ("# Office Unbound: who may reach the ICS console under its public name (written by ou-console-access; "
                                        "Settings -> Network & domains)\n# mode: public\nallow all;\n")


def test_lan_vpn_defaults_to_the_lan_and_vpn_ranges():
    m = ca.ManagementAccess(mode="lan_vpn")
    assert m.allowed == ["192.168.22.0/24", "10.0.0.0/8"]
    assert ca.render_access_conf(m).splitlines()[1:] == ["# mode: lan_vpn", "allow 192.168.22.0/24;", "allow 10.0.0.0/8;", "deny all;"]


def test_allowlist_is_normalized_and_rendered_exactly():
    m = ca.ManagementAccess(mode="allowlist", allowed=[" 203.0.113.7 ", "198.51.100.9/24", "2001:db8::1/64", "203.0.113.7/32"])
    assert m.allowed == ["203.0.113.7/32", "198.51.100.0/24", "2001:db8::/64"]          # host bits cleared, duplicates dropped
    assert ca.render_access_conf(m).splitlines()[1:] == ["# mode: allowlist", "allow 203.0.113.7/32;", "allow 198.51.100.0/24;",
                                                         "allow 2001:db8::/64;", "deny all;"]


@pytest.mark.parametrize("bad", [
    {"mode": "allowlist", "allowed": []},
    {"mode": "allowlist", "allowed": ["0.0.0.0/0"]},
    {"mode": "allowlist", "allowed": ["::/0"]},
    {"mode": "allowlist", "allowed": ["1.2.3.4; deny all"]},
    {"mode": "allowlist", "allowed": ["all"]},
    {"mode": "allowlist", "allowed": ["example.com"]},
    {"mode": "allowlist", "allowed": [f"10.0.{i}.0/24" for i in range(33)]},
    {"mode": "open"},
    {"mode": "public", "extra": 1},
])
def test_invalid_settings_are_refused(bad):
    with pytest.raises(ValidationError):
        ca.ManagementAccess.model_validate(bad)


def test_rendered_files_pass_the_helpers_own_check():
    for m in (ca.ManagementAccess(), ca.ManagementAccess(mode="lan_vpn"), ca.ManagementAccess(mode="allowlist", allowed=["2001:db8::/48"])):
        conf = ca.render_access_conf(m)
        assert core.validate(conf.encode()) == conf


# ---------------------------------------------------------------- helper core
@pytest.mark.parametrize("bad", [
    b"allow all; include /etc/passwd;\n",
    b"return 200;\n",
    b"allow 1.2.3.4; deny all;\n",
    b"# comment only\n",
    b"",
    b"allow 1.2.3.4;\ninclude /etc/nginx/x.conf;\n",
    b"allow 1.2.3.4/33;\ndeny all;\n",
    b"allow 1.2.3.4;\r\ndeny all;\n",
    b"deny 1.2.3.4;\n",
    b" allow all;\n",
    b"allow all;\n" + b"#" * 9000,
    "# café\nallow all;\n".encode(),
])
def test_helper_refuses_anything_but_comments_and_allow_deny(bad):
    with pytest.raises(core.Refused):
        core.validate(bad)


def _fake(tmp_path, name, code):
    p = tmp_path / name
    p.write_text(f"import sys\nopen(sys.argv[1], 'a').write('{name}\\n')\nsys.exit({code})\n")
    return [sys.executable, str(p), str(tmp_path / "calls")]


def test_helper_applies_then_reloads(tmp_path):
    target = tmp_path / "ou-console-access.conf"
    target.write_text("# old\nallow all;\n")
    conf = ca.render_access_conf(ca.ManagementAccess(mode="lan_vpn"))
    rc = core.main(["apply"], io.BytesIO(conf.encode()), str(target), _fake(tmp_path, "test", 0), _fake(tmp_path, "reload", 0))
    assert rc == 0 and target.read_text() == conf
    assert (tmp_path / "ou-console-access.conf.prev").read_text() == "# old\nallow all;\n"
    assert (tmp_path / "calls").read_text() == "test\nreload\n"
    assert not (tmp_path / "ou-console-access.conf.new").exists()


def test_helper_restores_the_previous_file_when_nginx_rejects_it(tmp_path):
    target = tmp_path / "ou-console-access.conf"
    target.write_text("# old\nallow all;\n")
    rc = core.main(["apply"], io.BytesIO(b"allow 10.0.0.0/8;\ndeny all;\n"), str(target), _fake(tmp_path, "test", 1), _fake(tmp_path, "reload", 0))
    assert rc == 1 and target.read_text() == "# old\nallow all;\n"
    assert (tmp_path / "calls").read_text() == "test\n"                                   # never reloaded


def test_helper_refuses_bad_input_and_arguments_without_touching_the_file(tmp_path):
    target = tmp_path / "ou-console-access.conf"
    target.write_text("# old\nallow all;\n")
    t, r = _fake(tmp_path, "test", 0), _fake(tmp_path, "reload", 0)
    assert core.main(["apply"], io.BytesIO(b"allow all; include /etc/passwd;\n"), str(target), t, r) == 1
    assert core.main(["apply", "/etc/passwd"], io.BytesIO(b"allow all;\n"), str(target), t, r) == 2
    assert target.read_text() == "# old\nallow all;\n" and not (tmp_path / "calls").exists()


# ---------------------------------------------------------------- typed action end to end
def _run(adm, ah, apr, aph, rt, params):
    r = adm.post(f"{H}/plans", json={"action": "settings.management.update", "params": params}, headers=ah)
    assert r.status_code in (200, 201), r.text
    pid, jid = r.json()["plan_id"], r.json().get("job_id")
    if r.json()["status"] != "approved":
        a = apr.post(f"{H}/plans/{pid}/approve", headers=aph)
        assert a.status_code == 200, a.text
        jid = a.json()["job_id"]
    assert worker.run_once(rt)
    return adm.get(f"{H}/jobs/{jid}").json()


def test_the_action_applies_through_the_helper_then_stores_and_audits(rt, client, mk_user, login, monkeypatch):
    adm, ah = login(mk_user("boss", "admin"))
    apr, aph = login(mk_user("second", "approver"))
    op, oh = login(mk_user("op", "operator"))
    sent = []
    monkeypatch.setattr(ca, "apply_conf", lambda conf: sent.append(conf) or "applied")
    assert op.post(f"{H}/plans", json={"action": "settings.management.update", "params": {"mode": "lan_vpn"}}, headers=oh).status_code == 403
    assert adm.post(f"{H}/plans", json={"action": "settings.management.update", "params": {"mode": "allowlist", "allowed": ["0.0.0.0/0"]}},
                    headers=ah).status_code == 422
    assert adm.get(f"{H}/settings/network").json()["management"] == {"mode": "public", "allowed": []}
    job = _run(adm, ah, apr, aph, rt, {"mode": "allowlist", "allowed": ["203.0.113.0/24"]})
    assert job["status"] == "succeeded", job
    assert sent == [ca.render_access_conf(ca.ManagementAccess(mode="allowlist", allowed=["203.0.113.0/24"]))]
    ov = adm.get(f"{H}/settings/network").json()
    assert ov["management"] == {"mode": "allowlist", "allowed": ["203.0.113.0/24"]} and "your_address" in ov
    with rt.session() as db:
        row = db.execute(text("SELECT details FROM audit_events WHERE action = 'settings.management_access_updated'")).first()
    assert row.details["old"] == {"mode": "public", "allowed": []} and row.details["new"] == {"mode": "allowlist", "allowed": ["203.0.113.0/24"]}
    assert adm.get(f"{H}/audit/verify").json()["ok"] is True


def test_a_failed_apply_fails_the_job_and_keeps_the_old_setting(rt, client, mk_user, login, monkeypatch):
    adm, ah = login(mk_user("boss", "admin"))
    apr, aph = login(mk_user("second", "approver"))
    monkeypatch.setattr(ca, "apply_conf", lambda conf: "applied")
    assert _run(adm, ah, apr, aph, rt, {"mode": "lan_vpn"})["status"] == "succeeded"

    def refuse(conf):
        raise ca.ApplyError("the access helper refused or failed: nginx rejected the configuration")
    monkeypatch.setattr(ca, "apply_conf", refuse)
    job = _run(adm, ah, apr, aph, rt, {"mode": "allowlist", "allowed": ["203.0.113.0/24"]})
    assert job["status"] == "failed" and "nginx rejected" in str(job), job
    assert adm.get(f"{H}/settings/network").json()["management"] == {"mode": "lan_vpn", "allowed": ["192.168.22.0/24", "10.0.0.0/8"]}


def test_apply_conf_talks_to_the_root_helper_over_its_socket_and_reports_its_answer(tmp_path):
    """The console never runs anything as root (its sandbox forbids it): it hands the rules to ou-console-access.socket, where systemd starts
    the helper with the connection as stdin/stdout (Accept=yes). Here a thread plays systemd and runs the REAL helper core in socket mode."""
    import socket
    import threading
    target = tmp_path / "ou-console-access.conf"
    target.write_text("allow all;\n")
    sock = str(tmp_path / "h.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock)
    srv.listen(2)
    test_cmd = {"cmd": ["true"]}

    def serve():
        for _ in range(2):
            c, _a = srv.accept()
            with c:
                inp, out = c.makefile("rb"), io.StringIO()
                old = sys.stdout
                sys.stdout = out
                try:
                    core.main(["apply", "--socket"], inp, str(target), test_cmd["cmd"], ["true"])
                finally:
                    sys.stdout = old
                c.sendall(out.getvalue().encode())
    threading.Thread(target=serve, daemon=True).start()
    assert ca.apply_conf("allow 10.0.0.0/8;\ndeny all;\n", sock, 10).startswith("") and target.read_text() == "allow 10.0.0.0/8;\ndeny all;\n"
    test_cmd["cmd"] = ["false"]                                  # nginx -t refuses: the helper restores the previous file
    with pytest.raises(ca.ApplyError, match="refused or failed"):
        ca.apply_conf("allow 192.168.1.0/24;\ndeny all;\n", sock)
    assert target.read_text() == "allow 10.0.0.0/8;\ndeny all;\n"
    srv.close()
    with pytest.raises(ca.ApplyError, match="could not reach the access helper"):
        ca.apply_conf("allow all;\n", str(tmp_path / "missing.sock"))