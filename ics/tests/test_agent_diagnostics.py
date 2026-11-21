"""Node agent `guest.journal` (agent/ou_agent/diagspec.py, diaghelper.py): closed schema, fixed sources, redaction, size cap, the root helper's
re-validation and its file handling (no symlink, no hard link), the template unit's confinement, polkit, first boot and the bundle."""
import json
import os
import subprocess
import sys

import pytest

from ou_agent import diaghelper as h
from ou_agent import diagspec as d
from ou_agent import firstboot, runbooks
from ou_agent.proto import Reject

AGENT = os.path.join(os.path.dirname(__file__), "..", "agent")
CFG = {"listen": {"address": "0.0.0.0", "port": 8443}, "runbooks": {"guest.journal": {"enabled": True}}}


# ---------------------------------------------------------------- schema
def test_valid_requests_are_normalised():
    assert d.check({"unit": "php8.3-fpm", "lines": 300}) == {"unit": "php8.3-fpm", "lines": 300}
    assert d.check({"unit": "keycloak", "lines": 1, "since_minutes": 1440, "grep": "error"}) == {"unit": "keycloak", "lines": 1, "since_minutes": 1440, "grep": "error"}
    assert d.check({"file": "nginx-error", "lines": 20, "grep": None, "since_minutes": None}) == {"file": "nginx-error", "lines": 20}


@pytest.mark.parametrize("p, code", [
    ({"unit": "sshd", "lines": 10}, "not_allowed"),
    ({"unit": "nginx.service", "lines": 10}, "not_allowed"),               # the key, never the unit name
    ({"unit": "ou-identity-keycloak", "lines": 10}, "not_allowed"),
    ({"file": "../../etc/shadow", "lines": 10}, "not_allowed"),
    ({"file": "/var/log/nginx/error.log", "lines": 10}, "not_allowed"),
    ({"file": "nginx-error/../../../etc/shadow", "lines": 10}, "not_allowed"),
    ({"file": ["nginx-error"], "lines": 10}, "not_allowed"),
    ({"unit": "nginx", "lines": 301}, "bad_params"),
    ({"unit": "nginx", "lines": 0}, "bad_params"),
    ({"unit": "nginx", "lines": "10"}, "bad_params"),
    ({"unit": "nginx", "lines": True}, "bad_params"),
    ({"unit": "nginx"}, "bad_params"),
    ({"lines": 5}, "bad_params"),
    ({"unit": "nginx", "file": "nginx-error", "lines": 5}, "bad_params"),
    ({"unit": "nginx", "lines": 5, "since_minutes": 1441}, "bad_params"),
    ({"unit": "nginx", "lines": 5, "since_minutes": 0}, "bad_params"),
    ({"file": "nginx-error", "lines": 5, "since_minutes": 5}, "bad_params"),
    ({"unit": "nginx", "lines": 5, "grep": "pass.*"}, "bad_params"),
    ({"unit": "nginx", "lines": 5, "grep": "error|password"}, "bad_params"),
    ({"unit": "nginx", "lines": 5, "path": "/etc/shadow"}, "bad_params"),
    ("nginx", "bad_params"),
])
def test_anything_else_is_refused(p, code):
    with pytest.raises(Reject) as e:
        d.check(p)
    assert e.value.code == code


def test_the_fixed_tables_name_only_plain_units_and_absolute_log_paths():
    for kind, unit in d.UNITS.values():
        assert kind in ("system", "user") and runbooks.UNIT_RE.fullmatch(unit.rsplit(".", 1)[0]) and unit.endswith((".service", ".timer"))
    for path in d.FILES.values():
        assert path.startswith("/var/log/") and ".." not in path.split("/") and "*" not in path
    import re
    for rx in d.GREPS.values():
        re.compile(rx)


def test_agent_config_capability_and_dispatch():
    runbooks.validate_config(CFG)
    assert runbooks.capabilities(CFG) == {"guest.journal": {"enabled": True}}
    with pytest.raises(ValueError):
        runbooks.validate_config({"listen": {}, "runbooks": {"guest.journal": {"enabled": True, "units": ["sshd"]}}})
    assert runbooks.check_allowed(CFG, "guest.journal", {"unit": "nginx", "lines": 5}) == {"unit": "nginx", "lines": 5}
    with pytest.raises(Reject):
        runbooks.check_allowed({"runbooks": {}}, "guest.journal", {"unit": "nginx", "lines": 5})   # not enabled on this node


def test_spool_unit_and_result(tmp_path, monkeypatch):
    spool, res = tmp_path / "spool", tmp_path / "run"
    spool.mkdir()
    (res / "ou-rb-diag").mkdir(parents=True)
    monkeypatch.setattr(runbooks, "SPOOL_DIR", str(spool))
    monkeypatch.setattr(runbooks, "RESULT_ROOT", str(res))
    seen = {}

    def fake_systemctl(*a, timeout=60):
        seen["argv"] = a
        rid = a[-1].split("@")[1].split(".")[0]
        seen["req"] = json.loads((spool / (rid + ".json")).read_text())
        (res / "ou-rb-diag" / (rid + ".json")).write_text(json.dumps({"rid": rid, "result": {"lines": ["x"]}}))
        return subprocess.CompletedProcess(a, 0, "", "")
    monkeypatch.setattr(runbooks, "_systemctl", fake_systemctl)
    out = runbooks.execute("guest.journal", {"unit": "nginx", "lines": 5})
    assert seen["argv"][:2] == ("start", "--wait") and seen["argv"][2].startswith("ou-rb-diag@r")
    assert seen["req"] == {"action": "guest.journal", "params": {"unit": "nginx", "lines": 5}}
    assert out == {"returncode": 0, "result": {"lines": ["x"]}} and os.listdir(spool) == []


# ---------------------------------------------------------------- redaction
@pytest.mark.parametrize("line, secret", [
    ("Authorization: Bearer abcdefghijklmnop", "abcdefghijklmnop"),
    ("proxy said bearer AbC123xyz789", "AbC123xyz789"),
    ("id_token eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJib2IifQ.c2lnbmF0dXJl", "eyJzdWIiOiJib2IifQ"),
    ("GET /web/?code=4f1c2b9a-aa&session_state=77ab HTTP/1.1", "4f1c2b9a-aa"),
    ("POST /login password=hunter2&user=bob", "hunter2"),
    ("client_secret=S3cr3tValue rest", "S3cr3tValue"),
    ("x access_token=tok123&y=1", "tok123"),
    ("Cookie: PHPSESSID=abcd1234; KEYCLOAK_IDENTITY=zzz", "abcd1234"),
    ("Set-Cookie: grommunio_sid=deadbeef; path=/", "deadbeef"),
    ('{"password":"s3cr3t","user":"bob"}', "s3cr3t"),
    ("$config['db_password'] => 'pw-in-php'", "pw-in-php"),
    ("ldap bind password: hunter22 failed", "hunter22"),
    ("Basic YWxhZGRpbjpvcGVuc2VzYW1l", "YWxhZGRpbjpvcGVuc2VzYW1l"),
    ("X-Auth-Token: abc", "abc"),
    ("key aB3dE5fG7hJ9kL1mN3pQ5rS7tU", "aB3dE5fG7hJ9kL1mN3pQ5rS7tU"),
    ("-----BEGIN PRIVATE KEY-----MIIEvQIBADANBg-----END PRIVATE KEY-----", "MIIEvQIBADANBg"),
])
def test_secrets_never_leave_the_vm(line, secret):
    out = d.redact_line(line)
    assert secret not in out and "***" in out or "[private key]" in out


@pytest.mark.parametrize("line", [
    "PHP Fatal error:  Uncaught Error: Call to undefined function mapi_logon_zarafa() in /usr/share/grommunio-web/server/includes/core/class.mapisession.php:93",
    "nginx.service: Main process exited, code=exited, status=1/FAILURE",
    "gromox-zcore.service: Failed with result 'exit-code'. signal=TERM ActiveState=failed",
    '10.0.0.5 - - [21/Nov/2026:10:00:00 +0000] "POST /web/ HTTP/1.1" 500 0 "-" "Mozilla/5.0"',
    "upstream prematurely closed connection while reading response header from upstream, client: 10.0.0.5",
])
def test_diagnostic_content_survives(line):
    assert d.redact_line(line) == line


def test_control_characters_and_length_are_neutralised_and_the_total_is_capped():
    assert d.redact_line("a\x1b[31mred\x00\nb") == "a?[31mred??b"
    assert len(d.redact_line("x" * 10000)) == d.MAX_LINE_CHARS
    lines, trunc = d.cap(["y" * 1000] * 100)
    assert trunc and sum(len(x) + 1 for x in lines) <= d.MAX_TOTAL_BYTES and len(lines) == d.MAX_TOTAL_BYTES // 1001
    assert d.cap(["a", "b"]) == (["a", "b"], False)


# ---------------------------------------------------------------- the root helper
def test_journal_argv_is_fixed_and_user_units_are_matched_by_the_service_users_uid():
    assert h.journal_argv({"unit": "php8.3-fpm", "lines": 50}) == [h.JOURNALCTL, "--no-pager", "-q", "-o", "short-iso", "--no-hostname", "-n", "50",
                                                                     "-u", "php8.3-fpm.service"]
    a = h.journal_argv({"unit": "keycloak", "lines": 5, "since_minutes": 10, "grep": "error"}, now=100000, uid_of=lambda n: 1001)
    assert a == [h.JOURNALCTL, "--no-pager", "-q", "-o", "short-iso", "--no-hostname", "-n", str(d.SCAN_LINES), "--since=@99400",
                 "_SYSTEMD_USER_UNIT=ou-identity-keycloak.service", "_UID=1001", "+", "USER_UNIT=ou-identity-keycloak.service", "_UID=1001"]


def test_helper_revalidates_the_spool_and_refuses_a_runbook_not_enabled(tmp_path, monkeypatch):
    spool, out, cfg = tmp_path / "spool", tmp_path / "out", tmp_path / "agent.json"
    spool.mkdir()
    monkeypatch.setattr(h, "SPOOL_DIR", str(spool))
    monkeypatch.setattr(h, "RESULT_DIR", str(out))
    monkeypatch.setattr(h, "CONFIG", str(cfg))
    cfg.write_text(json.dumps(CFG))
    rid = "r" + "0" * 16
    (spool / (rid + ".json")).write_text(json.dumps({"action": "guest.journal", "params": {"file": "../../etc/shadow", "lines": 5}}))
    assert h.main([rid]) == 0
    r = json.loads((out / (rid + ".json")).read_text())
    assert r["rejected"]["code"] == "not_allowed" and "result" not in r
    assert oct(os.stat(out / (rid + ".json")).st_mode & 0o777) == "0o640"
    cfg.write_text(json.dumps({"listen": {}, "runbooks": {}}))
    (spool / (rid + ".json")).write_text(json.dumps({"action": "guest.journal", "params": {"unit": "nginx", "lines": 5}}))
    h.main([rid])
    assert json.loads((out / (rid + ".json")).read_text())["rejected"]["code"] == "not_allowed"
    assert h.main(["../x"]) == 2


def test_helper_reads_the_tail_filters_and_redacts(tmp_path, monkeypatch):
    log = tmp_path / "error.log"
    log.write_text("".join(f"line {i} ok\n" for i in range(1000)) + "PHP Fatal error: boom token=abc123\nlast line\n")
    monkeypatch.setitem(d.FILES, "nginx-error", str(log))
    r = h.journal({"file": "nginx-error", "lines": 2})
    assert r["lines"] == ["PHP Fatal error: boom token=***", "last line"] and r["exists"] and r["redacted"] and not r["truncated"]
    r = h.journal({"file": "nginx-error", "lines": 5, "grep": "php"})
    assert r["lines"] == ["PHP Fatal error: boom token=***"]
    big = tmp_path / "big.log"
    big.write_text("z" * 100 + "\n" + ("q" * 99 + "\n") * 5000)     # bigger than the tail window: the cut first line is dropped
    monkeypatch.setitem(d.FILES, "nginx-error", str(big))
    r = h.journal({"file": "nginx-error", "lines": 300})
    assert r["count"] == 300 and all(x == "q" * 99 for x in r["lines"])


def test_helper_refuses_symlinks_hardlinks_and_missing_files(tmp_path, monkeypatch):
    target = tmp_path / "shadow"
    target.write_text("root:$6$secret:...\n")
    (tmp_path / "link.log").symlink_to(target)
    os.link(target, tmp_path / "hard.log")
    for name in ("link.log", "hard.log"):
        monkeypatch.setitem(d.FILES, "nginx-error", str(tmp_path / name))
        r = h.journal({"file": "nginx-error", "lines": 5})
        assert r["lines"] == [] and r["error"] and "secret" not in json.dumps(r)
    monkeypatch.setitem(d.FILES, "nginx-error", str(tmp_path / "missing.log"))
    assert h.journal({"file": "nginx-error", "lines": 5})["exists"] is False


def test_helper_journal_output_is_redacted(monkeypatch):
    def fake_run(argv, **kw):
        assert kw["shell"] is False and argv[0] == h.JOURNALCTL
        return subprocess.CompletedProcess(argv, 0, b"a Authorization: Bearer xyz.abc\nb ok\n", b"")
    monkeypatch.setattr(h.subprocess, "run", fake_run)
    r = h.journal({"unit": "nginx", "lines": 10})
    assert r["lines"] == ["a Authorization: ***", "b ok"] and r["target"] == "nginx.service" and r["scope"] == "system"


# ---------------------------------------------------------------- deployment plumbing
def test_unit_is_confined_polkit_allows_the_template_first_boot_and_bundle_know_it(tmp_path):
    unit = open(os.path.join(AGENT, "deploy", "runbooks", "ou-rb-diag@.service")).read()
    for line in ("CapabilityBoundingSet=CAP_DAC_READ_SEARCH", "NoNewPrivileges=true", "ProtectSystem=strict", "PrivateNetwork=true", "Group=ou-agent",
                 "RuntimeDirectoryMode=0750", "ExecStart=/usr/bin/python3 -m ou_agent.diaghelper %i"):
        assert line in unit.splitlines(), line
    f = tmp_path / "a.json"
    f.write_text(json.dumps(CFG))
    out = subprocess.run([sys.executable, os.path.join(AGENT, "deploy", "render_polkit.py"), str(f)], capture_output=True, text=True, check=True).stdout
    assert 'var tmpl = ["ou-rb-diag"]' in out
    assert "guest.journal" in firstboot.RUNBOOKS and "guest.journal" in firstboot.FEATURES
    rep = firstboot.build_report({"bid": "0" * 16, "secret": "00" * 32}, {"address": "10.0.0.1", "port": 8443, "tls_fingerprint_sha256": "1" * 64,
                                                                           "agent_key_fingerprint_sha256": "2" * 64}, "T" * 43)
    assert rep["features"] == ["guest.journal"]
    from ics.guest import cloudinit
    import tarfile, io, gzip
    names = tarfile.open(fileobj=io.BytesIO(gzip.decompress(cloudinit.build_agent_bundle(AGENT)))).getnames()
    assert "runbooks/ou-rb-diag@.service" in names and "ou_agent/diagspec.py" in names and "ou_agent/diaghelper.py" in names
    assert "install -m 0644 \"$D/runbooks/ou-rb-diag@.service\"" in open(os.path.join(AGENT, "deploy", "install-agent.sh")).read()
