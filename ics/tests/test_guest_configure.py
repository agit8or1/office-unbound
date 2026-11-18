"""Guest configuration runbooks (cfg.*): the agent's closed schemas, the root helper's fixed actions (against recording stand-in binaries), the
0600 spool, and the ICS side (deployment secrets + CA, realm rendering, audit redaction). The executor path is in test_deploy_exec.py."""
import io
import json
import os
import stat
import subprocess
import sys
import tarfile

import pytest
from cryptography import x509

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
from ou_agent import cfghelper as h  # noqa: E402
from ou_agent import cfgspec as c  # noqa: E402
from ou_agent import firstboot, runbooks  # noqa: E402
from ou_agent.proto import Reject  # noqa: E402

from ics.deploy import configure  # noqa: E402

PW = "Abcdefghijklmnop_qrstuv-0123456789"
PW2 = "ZyxwvutsrqponmlkjI-0987654321_abc"
IMG = "artifacts.example:8446/ou/keycloak@sha256:" + "a" * 64


def _ca_leaf(names=("auth.e2e.example", "ldap.e2e.example")):
    ca = json.loads(configure._new_ca("e2e.example", "e2e"))
    cert, key = configure.leaf(ca, list(names))
    return ca, cert, key


# ---------------------------------------------------------------- closed schemas
@pytest.mark.parametrize("action,params", [
    ("cfg.hosts", {"entries": [{"ip": "10.0.0.1", "names": ["auth.e2e.example\n10.6.6.6 evil.example"]}]}),
    ("cfg.hosts", {"entries": [{"ip": "10.0.0.1/8", "names": ["auth.e2e.example"]}]}),
    ("cfg.ldap_init", {"domain": "e2e.example", "organization": "Org\ndn: cn=x", "admin_password": PW, "bind_password": PW, "tls_name": "deployment", "groups": []}),
    ("cfg.ldap_init", {"domain": "e2e.example", "organization": "Org", "admin_password": "short", "bind_password": PW, "tls_name": "deployment", "groups": []}),
    ("cfg.ldap_init", {"domain": "e2e.example", "organization": "Org", "admin_password": PW + "'", "bind_password": PW, "tls_name": "deployment", "groups": []}),
    ("cfg.pg_db", {"role": "kc'; DROP ROLE x; --", "database": "keycloak", "password": PW}),
    ("cfg.podman_secret", {"name": "../x", "value": PW}),
    ("cfg.volume_files", {"component": "identity", "volume": "data", "image": IMG, "owner": "1:1", "files": [{"path": "../etc/passwd", "mode": 0o644, "content": "x"}]}),
    ("cfg.volume_files", {"component": "identity", "volume": "data", "image": IMG, "owner": "1:1", "files": [{"path": "/abs", "mode": 0o644, "content": "x"}]}),
    ("cfg.volume_files", {"component": "identity", "volume": "data", "image": IMG, "owner": "1:1", "files": [{"path": "a", "mode": 0o4755, "content": "x"}]}),
    ("cfg.volume_files", {"component": "identity", "volume": "data", "image": "keycloak:latest", "owner": "1:1", "files": [{"path": "a", "mode": 0o644, "content": "x"}]}),
    ("cfg.nginx_site", {"name": "auth", "server_names": ["auth.e2e.example"], "upstream": "http://evil.example:80", "tls_name": "deployment", "max_body_mb": 1}),
    ("cfg.nginx_site", {"name": "auth", "server_names": ["auth.e2e.example;"], "upstream": "http://127.0.0.1:8080", "tls_name": "deployment", "max_body_mb": 1}),
    ("cfg.tls", {"name": "deployment", "ca_pem": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\nextra", "cert_pem": "x", "key_pem": "y"}),
    ("cfg.hosts", {"entries": [], "extra": 1}),
])
def test_closed_schemas_refuse_injection_and_unexpected_shapes(action, params):
    with pytest.raises(Reject):
        c.CHECKS[action](params, {"enabled": True})


def test_valid_requests_pass_unchanged():
    ca, cert, key = _ca_leaf()
    assert c.check_tls({"name": "deployment", "ca_pem": ca["cert"], "cert_pem": cert, "key_pem": key}, {})["key_pem"] == key
    assert c.check_pg_db({"role": "keycloak", "database": "keycloak", "password": PW}, {}) == {"role": "keycloak", "database": "keycloak", "password": PW}
    assert c.base_dn("e2e.example") == "dc=e2e,dc=example"


def test_agent_knows_the_family_and_first_boot_accepts_it(tmp_path):
    cfg = {"listen": {"address": "0.0.0.0", "port": 8443}, "runbooks": {r: {"enabled": True} for r in c.CFG_RUNBOOKS}}
    runbooks.validate_config(cfg)
    assert set(runbooks.capabilities(cfg)) == set(c.CFG_RUNBOOKS)
    assert set(c.CFG_RUNBOOKS) <= firstboot.RUNBOOKS
    with pytest.raises(ValueError):
        runbooks.validate_config({"listen": {}, "runbooks": {"cfg.hosts": {"enabled": True, "paths": ["/"]}}})
    f = tmp_path / "a.json"
    f.write_text(json.dumps(cfg))
    out = subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), "..", "agent", "deploy", "render_polkit.py"), str(f)],
                         capture_output=True, text=True, check=True).stdout
    assert 'var tmpl = ["ou-rb-cfg"]' in out


def test_the_cfg_spool_is_private_and_removed(tmp_path, monkeypatch):
    """Secrets are in the request: the spool file is 0600 (the other families' spool is world-readable) and is deleted afterwards."""
    spool, res = tmp_path / "spool", tmp_path / "run"
    spool.mkdir()
    (res / "ou-rb-cfg").mkdir(parents=True)
    monkeypatch.setattr(runbooks, "SPOOL_DIR", str(spool))
    monkeypatch.setattr(runbooks, "RESULT_ROOT", str(res))
    seen = {}

    def fake_systemctl(*a, timeout=60):
        rid = a[-1].split("@")[1].split(".")[0]
        p = spool / (rid + ".json")
        seen["mode"] = stat.S_IMODE(os.stat(p).st_mode)
        seen["req"] = json.loads(p.read_text())
        (res / "ou-rb-cfg" / (rid + ".json")).write_text(json.dumps({"rid": rid, "result": {"name": "kc-db-password"}}))
        return subprocess.CompletedProcess(a, 0, "", "")
    monkeypatch.setattr(runbooks, "_systemctl", fake_systemctl)
    out = runbooks.execute("cfg.podman_secret", {"name": "kc-db-password", "value": PW})
    assert seen["mode"] == 0o600 and seen["req"]["params"]["value"] == PW
    assert out["result"] == {"name": "kc-db-password"} and PW not in json.dumps(out) and os.listdir(spool) == []


# ---------------------------------------------------------------- the root helper, against recording stand-ins
@pytest.fixture()
def fake(tmp_path, monkeypatch):
    """Every program the helper runs is a stub that records its argv and stdin; /etc paths point into tmp."""
    bindir, log = tmp_path / "bin", tmp_path / "log"
    bindir.mkdir()
    log.mkdir()
    stubs = {}
    for name in h.BIN:
        p = bindir / name
        p.write_text(f"#!/bin/sh\nn=$(ls {log} | wc -l)\nprintf '%s\\n' \"$@\" > {log}/$n.{name}.argv\ncat > {log}/$n.{name}.stdin\n"
                     f"[ -f {bindir}/{name}.out ] && cat {bindir}/{name}.out\nexit $(cat {bindir}/{name}.rc 2>/dev/null || echo 0)\n")
        p.chmod(0o755)
        stubs[name] = str(p)
    monkeypatch.setattr(h, "BIN", stubs)
    monkeypatch.setattr(h.os, "chown", lambda *a, **k: None)
    monkeypatch.setattr(h, "HOSTS", str(tmp_path / "hosts"))
    monkeypatch.setattr(h, "TLS_DIR", str(tmp_path / "tls"))
    monkeypatch.setattr(h, "CA_TRUST", str(tmp_path / "ca-trust.crt"))
    monkeypatch.setattr(h, "LDAP_TLS", str(tmp_path / "ldaptls"))
    monkeypatch.setattr(h, "SLAPD_DEFAULT", str(tmp_path / "slapd.default"))
    monkeypatch.setattr(h, "LDAP_CONF", str(tmp_path / "ldap.conf"))
    monkeypatch.setattr(h, "NGINX_AVAIL", str(tmp_path / "avail"))
    monkeypatch.setattr(h, "NGINX_ENABLED", str(tmp_path / "enabled"))
    monkeypatch.setattr(h, "NGINX_MAP", str(tmp_path / "map.conf"))
    monkeypatch.setattr(h, "VERIFIED_DIR", str(tmp_path / "verified"))
    monkeypatch.setattr(h, "svc_env", lambda: {"PATH": "/usr/bin:/bin", "HOME": "/var/lib/ou-svc", "XDG_RUNTIME_DIR": "/run/user/1001"})
    monkeypatch.setattr(h.pwd, "getpwnam", lambda n: type("P", (), {"pw_uid": 1001, "pw_gid": 1001})())

    class F:
        path = tmp_path

        @staticmethod
        def out(name, text, rc=0):
            (bindir / f"{name}.out").write_text(text)
            (bindir / f"{name}.rc").write_text(str(rc))

        @staticmethod
        def calls(name=None):
            out = []
            for f in sorted(log.glob("*.argv"), key=lambda p: int(p.name.split(".")[0])):
                prog = f.name.split(".", 1)[1].rsplit(".", 1)[0]
                if name is None or prog == name:
                    out.append((prog, f.read_text().splitlines(), (log / f.name.replace(".argv", ".stdin")).read_text()))
            return out

        @staticmethod
        def every_argv():
            return "\n".join(p.read_text() for p in log.glob("*.argv"))
    return F


def _run(action, params):
    return h.handle({"action": action, "params": params}, {"runbooks": {action: {"enabled": True}}})


def test_hosts_block_is_managed_idempotently_and_keeps_other_lines(fake):
    (fake.path / "hosts").write_text("127.0.0.1 localhost\n")
    p = {"entries": [{"ip": "10.0.0.5", "names": ["auth.e2e.example", "ldap.e2e.example"]}]}
    assert _run("cfg.hosts", p) == {"entries": 1, "changed": True}
    assert _run("cfg.hosts", p)["changed"] is False
    _run("cfg.hosts", {"entries": [{"ip": "10.0.0.6", "names": ["auth.e2e.example"]}]})
    t = (fake.path / "hosts").read_text()
    assert t.startswith("127.0.0.1 localhost\n") and "10.0.0.5" not in t and "10.0.0.6 auth.e2e.example" in t and t.count(h.HOSTS_BEGIN) == 1


def test_tls_files_have_the_right_modes_and_a_foreign_key_is_refused(fake, monkeypatch):
    ca, cert, key = _ca_leaf()
    monkeypatch.setitem(h.BIN, "openssl", "/usr/bin/openssl")   # the real tool: the pairing and chain checks are the point
    assert _run("cfg.tls", {"name": "deployment", "ca_pem": ca["cert"], "cert_pem": cert, "key_pem": key})["ca_trust_updated"] is True
    tls = fake.path / "tls"
    assert stat.S_IMODE(os.stat(tls / "deployment.key").st_mode) == 0o600 and stat.S_IMODE(os.stat(tls / "deployment.crt").st_mode) == 0o644
    assert (fake.path / "ca-trust.crt").read_text() == ca["cert"] and fake.calls("update-ca")
    _, _, other_key = _ca_leaf()
    with pytest.raises(h.Failed, match="does not belong"):
        _run("cfg.tls", {"name": "deployment", "ca_pem": ca["cert"], "cert_pem": cert, "key_pem": other_key})


def test_ldap_init_configures_the_directory_with_secrets_on_stdin_only(fake, monkeypatch):
    for f in ("deployment.crt", "deployment.key", "ca.crt"):
        (fake.path / "tls").mkdir(exist_ok=True)
        (fake.path / "tls" / f).write_text("x")
    fake.out("dpkg-query", "install ok installed")

    def search(x, base, flt, attrs, scope="sub"):   # a fresh slapd: the database exists, nothing of ours is in it yet
        return "dn: olcDatabase={1}mdb,cn=config\n" if flt == "(olcSuffix=dc=e2e,dc=example)" else ""
    monkeypatch.setattr(h, "ldap_search", search)
    r = _run("cfg.ldap_init", {"domain": "e2e.example", "organization": "Office Unbound", "admin_password": PW, "bind_password": PW2,
                               "tls_name": "deployment", "groups": ["opencloudAdmin", "mail-users"]})
    assert r["suffix"] == "dc=e2e,dc=example" and r["reconfigured"] is True   # the stub's cn=config has no olcSuffix for this domain
    assert PW not in fake.every_argv() and PW2 not in fake.every_argv()       # never on a command line
    deb = [x for x in fake.calls("debconf-set")]
    assert PW in deb[0][2] and "slapd/domain string e2e.example" in deb[0][2] and PW not in deb[-1][2]   # set, then cleared after reconfigure
    ldif = "\n".join(x[2] for x in fake.calls("ldapmodify"))
    assert 'to * by dn.exact="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth" manage by * break' in ldif
    assert "olcOverlay: memberof" in ldif and "olcTLSProtocolMin: 3.3" in ldif and PW2 not in ldif and "{SSHA}" in ldif
    assert "dn: cn=opencloudAdmin,ou=groups,dc=e2e,dc=example" in ldif and "olcModuleLoad: ppolicy" in ldif
    assert set(r["created"]) >= {"ou=people", "cn=svc-bind", "cn=mail-users"}
    assert 'SLAPD_SERVICES="ldap://127.0.0.1:389/ ldaps:/// ldapi:///"' in (fake.path / "slapd.default").read_text()


def test_pg_db_password_reaches_psql_on_stdin_and_errors_are_scrubbed(fake):
    assert _run("cfg.pg_db", {"role": "keycloak", "database": "keycloak", "password": PW}) == {"role": "keycloak", "database": "keycloak"}
    psql = fake.calls("runuser")[-1]
    assert PW not in "\n".join(psql[1]) and f"PASSWORD '{PW}'" in psql[2] and "postgres" in psql[1]
    fake.out("runuser", f"ERROR: syntax error at or near \"x\"\nLINE 1: ALTER ROLE keycloak WITH LOGIN PASSWORD '{PW}'", rc=1)
    with pytest.raises(h.Failed) as e:
        _run("cfg.pg_db", {"role": "keycloak", "database": "keycloak", "password": PW})
    assert PW not in str(e.value) and "***" in str(e.value)


def test_podman_secret_value_on_stdin_only(fake):
    _run("cfg.podman_secret", {"name": "kc-db-password", "value": PW})
    call = fake.calls("runuser")[-1]
    assert PW not in "\n".join(call[1]) and call[2] == PW and call[1][-4:] == ["secret", "create", "kc-db-password", "-"]
    assert fake.calls("runuser")[-2][1][-3:] == ["secret", "rm", "kc-db-password"]


def test_volume_files_need_a_verified_image_and_carry_exact_modes(fake, monkeypatch):
    p = {"component": "identity", "volume": "data", "image": IMG, "owner": "10130:10130",
         "files": [{"path": "import/realm-ou.json", "mode": 0o600, "content": "{}"}]}
    with pytest.raises(h.Failed, match="not pulled and verified"):
        _run("cfg.volume_files", p)
    (fake.path / "verified").mkdir()
    (fake.path / "verified" / ("a" * 64 + ".json")).write_text("{}")
    seen = {}

    def fake_run(argv, input=None, capture_output=True, timeout=None, cwd=None):
        seen["argv"], seen["tar"] = argv, input
        return subprocess.CompletedProcess(argv, 0, b"", b"")
    monkeypatch.setattr(h.subprocess, "run", fake_run)
    monkeypatch.setattr(h.Ctx, "run", lambda self, argv, **kw: subprocess.CompletedProcess(argv, 0, "", ""))
    assert _run("cfg.volume_files", p)["volume"] == "ou-identity-data"
    t = tarfile.open(fileobj=io.BytesIO(seen["tar"]))
    m = t.getmember("import/realm-ou.json")
    assert m.mode == 0o600 and t.extractfile(m).read() == b"{}"
    assert "--network=none" in seen["argv"] and "--pull=never" in seen["argv"] and seen["argv"][-1] == "tar -xf - -C /d && chown -R 10130:10130 /d"


def test_nginx_site_is_rendered_from_the_fixed_template_and_rolled_back_when_refused(fake):
    (fake.path / "tls").mkdir()
    for f in ("deployment.crt", "deployment.key"):
        (fake.path / "tls" / f).write_text("x")
    (fake.path / "enabled").mkdir()
    (fake.path / "enabled" / "default").write_text("")
    p = {"name": "auth", "server_names": ["auth.e2e.example"], "upstream": "http://127.0.0.1:8080", "tls_name": "deployment", "max_body_mb": 16}
    assert _run("cfg.nginx_site", p)["site"] == "ou-auth"
    site = (fake.path / "avail" / "ou-auth").read_text()
    assert "server_name auth.e2e.example;" in site and "proxy_pass http://127.0.0.1:8080;" in site and "client_max_body_size 16m;" in site
    assert os.path.islink(fake.path / "enabled" / "ou-auth") and not (fake.path / "enabled" / "default").exists()
    fake.out("nginx", "nginx: [emerg] something", rc=1)
    with pytest.raises(h.Failed, match="nginx refused"):
        _run("cfg.nginx_site", {**p, "name": "cloud", "server_names": ["cloud.e2e.example"]})
    assert not (fake.path / "avail" / "ou-cloud").exists() and not os.path.lexists(fake.path / "enabled" / "ou-cloud")


def test_unknown_or_disabled_actions_are_refused(fake):
    with pytest.raises(Reject):
        h.handle({"action": "cfg.hosts", "params": {"entries": []}}, {"runbooks": {}})
    with pytest.raises(Reject):
        h.handle({"action": "pkg.install_pinned", "params": {}}, {"runbooks": {"pkg.install_pinned": {"packages": []}}})


# ---------------------------------------------------------------- ICS side
def test_the_deployment_ca_can_only_vouch_for_its_own_domain():
    ca, cert, _ = _ca_leaf()
    cac = x509.load_pem_x509_certificate(ca["cert"].encode())
    nc = cac.extensions.get_extension_for_class(x509.NameConstraints)
    assert nc.critical and [n.value for n in nc.value.permitted_subtrees] == ["e2e.example"]
    leaf = x509.load_pem_x509_certificate(cert.encode())
    leaf.verify_directly_issued_by(cac)
    assert leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName) == ["auth.e2e.example", "ldap.e2e.example"]


def test_realm_is_rendered_for_the_deployment_without_lab_leftovers():
    r = json.loads(configure.realm_json("e2e.example", PW))
    s = json.dumps(r)
    assert r["realm"] == configure.REALM and "@" not in s.replace("@e2e", "") and "ou-lab" not in s
    assert "ou-lab-test" not in [c["clientId"] for c in r["clients"]] and not any(c.get("directAccessGrantsEnabled") for c in r["clients"])
    assert PW in s and "ldaps://ldap.e2e.example:636" in s and "dc=e2e,dc=example" in s


def test_names_by_vm_follow_the_plan_records_and_add_the_directory_name():
    plan = {"input": {"domain": "e2e.example"}, "vms": [{"name": "id", "components": ["identity", "edge"]}, {"name": "gw", "components": ["groupware"]}],
            "dns": [{"name": "auth.e2e.example", "type": "A", "value": "vm:id"}, {"name": "mail.e2e.example", "type": "A", "value": "vm:gw"},
                    {"name": "autodiscover.e2e.example", "type": "CNAME", "value": "mail.e2e.example"},
                    {"name": "e2e.example", "type": "MX", "value": "10 mail.e2e.example"}]}
    assert configure.names_by_vm(plan, "e2e.example") == {"gw": ["autodiscover.e2e.example", "mail.e2e.example"],
                                                          "id": ["auth.e2e.example", "ldap.e2e.example"]}


def test_audit_redaction_keeps_no_secret_and_no_file_content():
    ca, cert, key = _ca_leaf()
    red = configure.redact("cfg.tls", {"name": "deployment", "ca_pem": ca["cert"], "cert_pem": cert, "key_pem": key})
    red2 = configure.redact("cfg.volume_files", {"component": "identity", "volume": "data", "image": IMG, "owner": "1:1",
                                                 "files": [{"path": "import/realm-ou.json", "mode": 0o600, "content": "secret " + PW}]})
    red3 = configure.redact("cfg.ldap_init", {"domain": "e2e.example", "admin_password": PW, "bind_password": PW2, "groups": []})
    s = json.dumps([red, red2, red3])
    assert "PRIVATE KEY" not in s and PW not in s and PW2 not in s and red2["files"][0]["bytes"] == len("secret " + PW)
    assert configure.redact("podman.status", {"component": "x"}) == {"component": "x"}


def test_firewall_allowances_are_exact_triples_written_for_the_boot_include(fake):
    with pytest.raises(Reject):
        c.check_firewall({"rules": [{"source": "10.0.0.0/8", "proto": "tcp", "port": 9200}]}, {})
    with pytest.raises(Reject):
        c.check_firewall({"rules": [{"source": "10.0.0.1", "proto": "icmp", "port": 1}]}, {})
    import ou_agent.cfghelper as hh
    hh.NFT_ALLOW = str(fake.path / "nft-allow.d" / "ou-peers.nft")
    assert _run("cfg.firewall", {"rules": [{"source": "10.0.0.7", "proto": "tcp", "port": 9200}, {"source": "10.0.0.6", "proto": "tcp", "port": 636}]}) == {"rules": 2}
    text = (fake.path / "nft-allow.d" / "ou-peers.nft").read_text()
    assert "flush set inet ou_guest cfg_allow4" in text and "{ 10.0.0.6 . tcp . 636, 10.0.0.7 . tcp . 9200 }" in text
    assert [x[1][0] for x in fake.calls("nft")][-2:] == ["-c", "-f"]
    _run("cfg.firewall", {"rules": []})
    assert "add element" not in (fake.path / "nft-allow.d" / "ou-peers.nft").read_text()


def test_first_boot_ruleset_has_the_empty_peer_set_and_its_include():
    r = firstboot.nft_ruleset({"agent_port": 8443, "mgmt_sources": ["192.0.2.1/32"], "ports": []})
    assert "set cfg_allow4 {\n    type ipv4_addr . inet_proto . inet_service\n  }" in r and "elements" not in r
    assert "ip saddr . meta l4proto . th dport @cfg_allow4 accept" in r and r.endswith('include "/etc/ou-agent/nft-allow.d/*.nft"\n')
    assert "policy drop" in r


def test_peer_rules_come_from_the_plan_with_exact_addresses():
    class A:
        def address(self, vm):
            return {"files": "10.0.0.7", "gw": "10.0.0.8"}[vm]
    ctx = type("C", (), {"plan": {"vms": [{"name": "id"}, {"name": "files"}, {"name": "gw"}],
                                  "firewall": [{"vm": "id", "port": 636, "proto": "tcp", "from": "files"}, {"vm": "id", "port": 636, "proto": "tcp", "from": "gw"},
                                               {"vm": "id", "port": 443, "proto": "tcp", "from": "any"}, {"vm": "files", "port": 9200, "proto": "tcp", "from": "id"}]},
                         "env": type("E", (), {"agent": A()})()})()
    assert configure.firewall_runbook(ctx, "id")["params"]["rules"] == [{"source": "10.0.0.7", "proto": "tcp", "port": 636},
                                                                         {"source": "10.0.0.8", "proto": "tcp", "port": 636}]
    with pytest.raises(configure.ConfigError):
        configure.firewall_runbook(ctx, "files")   # the id VM's address is unknown here: refused, never widened
